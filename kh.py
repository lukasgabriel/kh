"""
kh - known_hosts manager

Formats ssh-keyscan output into a clean, deduplicated known_hosts file where each
host has all its addresses (hostname, private IP, public IP) on one line.

Usage:
  kh add <address> [-p PORT] [-f FILE]
  kh cleanup <file>

Examples:
  kh add 10.21.181.2                        # scan and print formatted block
  kh add db.example.com -p 2222             # non-standard port
  kh add 10.21.181.2 -f known_hosts         # merge into existing file
  kh cleanup known_hosts                    # normalize and enrich existing file
"""

import argparse
import ipaddress
import re
import subprocess
import sys

ALGO_ORDER = ["ssh-rsa", "ecdsa-sha2-nistp256", "ssh-ed25519", "ssh-dss"]
KEYSCAN_COMMENT_RE = re.compile(r"^#\s*\S+:\d+\s+SSH-")
CHEZMOI_RE = re.compile(r"^\s*\{\{.*\}\}\s*$")


# --- Address helpers ---


def is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def is_private_ip(s):
    try:
        return ipaddress.ip_address(s).is_private
    except ValueError:
        return False


def parse_addr(addr_str):
    """Parse '[host]:port' or 'host' -> (host, port|None)."""
    m = re.match(r"^\[(.+)\]:(\d+)$", addr_str)
    if m:
        return m.group(1), int(m.group(2))
    return addr_str, None


def fmt_addr(host, port):
    if port and port != 22:
        return f"[{host}]:{port}"
    return host


def classify_addrs(addresses):
    """Split into (hostnames, private_ips, public_ips).
    Hostnames sorted shortest-first (then alphabetically as tiebreaker).
    IPs sorted alphabetically."""
    hostnames, priv, pub = [], [], []
    for a in addresses:
        if is_ip(a):
            (priv if is_private_ip(a) else pub).append(a)
        else:
            hostnames.append(a)
    return sorted(hostnames, key=lambda h: (len(h), h)), sorted(priv), sorted(pub)


def order_addrs(addresses):
    """Canonical order: hostnames (shortest first), private IPs, public IPs."""
    h, priv, pub = classify_addrs(addresses)
    return h + priv + pub


# --- DNS resolution ---


def reverse_dns(ip_addr):
    try:
        r = subprocess.run(
            ["dig", "-x", ip_addr, "+short", "+timeout=3", "+tries=1"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return [
            line.strip().rstrip(".")
            for line in r.stdout.strip().splitlines()
            if line.strip() and not is_ip(line.strip().rstrip("."))
        ]
    except Exception:
        return []


def forward_dns(hostname):
    try:
        r = subprocess.run(
            ["dig", "+short", hostname, "+timeout=3", "+tries=1"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return [
            line.strip()
            for line in r.stdout.strip().splitlines()
            if is_ip(line.strip())
        ]
    except Exception:
        return []


def resolve_addresses(address):
    """Given one address, discover all associated addresses via DNS."""
    found = {address}
    if is_ip(address):
        hostnames = reverse_dns(address)
        found.update(hostnames)
        for h in hostnames:
            found.update(forward_dns(h))
    else:
        ips = forward_dns(address)
        found.update(ips)
        for ip in ips:
            found.update(reverse_dns(ip))
    return found


def enrich_addresses(addresses):
    """Try to fill in missing components for an existing address set."""
    all_a = set(addresses)
    for a in list(addresses):
        all_a.update(resolve_addresses(a))
    return all_a


# --- ssh-keyscan ---


def keyscan(address, port=22):
    cmd = ["ssh-keyscan"]
    if port != 22:
        cmd += ["-p", str(port)]
    cmd.append(address)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        print("error: ssh-keyscan not found", file=sys.stderr)
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print(f"error: ssh-keyscan timed out for {address}", file=sys.stderr)
        sys.exit(1)

    keys = []
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 2)
        if len(parts) == 3:
            keys.append((parts[1], parts[2]))
    if not keys:
        print(f"error: no keys returned for {address}:{port}", file=sys.stderr)
        print("  Make sure the host is reachable and sshd is running.", file=sys.stderr)
        sys.exit(1)
    return keys


# --- known_hosts parsing ---


def parse_line(line):
    parts = line.split(None, 2)
    if len(parts) != 3:
        return None
    addr_str, algo, key_data = parts
    port = 22
    addresses = set()
    for component in addr_str.split(","):
        host, p = parse_addr(component)
        addresses.add(host)
        if p is not None:
            port = p
    return addresses, port, algo, key_data


def parse_file(text):
    """Parse known_hosts text into structured items.

    Item types:
      ('comment', text)   - user comment (# Section heading)
      ('entry', addrs, port, algo, key_data)
      ('template', text)  - chezmoi template line ({{ ... }})
      ('blank',)          - empty line
    """
    items = []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            items.append(("blank",))
        elif CHEZMOI_RE.match(s):
            items.append(("template", s))
        elif s.startswith("#"):
            items.append(("comment", s))
        else:
            parsed = parse_line(s)
            if parsed:
                items.append(("entry",) + parsed)
            else:
                items.append(("comment", s))
    return items


# --- Host grouping ---


def _merge_keys(target, source):
    """Merge source keys into target, both {algo: [key_data, ...]}."""
    for algo, kds in source.items():
        if algo not in target:
            target[algo] = list(kds)
        else:
            for kd in kds:
                if kd not in target[algo]:
                    target[algo].append(kd)


def group_hosts(entries):
    """Group entries by overlapping addresses or identical key data,
    but only when ports match. Different ports = different services.

    Returns list of {'addresses': set, 'port': int, 'keys': {algo: [key_data, ...]}}
    """
    groups = []
    for addresses, port, algo, key_data in entries:
        matching = []
        for i, g in enumerate(groups):
            if g["port"] != port:
                continue
            if (g["addresses"] & addresses) or key_data in g["keys"].get(algo, []):
                matching.append(i)
        if not matching:
            groups.append(
                {
                    "addresses": set(addresses),
                    "port": port,
                    "keys": {algo: [key_data]},
                }
            )
        else:
            merged = {
                "addresses": set(addresses),
                "port": port,
                "keys": {algo: [key_data]},
            }
            for i in matching:
                merged["addresses"] |= groups[i]["addresses"]
                _merge_keys(merged["keys"], groups[i]["keys"])
            for i in sorted(matching, reverse=True):
                groups.pop(i)
            groups.append(merged)
    return groups


# --- Formatting ---


def fmt_block(addresses, port, keys):
    ordered = order_addrs(addresses)
    addr_str = ",".join(fmt_addr(a, port) for a in ordered)
    lines = []
    for algo in ALGO_ORDER:
        for kd in keys.get(algo, []):
            lines.append(f"{addr_str} {algo} {kd}")
    for algo in sorted(keys):
        if algo not in ALGO_ORDER:
            for kd in keys[algo]:
                lines.append(f"{addr_str} {algo} {kd}")
    return lines


# --- Section-aware processing ---


def split_into_sections(items):
    """Split parsed items into sections delimited by template lines.

    Returns list of sections, where each section is:
      {'prefix': [template/blank lines before content],
       'items': [comment/entry/blank items]}

    Template lines and surrounding blanks go into the *next* section's prefix.
    """
    sections = []
    current_items = []
    pending_prefix = []

    for item in items:
        if item[0] == "template":
            # Flush current section
            if current_items:
                sections.append(
                    {
                        "prefix": pending_prefix,
                        "items": current_items,
                    }
                )
                pending_prefix = []
                current_items = []
            pending_prefix.append(item)
        elif item[0] == "blank" and not current_items:
            # Blank before any real content goes into prefix
            pending_prefix.append(item)
        else:
            current_items.append(item)

    # Flush last section
    if current_items or pending_prefix:
        sections.append(
            {
                "prefix": pending_prefix,
                "items": current_items,
            }
        )

    return sections


def process_section_items(items):
    """Process items within a single template section.

    Returns list of output lines (strings).
    """
    entries = [(i[1], i[2], i[3], i[4]) for i in items if i[0] == "entry"]

    if not entries:
        # No entries - just pass through comments
        lines = []
        for item in items:
            if item[0] == "comment" and not KEYSCAN_COMMENT_RE.match(item[1]):
                lines.append(item[1])
        return lines

    groups = group_hosts(entries)

    # Build entry->group mapping for comment association
    e2g = {}
    for eidx, (addrs, port, algo, kd) in enumerate(entries):
        for gi, g in enumerate(groups):
            if kd in g["keys"].get(algo, []):
                e2g[eidx] = gi
                break

    # Collect user comments (skip keyscan noise), associate with entries
    gc = {i: [] for i in range(len(groups))}
    orphans = []
    trailing = []
    entry_idx = 0
    pending = []
    for item in items:
        if item[0] == "comment":
            if not KEYSCAN_COMMENT_RE.match(item[1]):
                pending.append(item[1])
        elif item[0] == "entry":
            for c in pending:
                gi = e2g.get(entry_idx)
                if gi is not None:
                    if c not in gc[gi]:
                        gc[gi].append(c)
                else:
                    orphans.append(c)
            pending = []
            entry_idx += 1
    trailing = pending

    # Build output lines
    # Rule: blank line before comment headings, no blank lines between hosts
    out = []
    for i, g in enumerate(groups):
        comments = gc.get(i, [])
        if comments:
            if out:  # blank line before a comment heading (unless first)
                out.append("")
            for c in comments:
                out.append(c)
        for line in fmt_block(g["addresses"], g["port"], g["keys"]):
            out.append(line)

    for c in orphans + trailing:
        if out:
            out.append("")
        out.append(c)

    return out


def process_section_items_with_enrich(items):
    """Process items within a single template section, with DNS enrichment.

    Returns list of output lines (strings).
    """
    entries = [(i[1], i[2], i[3], i[4]) for i in items if i[0] == "entry"]

    if not entries:
        lines = []
        for item in items:
            if item[0] == "comment" and not KEYSCAN_COMMENT_RE.match(item[1]):
                lines.append(item[1])
        return lines

    groups = group_hosts(entries)

    # Enrich
    for g in groups:
        old = set(g["addresses"])
        g["addresses"] = enrich_addresses(g["addresses"])
        new = g["addresses"] - old
        if new:
            print(
                f"  {', '.join(order_addrs(old))}: +{', '.join(order_addrs(new))}",
                file=sys.stderr,
            )

    # Build entry->group mapping
    e2g = {}
    for eidx, (addrs, port, algo, kd) in enumerate(entries):
        for gi, g in enumerate(groups):
            if kd in g["keys"].get(algo, []):
                e2g[eidx] = gi
                break

    # Collect user comments
    gc = {i: [] for i in range(len(groups))}
    orphans = []
    entry_idx = 0
    pending = []
    for item in items:
        if item[0] == "comment":
            if not KEYSCAN_COMMENT_RE.match(item[1]):
                pending.append(item[1])
        elif item[0] == "entry":
            for c in pending:
                gi = e2g.get(entry_idx)
                if gi is not None:
                    if c not in gc[gi]:
                        gc[gi].append(c)
                else:
                    orphans.append(c)
            pending = []
            entry_idx += 1
    trailing = pending

    # Build output: blank line before comment headings only
    out = []
    for i, g in enumerate(groups):
        comments = gc.get(i, [])
        if comments:
            if out:
                out.append("")
            for c in comments:
                out.append(c)
        for line in fmt_block(g["addresses"], g["port"], g["keys"]):
            out.append(line)

    for c in orphans + trailing:
        if out:
            out.append("")
        out.append(c)

    return out


def emit_sections(sections, enrich=False):
    """Process and print all sections."""
    first_section = True
    for section in sections:
        # Print prefix (template lines + surrounding blanks)
        if section["prefix"]:
            if not first_section:
                # Ensure blank line before template directives
                print()
            for item in section["prefix"]:
                if item[0] == "template":
                    print(item[1])
                # Skip blank items in prefix - we handle spacing ourselves

        # Process section content
        if section["items"]:
            if enrich:
                out_lines = process_section_items_with_enrich(section["items"])
            else:
                out_lines = process_section_items(section["items"])

            if out_lines:
                if not first_section and not section["prefix"]:
                    print()
                for line in out_lines:
                    print(line)

        first_section = False


# --- Commands ---


def cmd_add(args):
    address = args.address
    port = args.port

    print(f"Scanning {address}:{port} ...", file=sys.stderr)
    keys = keyscan(address, port)
    keys_dict = {}
    for algo, kd in keys:
        keys_dict.setdefault(algo, []).append(kd)

    print("Resolving addresses ...", file=sys.stderr)
    addresses = resolve_addresses(address)
    print(f"  Found: {', '.join(order_addrs(addresses))}", file=sys.stderr)

    if args.file:
        try:
            with open(args.file) as f:
                text = f.read()
        except FileNotFoundError:
            print(f"warning: {args.file} not found, creating new", file=sys.stderr)
            text = ""

        items = parse_file(text)

        # Find which template section the new entry should go into.
        # If the host already exists somewhere (by key match), it merges there.
        # Otherwise, append to the last section.
        # We add the new entries as items, then let section processing handle it.
        for algo, kds in keys_dict.items():
            for kd in kds:
                items.append(("entry", addresses, port, algo, kd))

        sections = split_into_sections(items)
        print("Enriching addresses via DNS ...", file=sys.stderr)
        emit_sections(sections, enrich=True)
    else:
        for line in fmt_block(addresses, port, keys_dict):
            print(line)

    print(file=sys.stderr)
    print("Done.", file=sys.stderr)


def cmd_cleanup(args):
    try:
        with open(args.file) as f:
            text = f.read()
    except FileNotFoundError:
        print(f"error: {args.file} not found", file=sys.stderr)
        sys.exit(1)

    items = parse_file(text)
    entries = [i for i in items if i[0] == "entry"]

    if not entries:
        print("No entries found.", file=sys.stderr)
        sys.exit(0)

    sections = split_into_sections(items)
    print("Enriching addresses via DNS ...", file=sys.stderr)
    emit_sections(sections, enrich=True)

    print(file=sys.stderr)
    print("Done.", file=sys.stderr)


# --- CLI ---


def main():
    parser = argparse.ArgumentParser(
        prog="kh", description="known_hosts manager - clean, DRY known_hosts files"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_add = sub.add_parser(
        "add", help="Scan a host and output formatted known_hosts lines"
    )
    p_add.add_argument("address", help="Hostname or IP to scan")
    p_add.add_argument(
        "-p", "--port", type=int, default=22, help="SSH port (default: 22)"
    )
    p_add.add_argument("-f", "--file", help="Existing known_hosts file to merge into")

    p_clean = sub.add_parser(
        "cleanup", help="Normalize and enrich an existing known_hosts file"
    )
    p_clean.add_argument("file", help="known_hosts file to clean up")

    args = parser.parse_args()
    if args.command == "add":
        cmd_add(args)
    elif args.command == "cleanup":
        cmd_cleanup(args)


if __name__ == "__main__":
    main()
