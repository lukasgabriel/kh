# kh

Python script that helps you keep a tidy `known_hosts` file

## Description

`ssh-keyscan` outputs one line per address per algorithm, so scanning a host by hostname and IP gives you six messy, duplicated lines.
`kh` merges them into three clean ones with all addresses on each line: hostname first, then private IP, then public IP - keeping your `known_hosts` deduplicated and readable.

The motivation behind this script was to make it easy to keep a [chezmoi](https://www.chezmoi.io)-managed `known_hosts` files tidy, even when reaching thousands of entries. Therefore, the script also works on `.tmpl` files.

## Usage

```sh
# Scan a host, print formatted block to stdout
kh add 10.21.181.2
kh add my.server.com -p 2222

# Merge into an existing file (outputs full updated file to stdout)
kh add 10.21.181.2 -f known_hosts > known_hosts.new

# Clean up / deduplicate / enrich an existing file
kh cleanup known_hosts > known_hosts.new
```

Status messages go to stderr, clean output goes to stdout.
