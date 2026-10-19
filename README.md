# network-enumeration-lab

A lab guide plus a parser that turns an Nmap XML scan into a readable inventory of
hosts, ports and services. **It does not scan anything** — you run Nmap yourself
against systems you own or are authorized to test, and this tool summarizes the
results.

## Features

- Parses `nmap -oX` output with the standard library (`xml.etree`).
- Table output for humans, JSON for automation.
- Summaries: host count, open ports, services with product/version.
- Test fixture included, so the parser is verifiable without any network access.

## Installation

```bash
git clone https://github.com/victor-harden/network-enumeration-lab.git
cd network-enumeration-lab
```

## Usage

```bash
# 1. Build an authorized lab (see docs/lab-setup.md), then:
nmap -sV -oX scan.xml 192.168.56.0/24

# 2. Summarize it:
python3 tools/nmap_parse.py scan.xml
python3 tools/nmap_parse.py scan.xml --json
python3 tools/nmap_parse.py tests/sample_scan.xml --only-open
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Scope and ethics

Scan only hosts you own or have explicit written authorization to test. The lab
guide uses an isolated virtual network; never point these commands at the public
internet or an employer network without permission.

## License

MIT — see [LICENSE](LICENSE).
