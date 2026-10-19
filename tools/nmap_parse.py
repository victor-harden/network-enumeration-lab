#!/usr/bin/env python3
"""Summarize an Nmap XML report (no scanning is performed)."""
from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def parse_scan(path: Path):
    tree = ET.parse(path)
    root = tree.getroot()
    hosts = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        address = ""
        for addr in host.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                address = addr.get("addr", "")
                break
        hostname = ""
        names = host.find("hostnames")
        if names is not None:
            first = names.find("hostname")
            if first is not None:
                hostname = first.get("name", "")
        ports = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for port in ports_el.findall("port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                service = port.find("service")
                ports.append({
                    "port": int(port.get("portid", "0")),
                    "protocol": port.get("protocol", "tcp"),
                    "service": service.get("name", "") if service is not None else "",
                    "product": service.get("product", "") if service is not None else "",
                    "version": service.get("version", "") if service is not None else "",
                })
        hosts.append({"address": address, "hostname": hostname, "ports": ports})
    return hosts


def summarize(hosts):
    return {
        "hosts_up": len(hosts),
        "open_ports": sum(len(h["ports"]) for h in hosts),
        "services": sorted({p["service"] for h in hosts for p in h["ports"] if p["service"]}),
    }


def render(hosts) -> str:
    lines = []
    for host in hosts:
        label = host["address"] or "unknown"
        if host["hostname"]:
            label += f" ({host['hostname']})"
        lines.append(label)
        if not host["ports"]:
            lines.append("  no open ports in report")
            continue
        for port in host["ports"]:
            svc = port["service"] or "unknown"
            detail = " ".join(x for x in (port["product"], port["version"]) if x)
            lines.append(f"  {port['port']}/{port['protocol']:<4} {svc:<12} {detail}".rstrip())
    stats = summarize(hosts)
    lines.append("")
    lines.append(f"hosts up: {stats['hosts_up']} | open ports: {stats['open_ports']}")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Summarize an Nmap XML scan")
    parser.add_argument("xml", type=Path)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--only-open", action="store_true",
                        help="hide hosts without open ports")
    args = parser.parse_args(argv)

    if not args.xml.exists():
        print(f"file not found: {args.xml}", file=sys.stderr)
        return 2
    hosts = parse_scan(args.xml)
    if args.only_open:
        hosts = [h for h in hosts if h["ports"]]
    if args.json:
        print(json.dumps({"hosts": hosts, "summary": summarize(hosts)}, indent=2))
    else:
        print(render(hosts))
    return 0


if __name__ == "__main__":
    sys.exit(main())
