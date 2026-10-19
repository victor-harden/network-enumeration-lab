# Building an authorized lab

## Option A — two virtual machines

1. Create an isolated host-only network in VirtualBox/VMware (`192.168.56.0/24`).
2. Install a target VM (for example a deliberately vulnerable-by-design training
   image you are licensed to use).
3. Confirm the host-only adapter has **no** route to the internet.
4. Scan only the lab range.

```bash
ip route            # confirm the range
nmap -sn 192.168.56.0/24
nmap -sV -oX scan.xml 192.168.56.0/24
```

## Option B — containers on your own machine

Run services you control on localhost and scan `127.0.0.1` only. This is enough
to practise parsing and service identification.

## Rules

- Written authorization first, even in a lab shared with classmates.
- Keep the lab network isolated from production and from the internet.
- Stop if a scan could affect availability; document the rate limits you used.
