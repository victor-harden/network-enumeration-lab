import contextlib
import io
import json
import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE / "tools"))
import nmap_parse

SAMPLE = BASE / "tests" / "sample_scan.xml"


class NmapParseTests(unittest.TestCase):
    def test_parses_up_hosts_only(self):
        hosts = nmap_parse.parse_scan(SAMPLE)
        self.assertEqual(len(hosts), 2)
        self.assertNotIn("192.168.56.30", [h["address"] for h in hosts])

    def test_open_ports_only(self):
        hosts = nmap_parse.parse_scan(SAMPLE)
        ports = {p["port"] for p in hosts[0]["ports"]}
        self.assertEqual(ports, {22, 80})

    def test_service_details(self):
        hosts = nmap_parse.parse_scan(SAMPLE)
        ssh = next(p for p in hosts[0]["ports"] if p["port"] == 22)
        self.assertEqual(ssh["service"], "ssh")
        self.assertEqual(ssh["version"], "9.6")

    def test_hostname(self):
        hosts = nmap_parse.parse_scan(SAMPLE)
        self.assertEqual(hosts[0]["hostname"], "lab-web.local")

    def test_summary(self):
        hosts = nmap_parse.parse_scan(SAMPLE)
        stats = nmap_parse.summarize(hosts)
        self.assertEqual(stats["hosts_up"], 2)
        self.assertEqual(stats["open_ports"], 3)
        self.assertIn("redis", stats["services"])

    def test_json_cli(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = nmap_parse.main([str(SAMPLE), "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["summary"]["hosts_up"], 2)

    def test_missing_file(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(nmap_parse.main(["/nope/scan.xml"]), 2)


if __name__ == "__main__":
    unittest.main()
