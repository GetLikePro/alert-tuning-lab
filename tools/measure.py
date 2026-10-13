"""
Measure a detection rule's noise: runs the rule's ES|QL over a time window and reports
total firings, distinct hosts, alerts per host, and the top noise sources.

Usage:
    python tools/measure.py detections/before/T1053.005-schtasks-create.esql --hours 4
    python tools/measure.py <rule.esql> --start 2026-10-12T01:00:00Z --end 2026-10-12T09:00:00Z

The rule file is used as-is up to its final KEEP line; this script swaps that KEEP for STATS
so the numbers always come from exactly the logic in the file.
"""
import argparse
import json
import os
import re
import ssl
import sys
import urllib.request
from base64 import b64encode
from pathlib import Path

# File with "Username: ..." and "Password: ..." lines (git-ignored). Override with the ES_CREDS env var.
CREDS = Path(os.environ.get("ES_CREDS", Path(__file__).resolve().parent.parent / "credentials.txt"))
ES = "https://localhost:9200/_query"


def auth_header():
    text = CREDS.read_text()
    user = re.search(r"^Username:\s*(.+)$", text, re.M).group(1).strip()
    pw = re.search(r"^Password:\s*(.+)$", text, re.M).group(1).strip()
    return "Basic " + b64encode(f"{user}:{pw}".encode()).decode()


def esql(query):
    req = urllib.request.Request(
        ES, data=json.dumps({"query": query}).encode(),
        headers={"Content-Type": "application/json", "Authorization": auth_header()})
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE  # lab self-signed cert
    with urllib.request.urlopen(req, context=ctx, timeout=120) as r:
        body = json.load(r)
    cols = [c["name"] for c in body["columns"]]
    return [dict(zip(cols, row)) for row in body["values"]]


def rule_body(path):
    lines = [l for l in Path(path).read_text(encoding="utf-8").splitlines() if not l.strip().startswith("//")]
    text = "\n".join(lines)
    return re.split(r"\n\|\s*KEEP\b", text)[0].strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("rule")
    ap.add_argument("--hours", type=float, help="window = last N hours")
    ap.add_argument("--start", help="ISO8601 UTC start")
    ap.add_argument("--end", help="ISO8601 UTC end")
    ap.add_argument("--top", type=int, default=8)
    a = ap.parse_args()

    if a.hours:
        window = f'@timestamp > NOW() - {int(a.hours * 60)} minutes'
        label = f"last {a.hours:g}h"
    elif a.start and a.end:
        window = f'@timestamp >= "{a.start}" AND @timestamp < "{a.end}"'
        label = f"{a.start} -> {a.end}"
    else:
        sys.exit("give --hours or --start/--end")

    base = rule_body(a.rule) + f"\n| WHERE {window}"
    total = esql(base + "\n| STATS firings = COUNT(*), hosts = COUNT_DISTINCT(host.name)")[0]
    print(f"\n=== {Path(a.rule).name}  ({label}) ===")
    print(f"Firings: {total['firings']}   Hosts: {total['hosts']}   "
          f"Alerts per host: {total['firings'] / total['hosts'] if total['hosts'] else 0:.1f}")

    print("\nPer host:")
    for r in esql(base + "\n| STATS n = COUNT(*) BY host.name | SORT n DESC"):
        print(f"  {r['n']:5}  {r['host.name']}")

    print("\nParent -> user:")
    for r in esql(base + f"\n| STATS n = COUNT(*) BY process.parent.name, user.name | SORT n DESC | LIMIT {a.top}"):
        print(f"  {r['n']:5}  {r['process.parent.name']} -> {r['user.name']}")

    print("\nTop command lines:")
    for r in esql(base + f"\n| STATS n = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY process.command_line | SORT n DESC | LIMIT {a.top}"):
        cl = (r["process.command_line"] or "")
        print(f"  {r['n']:5}  ({r['hosts']} hosts)  {cl[:150]}{'...' if len(cl) > 150 else ''}")


if __name__ == "__main__":
    main()
