"""
Deploy the before/after .esql files as Elastic Security detection rules (detection-as-code).

The repo is the source of truth: each run creates or updates one rule per file, keyed by a stable
rule_id, so re-running after editing a .esql file pushes the change.

Usage:
    python tools/deploy_rules.py                      # create/update all 6 rules
    python tools/deploy_rules.py --backfill 2026-10-11T00:00:00Z 2026-10-12T20:00:00Z
                                                      # ...and replay them over a past window
    python tools/deploy_rules.py --disable            # turn them all off (cleanup)

ES|QL rules need METADATA _id, _index, _version so each alert maps to exactly one source event
(deduplication across overlapping runs, and a link back to the event). This script adds that to
the FROM line and to the final KEEP, so the .esql files stay plain runnable queries.
"""
import argparse
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from measure import auth_header  # noqa: E402

KIBANA = "http://localhost:5601"
REPO = Path(__file__).resolve().parent.parent
TAG = "alert-tuning-lab"

RULES = [
    # (file, rule_id, name, severity, risk)
    ("detections/before/T1059.001-powershell-encoded.esql", "atl-before-t1059-001",
     "[Before] Encoded PowerShell Command", "low", 21),
    ("detections/after/T1059.001-powershell-encoded.esql", "atl-after-t1059-001",
     "[After] Encoded PowerShell Command", "high", 73),
    ("detections/before/T1053.005-schtasks-create.esql", "atl-before-t1053-005",
     "[Before] Scheduled Task Created via schtasks.exe", "low", 21),
    ("detections/after/T1053.005-scheduled-task-created.esql", "atl-after-t1053-005",
     "[After] Scheduled Task Created", "medium", 47),
    ("detections/before/T1218.011-rundll32.esql", "atl-before-t1218-011",
     "[Before] Rundll32 Execution", "low", 21),
    ("detections/after/T1218.011-rundll32-suspicious.esql", "atl-after-t1218-011",
     "[After] Suspicious Rundll32 Execution", "high", 73),
]
TECH = {"t1059-001": ("T1059", "T1059.001", "TA0002", "Execution"),
        "t1053-005": ("T1053", "T1053.005", "TA0003", "Persistence"),
        "t1218-011": ("T1218", "T1218.011", "TA0005", "Defense Evasion")}


def kibana(method, path, body=None):
    req = urllib.request.Request(
        KIBANA + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": auth_header(), "kbn-xsrf": "true",
                 "x-elastic-internal-origin": "Kibana", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, context=ssl._create_unverified_context(), timeout=60) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def to_rule_query(path):
    lines = [l for l in (REPO / path).read_text(encoding="utf-8").splitlines()
             if not l.strip().startswith("//")]
    q = "\n".join(lines).strip()
    q = re.sub(r"^(FROM \S+)", r"\1 METADATA _id, _index, _version", q, count=1)
    q = re.sub(r"(\n\| KEEP )(.*)$", r"\1_id, _index, _version, \2", q)
    return q


def description(path):
    head = [l[2:].strip() for l in (REPO / path).read_text(encoding="utf-8").splitlines()
            if l.startswith("//")]
    return "\n".join(head) + f"\n\nSource: {path} (alert-tuning-lab repo)"


def threat(rule_id):
    t, sub, ta, ta_name = TECH[rule_id.split("-", 2)[2]]
    return [{"framework": "MITRE ATT&CK",
             "tactic": {"id": ta, "name": ta_name, "reference": f"https://attack.mitre.org/tactics/{ta}/"},
             "technique": [{"id": t, "name": t, "reference": f"https://attack.mitre.org/techniques/{t}/",
                            "subtechnique": [{"id": sub, "name": sub,
                                              "reference": f"https://attack.mitre.org/techniques/{sub.replace('.', '/')}/"}]}]}]


def deploy():
    ids = {}
    for path, rule_id, name, sev, risk in RULES:
        body = {"rule_id": rule_id, "name": name, "type": "esql", "language": "esql",
                "query": to_rule_query(path), "description": description(path),
                "severity": sev, "risk_score": risk, "interval": "1h", "from": "now-1h",
                "max_signals": 1000, "enabled": True,
                "tags": [TAG, "before" if "/before/" in path else "after"],
                "threat": threat(rule_id)}
        code, existing = kibana("GET", f"/api/detection_engine/rules?rule_id={rule_id}")
        code, res = kibana("PUT" if code == 200 else "POST", "/api/detection_engine/rules", body)
        if code != 200:
            sys.exit(f"FAILED {name}: {code} {json.dumps(res)[:600]}")
        ids[rule_id] = res["id"]
        print(f"ok  {name:52} id={res['id']}")
    return ids


def backfill(ids, start, end):
    body = [{"rule_id": i, "ranges": [{"start": start, "end": end}]} for i in ids.values()]
    for path in ("/api/alerting/rules/backfill/_schedule", "/internal/alerting/rules/backfill/_schedule"):
        code, res = kibana("POST", path, body)
        if code != 404:
            break
    print(f"backfill {start} -> {end}: HTTP {code}")
    print(json.dumps(res, indent=1)[:1500])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backfill", nargs=2, metavar=("START", "END"))
    ap.add_argument("--disable", action="store_true")
    a = ap.parse_args()
    if a.disable:
        for _, rule_id, name, *_ in RULES:
            code, _ = kibana("PATCH", "/api/detection_engine/rules", {"rule_id": rule_id, "enabled": False})
            print(f"{code}  disabled {name}")
        return
    ids = deploy()
    if a.backfill:
        backfill(ids, *a.backfill)


if __name__ == "__main__":
    main()
