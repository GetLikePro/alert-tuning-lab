# Alert Tuning Lab

**Three noisy detections, measured, tuned and regression-tested against real attack telemetry.**

| Detection | Before | After | Attacks detected |
|---|---|---|---|
| Encoded PowerShell (T1059.001) | 113 alerts | **2** | 0 → **2 of 2** |
| Scheduled Task (T1053.005) | 93 alerts | **2** | 1 → **2 of 2** |
| Rundll32 (T1218.011) | 120 alerts | **2** | 2 → **2 of 2** |
| **Total** | **326** | **6** | **3 → 6** |

Alert volume dropped 98%, and the rules caught **twice as many** real attacks. Every remaining
alert is a true positive *on this lab's data window*. See [Limits](#limits) for exactly where that
claim stops.

## Why this project
Most tuning advice stops at "add exclusions until it's quiet." This lab runs the whole loop
with real numbers: generate realistic benign noise, run real attack techniques with recorded
timestamps, measure each rule, tune it, then prove the tuned rule still catches every attack.
Each decision is written down, including **what each change gives up**.

## Lab setup
```
 ┌───────────────────────────── Windows 11 host ─────────────────────────────┐
 │  Elasticsearch 9.2.4 ── Kibana 9.2.4 (Elastic Security) ── Fleet Server   │
 │          ▲                                                                │
 │          │ Elastic Agent: Sysmon, PowerShell 4104, Windows Security       │
 │  ┌───────┴──────┬──────────────┬──────────────┐  VirtualBox               │
 │  │ windows-lab  │ tuning-host2 │ tuning-host3 │  Windows 11 VMs           │
 │  │ + atomics    │              │              │                           │
 │  └──────────────┴──────────────┴──────────────┘                           │
 └───────────────────────────────────────────────────────────────────────────┘
```
- **Benign noise:** [`generators/Install-BenignNoise.ps1`](generators/Install-BenignNoise.ps1)
  turns each VM into a managed corporate endpoint ("Contoso IT"): an inventory agent, software
  updater, backup jobs, an RMM tool and a rare reporting tool. All run from Task Scheduler, so
  they produce the **same process trees attackers do**. That overlap is the point.
- **Attacks:** [`generators/Invoke-LabAtomics.ps1`](generators/Invoke-LabAtomics.ps1) runs 8
  selected [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) tests, 2 minutes
  apart, with UTC timestamps as ground truth. Tests using real offensive tooling are excluded.
- **Data:** ~85,000 events from 3 hosts.

## What each rule taught
Each rule needed a **different** tuning strategy. Full records with before/after queries are
in [`tuning-records/`](tuning-records/).

**1. Encoded PowerShell: the noisiest-looking rule was actually blind.**
`LIKE "*-enc*"` misses `-e` and `-E`. PowerShell accepts *any* abbreviation of
`-EncodedCommand`, and both attacks used the short form. Fix: widen the match first (every
abbreviation, `/`, Unicode dashes, renamed binaries), then add exclusions sized to the data:
an exact command line for the identical inventory payload, and context (user + parent script)
for an RMM tool whose payload changes every run.
→ [record](tuning-records/T1059.001-encoded-powershell.md)

**2. Scheduled Task: the rule's data source was the problem, not its logic.**
One attack created its task through the PowerShell API, so `schtasks.exe` never ran and no
query on process events could see it. Switched to Security **event 4698**, which records that a
task *exists*, whatever created it. Exclusions anchor on what a task **runs**, never its name,
because names are attacker-chosen. Found along the way: 88 alerts vanished because
`schtasks /create /f` logs **4702 (updated)**, not 4698. The same mechanism hides an attacker
who hijacks an existing task, so that blind spot is documented.
→ [record](tuning-records/T1053.005-scheduled-task.md)

**3. Rundll32: flip from allowlist to behavior.**
The noise was ~15 shapes of Windows itself, an exclusion list that would never be finished.
The rule now alerts on *how* rundll32 is used: DLLs from outside System32, known
proxy-execution entry points ([LOLBAS](https://lolbas-project.github.io/)), script protocols,
ordinals, or an empty command line.
→ [record](tuning-records/T1218.011-rundll32.md)

## How the results were validated
- **Regression test:** each tuned rule was re-run over the window containing the attacks. Every
  attack that executed still fired (6 of 6).
- **Per-exclusion accounting:** each exclusion's removals were counted separately and confirmed
  to cover only their intended benign family, with no overlaps.
- **Unit tests for detection logic:** synthetic attack variants run through the exact rule logic
  with ES|QL `ROW` ([`tests/test_rundll32.py`](tests/test_rundll32.py), 15 cases). This caught a real bug (`#` is reserved in Lucene regex, so an ordinal
  check could never fire) that the real attack data would never have exposed.
- **Detection-as-code deployment:** [`tools/deploy_rules.py`](tools/deploy_rules.py) pushes the
  `.esql` files to Elastic Security as ES|QL detection rules and replays them over the window
  with Kibana's backfill. The detection engine reproduced the offline counts exactly.



Full detail in [`RESULTS.md`](RESULTS.md), under "What surprised us" and "What we could not do".

## Repo layout
```
detections/before/   the naive rules, as first written (runnable ES|QL)
detections/after/    the tuned rules, with the reasoning in comments
tuning-records/      one record per rule: numbers, hypothesis, change, trade-offs, validation
evidence/            the atomic runner's ground-truth log and Defender's detection history
generators/          benign-noise installer and atomic test runner (lab VMs)
tools/measure.py     runs a rule over a time window and reports volume, hosts, top sources
tools/deploy_rules.py  deploys rules to Elastic Security and schedules a backfill replay
tests/               unit tests: synthetic command lines run through the rundll32 rule's logic
RESULTS.md           the full results write-up
```

## Running it
```powershell
# Credentials file with "Username: ..." / "Password: ..." lines
$env:ES_CREDS = "C:\path\to\credentials.txt"

# Measure a rule over a window
python tools/measure.py detections/after/T1218.011-rundll32-suspicious.esql `
    --start 2026-10-11T00:00:00Z --end 2026-10-12T20:00:00Z

# Unit-test the rundll32 rule's logic (needs only a running Elasticsearch)
python tests/test_rundll32.py

# Deploy all six rules to Elastic Security and replay them over the window
python tools/deploy_rules.py --backfill 2026-10-11T00:00:00Z 2026-10-12T20:00:00Z
```
Lab only. The generators create local accounts and scheduled tasks; run them in disposable VMs.

---
Built with Elastic Stack 9.2.4, Sysmon, Atomic Red Team and VirtualBox.
