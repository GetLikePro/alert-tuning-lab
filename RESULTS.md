# Alert Tuning Lab — Results

Per-detection detail, including full before/after queries, is in `tuning-records/`.
Commit history shows the progression from loose to tuned.

## Setup
- **Platform:** Elastic Stack 9.2.4 (Elasticsearch, Kibana, Fleet), native Windows install,
  detections written in ES|QL. Chosen because the stack was already built and ingesting Sysmon,
  PowerShell 4104 and Windows Security logs from the detection-engineering lab.
- **Hosts:** 3 Windows 11 Enterprise (Evaluation) VMs: `windows-lab` plus linked clones
  `tuning-host2` / `tuning-host3`, each with Sysmon (SwiftOnSecurity config) and Elastic Agent.
- **Data window:** 2026-10-11T00:00Z – 2026-10-12T20:00Z. **85,120 events** from the 3 hosts
  (windows-lab 51,725, tuning-host2 16,965, tuning-host3 16,430). Hosts were **not** up for the
  whole window: data exists for 17 hours, all 3 hosts together for only 7 (clones were shut down
  overnight; see "What we could not do").
- **Benign activity** ("Contoso IT", `generators/Install-BenignNoise.ps1`), all from Task
  Scheduler with random jitter:

  | Job | Runs as | Every | Overlaps with |
  |---|---|---|---|
  | Inventory | SYSTEM | 15 min | T1059.001: identical `-EncodedCommand` every run, every host |
  | Updater | SYSTEM | 30 min | T1053.005 (`schtasks /create /f`), T1543.003, `msiexec /qn` |
  | Backup | svc_backup | 60 min | T1053.005 via PowerShell API (no schtasks.exe) |
  | Maintenance | SYSTEM | 20 min | T1218.011: rundll32 / regsvr32 the way Windows calls them |
  | AdminScript (RMM) | it.admin | 45 min | T1059.001: encoded payload different every run |
  | ReportTool | SYSTEM | 2 h | rare-but-legit tool on one host only (prevalence trap) |

  Windows itself (scheduled maintenance, SoftLanding, Google Updater) added noise we did not generate.
- **Techniques executed** (`generators/Invoke-LabAtomics.ps1`, windows-lab, 2026-10-12, 2 minutes
  apart, explicit `-TestNumbers`). Timestamps were first reconstructed from telemetry
  (Invoke-AtomicTest's `hostname`/`whoami` markers, then the payload process), then confirmed
  against the runner's own log, [`evidence/atomic-runs.csv`](evidence/atomic-runs.csv), which
  matches every slot to the second.

  | Test | Slot start (UTC) | Outcome |
  |---|---|---|
  | T1053.005-2 | 18:59:37 | ran: `schtasks /create /tn spawn` |
  | T1053.005-4 | 19:01:38 | ran: `Register-ScheduledTask` → `\AtomicTask` |
  | T1053.005-7 | 19:03:39 | **blocked by Defender** (`Trojan:Win32/Commandrob.A!ml`, 19:03:40) |
  | T1059.001-15 | 19:05:40 | ran: payload `powershell.exe -NoProfile -E ...` at 19:05:43 |
  | T1059.001-17 | 19:07:43 | ran: `powershell.exe -e ...` |
  | T1218.011-2 | 19:09:44 | **blocked by Defender** (`Trojan:Win32/Powessere.G`, 19:09:45) |
  | T1218.011-12 | 19:11:45 | ran: `shell32.dll,Control_RunDLL "...\calc.dll"` |
  | T1218.011-15 | 19:13:46 | ran: `url.dll,FileProtocolHandler calc.exe` |

  The runner's CSV confirms the test-number-to-slot mapping. For both blocked tests it records
  `Access is denied` when starting the process, and Defender's history
  ([`evidence/defender-*.csv`](evidence/), events 1116/1117) shows a detection within a second
  on the exact command line, with `DidThreatExecute = False`.

## Per detection

| | Encoded PowerShell (T1059.001) | Scheduled Task (T1053.005) | Rundll32 (T1218.011) |
|---|---|---|---|
| **Before: volume / hosts / per host** | 113 / 3 / 37.7 | 93 / 3 / 31.0 | 120 / 3 / 40.0 |
| **Before: atomics detected** | **0 of 2** | 1 of 2 | 2 of 2 |
| **Before: FP rate** | 99.1% | 98.9% | 98.3% |
| **After: volume / hosts** | 2 / 1 | 2 / 1 | 2 / 1 |
| **After: atomics detected** | **2 of 2** | **2 of 2** | 2 of 2 |
| **After: alerts that were attacks** | 2 of 2 | 2 of 2 | 2 of 2 |
| **Reduction** | 98.2% | 97.8% | 98.3% |

Overall: **326 → 6 alerts, and detected atomics 3 → 6.**

- **Encoded PowerShell:** *widen, then narrowest exceptions.* The rule was blind: `LIKE "*-enc*"`
  misses `-e`/`-E`, which both atomics used. Replaced with a regex covering every abbreviation
  of `-EncodedCommand`, `-ec`, `/`, Unicode dashes and renamed binaries. Then three exclusions
  sized to the data: exact command line (inventory), exact command line + parent (printer), and
  user + parent script (RMM, whose payload varies). Prevalence rejected: with 3 hosts any
  threshold that hides the inventory agent also hides a 2-host attacker, and it cannot handle a
  payload that is unique every run.
  *Gives up:* the RMM channel (stolen `it.admin` + `adminscript.ps1` is invisible; 4104 content
  rules compensate) and anyone who can edit `inventory.ps1`.
- **Scheduled Task:** *change the data source.* The miss (API-created task) was unfixable in the
  old data, because `schtasks.exe` never ran. Moved to Security 4698, which records that a task
  exists whatever created it. Exclusions anchor on what the task **runs** (path, args template,
  COM CLSID), never its name, since names are attacker-chosen.
  *Gives up:* task **overwrites** (4702) are invisible, and the rule depends on audit policy.
- **Rundll32:** *flip from allowlist to behavior.* The noise was ~15 shapes of Windows itself, an
  exclusion list that would never be finished. The rule now alerts only on abuse patterns:
  non-System32 paths, LOLBAS proxy-execution entry points, script protocols / ordinals, empty
  command line. Unit-tested with 15 synthetic cases.
  *Gives up:* new abuse of a System32 DLL that is not on the list (pair with a rare-usage hunt).

**Regression:** every atomic that executed fires on the tuned rules (6 of 6). The 2
Defender-blocked tests (confirmed from Defender's own history) never started a process, so there
was no telemetry to score.

## What surprised us
- **The worst rule was not the noisiest.** Encoded PowerShell looked like a noise problem
  (113 alerts) but was really a coverage problem: 0 of 2 attacks caught. Its only "hit" on an
  atomic matched the *test harness* text `-EncodedCommandParamVariation`. Volume reduction alone
  would have produced a quiet rule that still caught nothing.
- **88 of 93 scheduled-task alerts vanished for a dangerous reason.** Moving to 4698 removed the
  Contoso updater noise because `schtasks /create /f` on an existing task logs **4702 (updated),
  not 4698 (created)**. The same mechanism hides an attacker who hijacks an existing task. A big
  drop deserved scrutiny, and this is what scrutiny found.
- **Defender silently stopped 2 of 8 atomics, and the SIEM could not tell us.** The only trace in
  Elastic was `SecurityHealthHost.exe` (Defender's notification host) starting within a second of
  the test, because the Defender Operational channel is not collected. Confirmed afterwards from
  the VM: Defender blocked both on their **command line, before the process existed**, which is
  why Sysmon had no process event to send. A third detection showed up too: AMSI quarantined
  `DumpLSASS.ps1` inside the AtomicTestHarnesses module while T1059.001-15 loaded it. The
  encoded-command test itself still ran.
- **A regex bug that real data would never have exposed.** `#` is reserved in Elasticsearch
  (Lucene) regex and matches nothing, so the rundll32 ordinal check could never fire. None of the
  atomics used an ordinal; only the synthetic unit tests caught it (14/15 → fixed → 15/15).
- **The null-drop trap** (caught in design, not in production): in ES|QL, `NOT (field == "x")` is
  null when the field is missing, and null rows are dropped. 5 inventory events had no parent, so
  a naive exclusion pattern would silently hide parent-less attacks. All exclusions use
  `COALESCE(..., false)`.
- **Lab plumbing that cost the most time:** a ~16 GB Windows Update per VM, duplicated into each
  linked clone; Tenable Nessus in the base image rebuilding its plugin DB at GBs/hour; the
  Windows Evaluation license expiring (hourly forced shutdowns, fixed with `slmgr /rearm`); a
  1,295-character `-EncodedCommand` in a task action failing every run; a non-admin service
  account failing with 4625 / 0xC000015B because SeBatchLogonRight is not auto-granted; disk
  pressure on the host; and a host crash about 20 minutes after the atomics finished (no data
  lost).
- **No tuning went too far and needed correcting** against the atomics. The closest equivalent is
  the regex bug above, a silent never-fire caught by tests before it mattered.

## What we could not do
- **Tuned and validated on the same data.** No held-out window has been run through the after
  rules. "Every remaining alert was an attack" holds for *this* window only; a fresh day of noise is needed before
  claiming them generally.
- **Thin baseline.** Data in 17 hours, 3 hosts together in only 7. A real baseline would cover
  weeks, including patch days and month-end jobs.
- **We wrote the noise ourselves.** The Contoso tools were designed to collide with the rules, so
  we knew their shape in advance. Real environments have unknown tools, real users and drift.
- **3 hosts make prevalence meaningless.** "Seen on most hosts" means 2 or 3 machines.
  Prevalence baselining was considered and rejected for that reason, so the ReportTool trap
  (built to test prevalence) was never exercised, and nothing was "swallowed by the baseline"
  because no baseline-based rule was deployed.
- **Small attack sample.** 6 executed atomic tests from 3 techniques, from a single admin user on
  one host. Atomics are clean reproductions, not real adversary tradecraft (no obfuscation
  chains, no living off trusted tools).
- **Defender blocks were confirmed only after the fact**, from the VM itself
  (`Get-MpThreatDetection` and the Operational log), not from the SIEM. Defender telemetry was
  never collected during the lab.
- **Containers not covered at all.** Containerized workloads, a major real-world source of
  alert volume, have no representation in this lab.
- **Detection rules were only replayed, not run live.** All 6 rules were deployed to Elastic
  Security from the repo (`tools/deploy_rules.py`) and replayed over the window with Kibana's
  backfill; the detection engine reproduced the measured counts exactly (113/93/120 → 2/2/2).
  They have not run on live data for any length of time, and alert suppression and
  notification actions were not configured.
- **ACLs not checked.** The inventory exclusion's safety depends on
  `C:\ProgramData\ContosoIT\jobs` not being user-writable; not verified.

## Open questions
1. **Containers:** how do the same techniques apply where the noise comes from short-lived, highly
   replicated workloads (identical processes across hundreds of pods, image-level vs
   runtime-level baselining)? Not lab-tested.
2. **4702 companion rule:** how to detect task-action hijacking without drowning in Windows' own
   4702 updates (baseline each task's action and alert on change?).
3. **Held-out validation:** run the noise generator for another day and re-measure the after rules
   to see whether the tuned rules stay quiet on new data.
4. **Compensating 4104 rules:** the RMM exclusion leans on script-block logging. Which content
   patterns would we actually alert on?
5. **Should Defender Operational (1116/1117) be collected?** It would have confirmed the blocks in
   the SIEM at the time they happened, instead of by logging into the VM afterwards. In a real SOC,
   an attempt the EDR blocked is itself worth an alert.
