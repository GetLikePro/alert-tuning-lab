<#
.SYNOPSIS
    Runs the selected Atomic Red Team tests one at a time, 2 minutes apart, recording exact UTC
    start/end timestamps. Those timestamps are the ground truth for "true positive" in the tuning
    measurements and the regression test.

    Run in an elevated PowerShell on the lab VM, while the Contoso benign jobs are running:
        & \\VBOXSVR\generators\Invoke-LabAtomics.ps1 -CheckOnly     # prerequisites only, runs nothing
        & \\VBOXSVR\generators\Invoke-LabAtomics.ps1                # run the tests

    Log: C:\ProgramData\AtomicRuns\atomic-runs.csv  (also printed at the end)

.NOTES
    Deliberately excluded: T1059.001-1/2/3/4/18/19/21/22 (Mimikatz, BloodHound, PowerUp, SOAPHound,
    known-malicious cmdlets) and T1053.005-13/14 (Turla samples). Always run with explicit test numbers.
#>
param([switch] $CheckOnly, [int] $GapSeconds = 120)
#Requires -RunAsAdministrator

$tests = @(
    @{ T = 'T1053.005'; N = 2 },  @{ T = 'T1053.005'; N = 4 },  @{ T = 'T1053.005'; N = 7 },
    @{ T = 'T1059.001'; N = 15 }, @{ T = 'T1059.001'; N = 17 },
    @{ T = 'T1218.011'; N = 2 },  @{ T = 'T1218.011'; N = 12 }, @{ T = 'T1218.011'; N = 15 }
)

Import-Module 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1' -Force
$logDir = 'C:\ProgramData\AtomicRuns'; New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$log = "$logDir\atomic-runs.csv"

if ($CheckOnly) {
    foreach ($t in $tests) {
        Write-Host "`n=== $($t.T)-$($t.N) prerequisites ===" -ForegroundColor Cyan
        Invoke-AtomicTest $t.T -TestNumbers $t.N -CheckPrereqs
    }
    Write-Host "`nIf any say 'Prerequisites not met', run:  Invoke-AtomicTest <T> -TestNumbers <N> -GetPrereqs" -ForegroundColor Yellow
    return
}

if (-not (Test-Path $log)) { 'host,test,start_utc,end_utc,status' | Set-Content $log }
foreach ($t in $tests) {
    $id = "$($t.T)-$($t.N)"
    Write-Host "`n=== Running $id ===" -ForegroundColor Cyan
    $start = (Get-Date).ToUniversalTime().ToString('o')
    try   { Invoke-AtomicTest $t.T -TestNumbers $t.N -TimeoutSeconds 60 -ErrorAction Stop; $status = 'ran' }
    catch { $status = "error: $($_.Exception.Message -replace ',', ';')" }
    $end = (Get-Date).ToUniversalTime().ToString('o')
    "$env:COMPUTERNAME,$id,$start,$end,$status" | Add-Content $log
    Write-Host "$id  $start -> $end  ($status)"
    # Close anything the tests popped up (calc etc.) so the next test starts clean
    Get-Process calc, CalculatorApp, notepad -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds $GapSeconds
}

Write-Host "`n=== Cleanup (removes the tasks, registry keys and files the tests created) ===" -ForegroundColor Cyan
foreach ($t in $tests) { Invoke-AtomicTest $t.T -TestNumbers $t.N -Cleanup -ErrorAction SilentlyContinue | Out-Null }
"$env:COMPUTERNAME,CLEANUP,$((Get-Date).ToUniversalTime().ToString('o')),,done" | Add-Content $log

Write-Host "`n=== Ground-truth log ===" -ForegroundColor Green
Get-Content $log
