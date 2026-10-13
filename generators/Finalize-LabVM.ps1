<#
.SYNOPSIS
    End-of-lab step for the Windows Lab VM. Run elevated inside the VM:
        powershell -ExecutionPolicy Bypass -File \\VBoxSvr\generators\Finalize-LabVM.ps1
    1. Saves the evidence that only exists inside the VM to \\VBoxSvr\labout (repo\evidence on the host):
       the atomic ground-truth CSV and Defender's detection history (were the 2 "silent" tests blocked?).
    2. Removes the Contoso IT benign noise (Remove-BenignNoise.ps1), so the VM goes back to being a
       plain log source for the detection lab.
#>
#Requires -RunAsAdministrator
$out = '\\VBoxSvr\labout'
if (-not (Test-Path $out)) { throw "Shared folder $out not found - is 'labout' attached to the VM?" }

# 1. Evidence
$csv = 'C:\ProgramData\AtomicRuns\atomic-runs.csv'
if (Test-Path $csv) { Copy-Item $csv "$out\atomic-runs.csv" -Force; Write-Host "Saved atomic-runs.csv" }
else { Write-Warning "$csv not found" }

Get-MpThreatDetection | Select-Object InitialDetectionTime, LastThreatStatusChangeTime, ThreatID,
    ActionSuccess, ThreatStatusID, ProcessName, DomainUser, @{n = 'Resources'; e = { $_.Resources -join ' | ' } } |
    Export-Csv "$out\defender-detections.csv" -NoTypeInformation
Get-MpThreat | Select-Object ThreatID, ThreatName, SeverityID, IsActive, DidThreatExecute,
    @{n = 'Resources'; e = { $_.Resources -join ' | ' } } |
    Export-Csv "$out\defender-threats.csv" -NoTypeInformation

# Defender's own event log for the attack window (1116 = detected, 1117 = action taken)
Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1116, 1117
    StartTime = [datetime]'2026-10-12T18:50:00Z'; EndTime = [datetime]'2026-10-12T19:30:00Z' } -ErrorAction SilentlyContinue |
    Select-Object @{n = 'TimeUtc'; e = { $_.TimeCreated.ToUniversalTime().ToString('o') } }, Id, Message |
    Export-Csv "$out\defender-events.csv" -NoTypeInformation
Write-Host "Saved Defender history" -ForegroundColor Green

# 2. Remove the benign noise
& '\\VBoxSvr\generators\Remove-BenignNoise.ps1'
$left = @(Get-ScheduledTask -TaskPath '\ContosoIT\*', '\ContosoUpdater\*' -ErrorAction SilentlyContinue).Count +
        @(Get-LocalUser svc_backup, it.admin -ErrorAction SilentlyContinue).Count +
        [int][bool](Get-Service ContosoUpdateSvc -ErrorAction SilentlyContinue)
"Leftover Contoso items: $left" | Tee-Object "$out\finalize-result.txt"
Write-Host "Done. Shut the VM down (Start > Power > Shut down)." -ForegroundColor Green
