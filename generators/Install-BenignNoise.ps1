<#
.SYNOPSIS
    Installs a realistic benign-activity baseline ("Contoso IT" fake vendor tooling) on a lab VM.

.DESCRIPTION
    Tuning is about separating malicious from benign activity that LOOKS IDENTICAL. A lab with only
    attack telemetry has nothing to tune against, so this script makes the VM behave like a managed
    corporate endpoint: inventory agents, software updaters, backup jobs, and an admin running scripts.

    Everything runs from Windows Task Scheduler, the way real software does, so the process tree is
    the realistic one:  svchost.exe (Schedule) -> powershell.exe / schtasks.exe / sc.exe / rundll32.exe
    That is the SAME parent chain the Atomic Red Team tests produce. That overlap is the point.

    Run once per VM, in an elevated PowerShell:
        & \\VBOXSVR\generators\Install-BenignNoise.ps1

    Every job appends a line to C:\ProgramData\ContosoIT\noise-log.csv - the ground truth of what
    benign activity ran and when.

    WHAT RUNS (each trigger gets a random delay so runs are not perfectly regular):

    Job          Runs as      Every   Techniques it overlaps with
    -----------  -----------  ------  ------------------------------------------------------------
    Inventory    SYSTEM       15 min  T1059.001 - IDENTICAL -EncodedCommand every run, every host
    Updater      SYSTEM       30 min  T1053.005 (schtasks.exe /create /f), T1543.003 (sc.exe create
                                      / delete, alternating), msiexec /qn
    Backup       svc_backup   60 min  T1053.005 via the PowerShell API (no schtasks.exe at all),
                                      bulk file write + delete (~300 files)
    Maintenance  SYSTEM       20 min  T1218.011 rundll32 / regsvr32 the way Windows maintenance
                                      and installers call them (one picked at random per run)
    AdminScript  it.admin     45 min  T1059.001 - an RMM-style tool spawning -EncodedCommand
                                      children whose content VARIES every run, plus discovery cmds
    ReportTool   SYSTEM       2 hrs   ONLY on TUNING-HOST3: a rare-but-legitimate tool. Exists so
                                      the prevalence baseline has a benign rarity to (wrongly) flag

.NOTES
    Remove with Remove-BenignNoise.ps1, or revert the VM snapshot.
    Lab only. Creates two local accounts with random passwords nobody ever sees.
#>
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

$root = 'C:\ProgramData\ContosoIT'
$jobs = "$root\jobs"

# If the jobs are already installed, show their state BEFORE re-registering (diagnostics on re-run)
$existing = Get-ScheduledTask -TaskPath '\ContosoIT\' -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Existing job state on $env:COMPUTERNAME (before re-install):" -ForegroundColor Yellow
    $existing | ForEach-Object {
        $i = $_ | Get-ScheduledTaskInfo
        [pscustomobject]@{ Task = $_.TaskName; State = $_.State; LastRun = $i.LastRunTime; Result = $i.LastTaskResult
                           Next = $i.NextRunTime; RepeatFor = $_.Triggers[0].Repetition.Duration }
    } | Format-Table -AutoSize | Out-String | Write-Host
}
New-Item -ItemType Directory -Force -Path $jobs, "$root\bin", "$root\backup", "$root\inventory" | Out-Null

# ---------------------------------------------------------------------------------------------
# Local accounts - so activity comes from more than one user, like a real fleet.
# Random passwords; Task Scheduler stores them, nobody needs to know them.
# ---------------------------------------------------------------------------------------------
function New-RandomPassword { -join ((48..57 + 65..90 + 97..122 + 33, 35, 36, 37) | Get-Random -Count 24 | ForEach-Object { [char]$_ }) + 'aA1!' }

$accounts = @{}
foreach ($name in 'svc_backup', 'it.admin') {
    $pw = New-RandomPassword
    $sec = ConvertTo-SecureString $pw -AsPlainText -Force
    if (Get-LocalUser -Name $name -ErrorAction SilentlyContinue) { Set-LocalUser -Name $name -Password $sec }
    else { New-LocalUser -Name $name -Password $sec -PasswordNeverExpires -Description 'Contoso IT lab account' | Out-Null }
    $accounts[$name] = $pw
}
Add-LocalGroupMember -Group Administrators -Member 'it.admin' -ErrorAction SilentlyContinue

# svc_backup is a normal user, so it needs "Log on as a batch job" (SeBatchLogonRight) to run
# scheduled tasks. Task Scheduler does NOT grant this automatically - without it every run fails
# with Security 4625, logon type 4, status 0xC000015B (found 2026-10-11).
$sid = (Get-LocalUser -Name 'svc_backup').SID.Value
$inf = "$env:TEMP\contoso-rights.inf"
secedit /export /cfg $inf /areas USER_RIGHTS | Out-Null
$policy = Get-Content $inf
if (-not ($policy -match "SeBatchLogonRight.*$sid")) {
    if ($policy -match '^SeBatchLogonRight') { $policy = $policy -replace '^(SeBatchLogonRight = .*)$', "`$1,*$sid" }
    else { $policy = $policy -replace '^\[Privilege Rights\]$', "[Privilege Rights]`r`nSeBatchLogonRight = *$sid" }
    $policy | Set-Content $inf -Encoding Unicode
    secedit /configure /db "$env:TEMP\contoso-rights.sdb" /cfg $inf /areas USER_RIGHTS | Out-Null
}
Remove-Item $inf, "$env:TEMP\contoso-rights.sdb" -ErrorAction SilentlyContinue

# svc_backup only needs to write its own folders (and the shared log)
icacls "$root\backup" /grant 'svc_backup:(OI)(CI)M' | Out-Null
icacls $root /grant 'svc_backup:(OI)(CI)RX' | Out-Null
New-Item -ItemType File -Force -Path "$root\noise-log.csv" | Out-Null
icacls "$root\noise-log.csv" /grant 'Users:M' | Out-Null

# ---------------------------------------------------------------------------------------------
# Shared logging helper - dot-sourced by every job
# ---------------------------------------------------------------------------------------------
@'
function Write-NoiseLog([string]$Job, [string]$Detail) {
    $line = '{0},{1},{2},{3},"{4}"' -f (Get-Date).ToUniversalTime().ToString('o'), $env:COMPUTERNAME, $Job, $env:USERNAME, ($Detail -replace '"', "'")
    for ($i = 0; $i -lt 5; $i++) { try { Add-Content -Path 'C:\ProgramData\ContosoIT\noise-log.csv' -Value $line -ErrorAction Stop; return } catch { Start-Sleep -Milliseconds 200 } }
}
'@ | Set-Content "$jobs\common.ps1"

# ---------------------------------------------------------------------------------------------
# Job: Updater - mimics Google/Adobe-style updaters
# ---------------------------------------------------------------------------------------------
@'
. C:\ProgramData\ContosoIT\jobs\common.ps1
$exe = 'C:\ProgramData\ContosoIT\bin\ContosoUpdate.exe'

# Updaters re-register their own tasks with /f on every check (this is exactly what GoogleUpdate does)
schtasks.exe /create /tn 'ContosoUpdater\ContosoUpdateTaskMachineCore' /tr "`"$exe`" /c" /sc daily /st 03:00 /ru SYSTEM /rl HIGHEST /f | Out-Null
schtasks.exe /create /tn 'ContosoUpdater\ContosoUpdateTaskMachineUA'   /tr "`"$exe`" /ua /installsource scheduler" /sc hourly /ru SYSTEM /f | Out-Null
Write-NoiseLog 'Updater' 'schtasks /create x2'

# Version bump: the updater service is removed and recreated (alternates each run)
if (Get-Service -Name ContosoUpdateSvc -ErrorAction SilentlyContinue) {
    sc.exe delete ContosoUpdateSvc | Out-Null
    Write-NoiseLog 'Updater' 'sc delete ContosoUpdateSvc'
} else {
    sc.exe create ContosoUpdateSvc binPath= "`"$exe`" /svc" start= demand DisplayName= 'Contoso Update Service' | Out-Null
    sc.exe description ContosoUpdateSvc 'Keeps Contoso software up to date.' | Out-Null
    Write-NoiseLog 'Updater' 'sc create ContosoUpdateSvc'
}

# Installer housekeeping: quiet uninstall of a product that is no longer present (harmless no-op)
Start-Process msiexec.exe -ArgumentList '/x {6B1E0F2A-6C3D-4E8B-9A71-C0A7D0C0FFEE} /qn /norestart' -Wait
Write-NoiseLog 'Updater' 'msiexec /x /qn'
'@ | Set-Content "$jobs\updater.ps1"

# ---------------------------------------------------------------------------------------------
# Job: Backup - bulk file churn + a task created through the API instead of schtasks.exe
# ---------------------------------------------------------------------------------------------
@'
. C:\ProgramData\ContosoIT\jobs\common.ps1
$stage = "C:\ProgramData\ContosoIT\backup\staging-$(Get-Date -Format yyyyMMdd-HHmmss)"
New-Item -ItemType Directory -Path $stage | Out-Null
1..300 | ForEach-Object { Set-Content -Path "$stage\chunk_$_.bak" -Value ([guid]::NewGuid().ToString() * 20) }
Write-NoiseLog 'Backup' "wrote 300 files to $stage"

# Retention: keep the 2 newest staging folders, delete the rest (mass delete)
Get-ChildItem 'C:\ProgramData\ContosoIT\backup' -Directory | Sort-Object CreationTime -Descending |
    Select-Object -Skip 2 | ForEach-Object { Remove-Item $_.FullName -Recurse -Force; Write-NoiseLog 'Backup' "deleted $($_.Name)" }

# Schedule a one-off verify pass for this backup set through the Task Scheduler API - NO schtasks.exe
# process is created, so only Security 4698 / the task file write records it. Remove the previous one.
Get-ScheduledTask -TaskName 'ContosoBackupVerify_*' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false
$name = "ContosoBackupVerify_$(Get-Date -Format yyyyMMddHHmm)"
$act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -Command `"Get-ChildItem '$stage' | Measure-Object | Out-Null`""
Register-ScheduledTask -TaskName $name -Action $act -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(10)) | Out-Null
Write-NoiseLog 'Backup' "registered $name via API"
'@ | Set-Content "$jobs\backup.ps1"

# ---------------------------------------------------------------------------------------------
# Job: Maintenance - LOLBins invoked the way Windows and installers really invoke them
# ---------------------------------------------------------------------------------------------
@'
. C:\ProgramData\ContosoIT\jobs\common.ps1
$calls = @(
    @{ exe = 'rundll32.exe'; args = 'advapi32.dll,ProcessIdleTasks' },                       # idle maintenance
    @{ exe = 'rundll32.exe'; args = 'C:\Windows\System32\inetcpl.cpl,ClearMyTracksByProcess 8' }, # temp-file cleanup
    @{ exe = 'rundll32.exe'; args = 'C:\Windows\System32\shell32.dll,SHCreateLocalServerRunDll {9aa46009-3ce0-458a-a354-715610a075e6}' },
    @{ exe = 'regsvr32.exe'; args = '/s C:\Windows\System32\msxml3.dll' },                   # installer re-registering a COM dll
    @{ exe = 'regsvr32.exe'; args = '/s C:\Windows\System32\jscript.dll' }
)
$c = $calls | Get-Random
$p = Start-Process $c.exe -ArgumentList $c.args -PassThru
if (-not $p.WaitForExit(60000)) { $p.Kill() }
Write-NoiseLog 'Maintenance' "$($c.exe) $($c.args)"
'@ | Set-Content "$jobs\maintenance.ps1"

# ---------------------------------------------------------------------------------------------
# Job: AdminScript - an RMM agent pushing encoded PowerShell that differs every run
# ---------------------------------------------------------------------------------------------
@'
. C:\ProgramData\ContosoIT\jobs\common.ps1
$checks = @(
    "Get-LocalGroupMember -Group Administrators | Select-Object Name | Out-Null",
    "Get-Service | Where-Object Status -eq 'Stopped' | Measure-Object | Out-Null",
    "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5 | Out-Null",
    "Get-NetIPConfiguration | Out-Null; Test-NetConnection 192.168.1.160 -Port 9200 -InformationLevel Quiet | Out-Null",
    "Get-WinEvent -LogName System -MaxEvents 50 | Group-Object Id | Out-Null"
)
$ticket = 'CHG{0:D6}' -f (Get-Random -Maximum 999999)
$script = "# RMM ticket $ticket run $(Get-Date -Format o)`n" + (($checks | Get-Random -Count 2) -join "`n")
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
Start-Process powershell.exe -ArgumentList "-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand $enc" -Wait -WindowStyle Hidden
Write-NoiseLog 'AdminScript' "encoded child for $ticket"

# Admins also poke around with plain discovery commands
foreach ($cmd in 'whoami /groups', 'ipconfig /all', 'net localgroup administrators') { cmd.exe /c $cmd | Out-Null }
Write-NoiseLog 'AdminScript' 'discovery commands'
'@ | Set-Content "$jobs\adminscript.ps1"

# ---------------------------------------------------------------------------------------------
# Job: ReportTool - rare but legitimate, only on one host
# ---------------------------------------------------------------------------------------------
@'
. C:\ProgramData\ContosoIT\jobs\common.ps1
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Get-CimInstance Win32_Printer | Export-Csv C:\ProgramData\ContosoIT\inventory\printers.csv -NoTypeInformation"))
Start-Process powershell.exe -ArgumentList "-NoProfile -WindowStyle Hidden -EncodedCommand $enc" -Wait -WindowStyle Hidden
schtasks.exe /create /tn 'ContosoIT\LegacyPrinterReport' /tr 'powershell.exe -NoProfile -File C:\ProgramData\ContosoIT\jobs\reporttool.ps1' /sc weekly /d MON /st 06:00 /ru SYSTEM /f | Out-Null
Write-NoiseLog 'ReportTool' 'printer report + task refresh'
'@ | Set-Content "$jobs\reporttool.ps1"

# ---------------------------------------------------------------------------------------------
# Inventory: the encoded command is FIXED - byte-identical every run, on every host.
# This is the "repeated identical activity" a prevalence baseline should learn is normal.
# Kept SHORT on purpose: a ~1,300-char -EncodedCommand in the task action failed every run
# (found 2026-10-11), so the encoded command just calls the script file, like real agents do.
# ---------------------------------------------------------------------------------------------
@'
$o = [ordered]@{ Host = $env:COMPUTERNAME; OS = (Get-CimInstance Win32_OperatingSystem).Caption
  Disks = Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID, FreeSpace, Size
  Services = (Get-Service | Measure-Object).Count; Hotfixes = (Get-HotFix | Measure-Object).Count }
$o | ConvertTo-Json -Depth 3 | Set-Content C:\ProgramData\ContosoIT\inventory\latest.json
. C:\ProgramData\ContosoIT\jobs\common.ps1; Write-NoiseLog 'Inventory' 'encoded inventory'
'@ | Set-Content "$jobs\inventory.ps1"
$inventoryEnc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('& C:\ProgramData\ContosoIT\jobs\inventory.ps1'))

# ---------------------------------------------------------------------------------------------
# Register the scheduled tasks
# ---------------------------------------------------------------------------------------------
function Register-NoiseTask {
    param($Name, $Arguments, [int]$EveryMinutes, $User = 'SYSTEM')
    $action   = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $Arguments
    # Explicit 30-day repetition + StartWhenAvailable: without them the jobs stopped running after
    # the VMs were rebooted (found 2026-10-11, after the expired-evaluation hourly shutdowns).
    $trigger  = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes((Get-Random -Minimum 1 -Maximum 6)) `
                    -RepetitionInterval (New-TimeSpan -Minutes $EveryMinutes) -RepetitionDuration (New-TimeSpan -Days 30) `
                    -RandomDelay (New-TimeSpan -Minutes ([math]::Max(1, [int]($EveryMinutes / 5))))
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
                    -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -MultipleInstances IgnoreNew
    $taskPath = '\ContosoIT\'
    if ($User -eq 'SYSTEM') {
        Register-ScheduledTask -TaskName $Name -TaskPath $taskPath -Action $action -Trigger $trigger -Settings $settings -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
    } else {
        Register-ScheduledTask -TaskName $Name -TaskPath $taskPath -Action $action -Trigger $trigger -Settings $settings -User $User -Password $accounts[$User] -RunLevel Highest -Force | Out-Null
    }
    Write-Host "  registered $taskPath$Name  (every $EveryMinutes min as $User)"
}

$file = '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\ProgramData\ContosoIT\jobs\'
Write-Host "Registering Contoso IT benign jobs on $env:COMPUTERNAME..." -ForegroundColor Cyan
Register-NoiseTask 'InventoryAgent'  "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand $inventoryEnc" 15
Register-NoiseTask 'UpdateCheck'     "${file}updater.ps1"     30
Register-NoiseTask 'BackupJob'       "${file}backup.ps1"      60 'svc_backup'
Register-NoiseTask 'Maintenance'     "${file}maintenance.ps1" 20
Register-NoiseTask 'RmmAgent'        "${file}adminscript.ps1" 45 'it.admin'
if ($env:COMPUTERNAME -eq 'TUNING-HOST3') {
    Register-NoiseTask 'LegacyPrinterReport' "${file}reporttool.ps1" 120
}

# Smoke test the job most likely to break (non-admin account, ~300 file writes)
Write-Host "`nTest-running BackupJob as svc_backup (up to 90s)..."
Start-ScheduledTask -TaskPath '\ContosoIT\' -TaskName 'BackupJob'
for ($i = 0; $i -lt 18; $i++) {
    Start-Sleep 5
    $info = Get-ScheduledTaskInfo -TaskPath '\ContosoIT\' -TaskName 'BackupJob'
    if ((Get-ScheduledTask -TaskPath '\ContosoIT\' -TaskName 'BackupJob').State -ne 'Running' -and $info.LastTaskResult -ne 267011) { break }
}
if ($info.LastTaskResult -eq 0) { Write-Host "BackupJob: success" -ForegroundColor Green }
else { Write-Host ("BackupJob: FAILED, result {0} - check the task's History tab" -f $info.LastTaskResult) -ForegroundColor Red }

Write-Host "`nDone. Benign activity starts within ~5 minutes." -ForegroundColor Green
Write-Host "Ground-truth log: $root\noise-log.csv"
