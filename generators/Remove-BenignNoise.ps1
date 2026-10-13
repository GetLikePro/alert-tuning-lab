<#
.SYNOPSIS
    Removes everything Install-BenignNoise.ps1 created. Run elevated inside the VM.
    (Reverting the "pre-tuning-lab" snapshot does the same thing for the original VM.)
#>
#Requires -RunAsAdministrator
Get-ScheduledTask -TaskPath '\ContosoIT\*' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false
Get-ScheduledTask -TaskPath '\ContosoUpdater\*' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false
if (Get-Service ContosoUpdateSvc -ErrorAction SilentlyContinue) { sc.exe delete ContosoUpdateSvc | Out-Null }
'svc_backup', 'it.admin' | ForEach-Object { Remove-LocalUser -Name $_ -ErrorAction SilentlyContinue }
Remove-Item 'C:\ProgramData\ContosoIT' -Recurse -Force -ErrorAction SilentlyContinue
Write-Host 'Contoso IT benign noise removed.' -ForegroundColor Green
