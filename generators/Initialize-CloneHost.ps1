<#
.SYNOPSIS
    One-time setup for a linked clone of "Windows Lab ": unique hostname + fresh Elastic Agent identity.

.DESCRIPTION
    A linked clone is a byte-for-byte copy of the original VM, so out of the box it has the SAME
    computer name and the SAME Elastic Agent ID. In the logs, three clones would look like one host
    and every per-host number in the tuning lab would be wrong. This script fixes both.

    Run inside each CLONE (not the original), in an elevated PowerShell:
        & \\VBOXSVR\generators\Initialize-CloneHost.ps1 -NewName TUNING-HOST2
    The Fleet enrollment token is read from enrollment-token.txt next to this script (git-ignored).

.NOTES
    Reboots the VM when done.
#>
param(
    [Parameter(Mandatory)] [string] $NewName,
    [string] $EnrollmentToken = (Get-Content (Join-Path $PSScriptRoot 'enrollment-token.txt') -Raw).Trim(),
    [string] $FleetUrl = 'https://192.168.1.160:8220'
)

$ErrorActionPreference = 'Stop'
$agent = 'C:\Program Files\Elastic\Agent\elastic-agent.exe'

# --force replaces the copied enrollment, so Fleet issues this clone its own agent ID.
# --insecure because the lab uses self-signed certificates (lab only).
Write-Host "Re-enrolling Elastic Agent with Fleet..." -ForegroundColor Cyan
& $agent enroll --url=$FleetUrl --enrollment-token=$EnrollmentToken --insecure --force
if ($LASTEXITCODE -ne 0) { throw "Agent enrollment failed (exit $LASTEXITCODE)" }

Write-Host "Renaming $env:COMPUTERNAME -> $NewName and rebooting..." -ForegroundColor Cyan
Rename-Computer -NewName $NewName -Force -Restart
