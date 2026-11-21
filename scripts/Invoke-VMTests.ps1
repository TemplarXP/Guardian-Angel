<#
.SYNOPSIS
  Runs every Guardian Angel test inside a test VM, including the attack tests, with one command.
.DESCRIPTION
  Prerequisites (see docs/VM-TESTING.md):
    1. A Windows 11 VM with a checkpoint taken BEFORE installing Guardian Angel.
    2. Guardian Angel installed (a Debug build is easiest) and LOCKED with the Simple setup.
    3. The .NET 10 SDK and this repository inside the VM.
  Run from an Administrator PowerShell:  .\scripts\Invoke-VMTests.ps1 -BlockedDomain example-blocked-site.com
#>
param(
  [string] $BlockedDomain = '',
  [string] $BlockPageIps = '',
  [switch] $AllowLockout
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path 'HKLM:\SOFTWARE\GuardianAngelTestVM')) { throw 'Not a test VM (missing HKLM:\SOFTWARE\GuardianAngelTestVM).' }
$root = Split-Path -Parent $PSScriptRoot

$env:GA_TEST_VM = '1'
$env:GA_TEST_BLOCKED_DOMAIN = $BlockedDomain
$env:GA_TEST_BLOCKPAGE_IPS = $BlockPageIps
$env:GA_TEST_ALLOW_LOCKOUT = if ($AllowLockout) { '1' } else { '0' }

$failed = $false
foreach ($proj in 'GuardianAngel.Core.Tests', 'GuardianAngel.Windows.Tests', 'GuardianAngel.AttackTests') {
  Write-Host "`n=== $proj ===" -ForegroundColor Cyan
  dotnet test (Join-Path $root "tests\$proj\$proj.csproj") --logger 'console;verbosity=normal'
  if ($LASTEXITCODE -ne 0) { $failed = $true }
}
if ($failed) { throw 'Some tests failed. Read the output above.' }
Write-Host "`nAll tests passed." -ForegroundColor Green
