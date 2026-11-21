<#
.SYNOPSIS
  Installs a Guardian Angel MSI. Run inside your TEST VM only, as Administrator.
#>
param([Parameter(Mandatory)] [string] $Msi)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path 'HKLM:\SOFTWARE\GuardianAngelTestVM')) {
  Write-Warning 'This does not look like a Guardian Angel test VM.'
  Write-Warning 'Create the marker first (inside the VM only):  New-Item HKLM:\SOFTWARE\GuardianAngelTestVM'
  throw 'Refusing to install outside a test VM.'
}
Start-Process msiexec.exe -ArgumentList "/i `"$Msi`" /qb /l*v `"$env:TEMP\GuardianAngel-install.log`"" -Wait -Verb RunAs
Get-Service GuardianAngel, GuardianAngelWatchdog | Format-Table Name, Status, StartType
