<#
.SYNOPSIS
  Builds Guardian Angel: publishes the service, watchdog and app, then builds the MSI installer.
.EXAMPLE
  .\scripts\build.ps1                         # Release build (no debug bypass)
  .\scripts\build.ps1 -Configuration Debug    # Debug build for VM testing (1-minute delays, debug bypass)
#>
param(
  [ValidateSet('Release', 'Debug')] [string] $Configuration = 'Release',
  [string] $Version = '0.1.0'
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$publish = Join-Path $root 'artifacts\publish'
$out = Join-Path $root 'artifacts'

if (Test-Path $publish) { Remove-Item $publish -Recurse -Force }
New-Item -ItemType Directory -Force $publish | Out-Null

foreach ($proj in 'GuardianAngel.Service', 'GuardianAngel.Watchdog', 'GuardianAngel.App') {
  Write-Host "Publishing $proj ($Configuration)..."
  dotnet publish (Join-Path $root "src\$proj\$proj.csproj") -c $Configuration -r win-x64 --self-contained true `
    -p:Version=$Version -o $publish
  if ($LASTEXITCODE -ne 0) { throw "Publishing $proj failed." }
}

if ($Configuration -eq 'Release') { & (Join-Path $PSScriptRoot 'Check-NoBypass.ps1') -Path $publish }

Write-Host 'Building the installer...'
dotnet build (Join-Path $root 'src\GuardianAngel.Installer\GuardianAngel.Installer.wixproj') -c Release `
  -p:PublishDir="$publish\" -p:ProductVersion=$Version -o (Join-Path $out 'msi')
if ($LASTEXITCODE -ne 0) { throw 'Building the installer failed.' }

$msi = Get-ChildItem (Join-Path $out 'msi') -Filter *.msi | Select-Object -First 1
$suffix = if ($Configuration -eq 'Debug') { '-DEBUG-VM-ONLY' } else { '' }
$final = Join-Path $out "GuardianAngel-$Version$suffix.msi"
Copy-Item $msi.FullName $final -Force
Write-Host "Built $final"
