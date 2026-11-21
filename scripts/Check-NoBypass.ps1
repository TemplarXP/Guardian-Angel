<#
.SYNOPSIS
  Fails if any binary contains the DEBUG bypass. Run on every Release build (CI does this automatically).
#>
param([Parameter(Mandatory)] [string] $Path)
$ErrorActionPreference = 'Stop'
$markers = 'GA-DEBUG-BYPASS-PRESENT', 'debug.unlockAll'
$found = @()
foreach ($file in Get-ChildItem $Path -Recurse -Include *.dll, *.exe) {
  $bytes = [IO.File]::ReadAllBytes($file.FullName)
  $utf16 = [Text.Encoding]::Unicode.GetString($bytes)
  $utf8 = [Text.Encoding]::UTF8.GetString($bytes)
  foreach ($m in $markers) {
    if ($utf16.Contains($m) -or $utf8.Contains($m)) { $found += "$($file.Name): $m" }
  }
}
if ($found.Count -gt 0) {
  $found | ForEach-Object { Write-Error "Debug bypass found in Release build: $_" -ErrorAction Continue }
  throw 'Release build contains the debug bypass. It must never ship.'
}
Write-Host 'OK: no debug bypass in Release binaries.'
