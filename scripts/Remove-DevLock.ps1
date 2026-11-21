<#
.SYNOPSIS
  DEBUG BUILDS ONLY, TEST VM ONLY: unlocks everything through the debug bypass, then uninstalls.
.DESCRIPTION
  Release builds don't contain the debug bypass, so this script does nothing to them (the service refuses).
  If the service isn't running at all, restore your VM checkpoint instead.
#>
$ErrorActionPreference = 'Stop'
if (-not (Test-Path 'HKLM:\SOFTWARE\GuardianAngelTestVM')) { throw 'Not a test VM.' }

$pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'GuardianAngel', [System.IO.Pipes.PipeDirection]::InOut)
$pipe.Connect(5000)
$json = [Text.Encoding]::UTF8.GetBytes('{"v":1,"op":"debug.unlockAll"}')
$pipe.Write([BitConverter]::GetBytes([int]$json.Length), 0, 4)
$pipe.Write($json, 0, $json.Length)
$pipe.Flush()
$len = New-Object byte[] 4
[void]$pipe.Read($len, 0, 4)
$body = New-Object byte[] ([BitConverter]::ToInt32($len, 0))
$read = 0; while ($read -lt $body.Length) { $read += $pipe.Read($body, $read, $body.Length - $read) }
$pipe.Dispose()
$reply = [Text.Encoding]::UTF8.GetString($body)
Write-Host $reply
if ($reply -notmatch '"ok":true') { throw 'The service refused (this is expected for Release builds). Restore your VM checkpoint.' }

Start-Sleep -Seconds 3
$product = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall |
  Where-Object { $_.PSChildName -like '{*' -and (Get-ItemProperty $_.PSPath).DisplayName -eq 'Guardian Angel' } |
  Select-Object -First 1
if ($product) { Start-Process msiexec.exe -ArgumentList "/x $($product.PSChildName) /qb" -Wait }
Write-Host 'Unlocked and uninstalled.'
