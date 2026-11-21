# Testing Guardian Angel in a virtual machine

> ⚠️ **Only ever install development builds inside a test VM.** Guardian Angel is designed to be hard to remove. A Release build locked on your real PC can only be removed by waiting out your delay (or with your partner's code). The installer and test scripts refuse to run unless the VM marker in step 3 exists.

## 1. Create the VM
Pick whichever your computer supports:

| Host | Tool | Notes |
|---|---|---|
| Windows 11 Pro/Enterprise/Education | **Hyper-V** (built in) | Turn on with *Turn Windows features on or off → Hyper-V*. Use "Quick Create → Windows 11 dev environment", or a fresh install from the ISO. |
| Windows Home, macOS (Intel) or Linux | **VirtualBox** (free) or **VMware Workstation Pro** (free for personal use) | Enable TPM 2.0 + Secure Boot (EFI) in the VM settings, because Windows 11 needs them. |
| Apple Silicon Mac | **UTM** or **Parallels** with Windows 11 on ARM | Guardian Angel is x64 today. It runs under emulation for testing, but WFP behaviour on ARM64 should be checked separately. |

Download Windows 11 from microsoft.com/software-download/windows11 (ISO). A VM without activation is fine for testing.

Recommended VM: 4 GB RAM, 2 CPUs, 64 GB disk, **NAT networking** (so the VM's DNS changes never affect your real network).

Inside the VM, create **two accounts**: your own admin, and later (for Milestone 2) a standard user.

## 2. Install the tools in the VM
In an Administrator PowerShell, inside the VM:
```powershell
winget install Microsoft.DotNet.SDK.10
winget install Git.Git
git clone https://github.com/TemplarXP/Guardian-Angel.git C:\src\Guardian-Angel
```
(Or download the `installers` artifact from the latest GitHub Actions run, which contains both MSIs.)

## 3. Mark the VM as a test VM and take a checkpoint
```powershell
New-Item HKLM:\SOFTWARE\GuardianAngelTestVM
```
Then **take a checkpoint/snapshot now, before installing**: Hyper-V *Checkpoint*, VirtualBox *Take Snapshot*, VMware *Snapshot*.
Name it "Clean, before Guardian Angel". Restoring it is your guaranteed way back.

## 4. Build and install (inside the VM)
```powershell
cd C:\src\Guardian-Angel
.\scripts\build.ps1 -Configuration Debug     # Debug: 1-minute delays allowed, debug bypass included
.\scripts\Install-Dev.ps1 -Msi .\artifacts\GuardianAngel-0.1.0-DEBUG-VM-ONLY.msi
```
Open **Guardian Angel** from the Start menu. Go through the guide, choose **Simple**, and pick a preset (for example CleanBrowsing Family). Run the connection test (optionally with a domain the filter blocks). Choose a **2-minute** delay, optionally add a partner using an authenticator app on your phone, write a reflection, then press **Lock**.

## 5. Run every test with one command
```powershell
.\scripts\Invoke-VMTests.ps1 -BlockedDomain <a site your filter blocks>
```
This runs the unit tests, the Windows integration tests and the **attack tests**. Each attack test tries a known bypass, and the bypass must fail:
- plain DNS, DoT and DoH to public resolvers;
- changing an adapter's DNS;
- adding a hosts-file redirect, or moving the hosts file;
- changing a browser's DNS policy;
- stopping or deleting the service;
- turning off Windows Firewall;
- `msiexec /x` while locked;
- moving the clock forward 3 days.

Add `-AllowLockout` to also test that five wrong partner codes lock codes out for an hour.

## 6. Manual checklist
Use these as well as the automated tests, and tick each one off:
1. `nslookup example.com 8.8.8.8` times out, while `nslookup example.com` works.
2. A site your filter blocks is blocked in Edge, Chrome and Firefox. `edge://policy` shows `DnsOverHttpsMode: off`.
3. Settings → Network → adapter → DNS shows your filter, encrypted. Change it to 8.8.8.8 manually: it's back within about 10 seconds.
4. Request **Change delay → shorter**. The reflection message and typed sentence appear, and a countdown shows. Restart the VM: the countdown continues from where it was. Cancel it.
5. Request **Change delay → longer**: it applies immediately.
6. With a partner: request a change, then press **Expedite** and enter the code from the phone. It applies immediately. The same code a second time is refused.
7. Settings → Apps → Guardian Angel → Uninstall shows the "queued change" message, and nothing is removed.
8. Request **Uninstall** with a 2-minute delay, then wait. DNS goes back to automatic, the firewall rules disappear (`netsh wfp show filters` lists no "Guardian Angel" entries), and the app is removed.
9. Test a Release build too (`.\scripts\build.ps1`), starting from your clean checkpoint. `sc stop GuardianAngel` must say "Access is denied", and the minimum delay is 1 hour.

## 7. Getting out
- **Debug build:** `.\scripts\Remove-DevLock.ps1` unlocks everything through the debug bypass, then uninstalls.
- **Release build, or the service isn't running:** restore the checkpoint from step 3. There's deliberately no other way out.

## Steps that could lock you out of a real machine
- ⚠️ Running `Install-Dev.ps1` or any MSI **outside** a VM. (The scripts refuse without the VM marker, but the MSI itself doesn't check.)
- ⚠️ Pressing **Lock** with a **Release** build. You'll only get out by waiting out the delay or restoring a checkpoint.
- ⚠️ Choosing "partner code only" (no delay) and losing the authenticator. A Release build would then never unlock. In a VM, restore the checkpoint.
- ⚠️ Later milestones (managed admin, application control, WinRE off, BitLocker) will each get their own warning here before you try them.
