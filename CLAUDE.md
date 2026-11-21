# CLAUDE.md: Guardian Angel

## Purpose
Guardian Angel is a free, open-source (GPL-3.0-or-later) self-control app for Windows 11. It locks the PC to a DNS filter **the user brings** (CleanBrowsing, Cloudflare for Families, NextDNS, AdGuard Home, Pi-hole...), and it closes the ways around that filter. It never filters anything itself. There is no server, no account and no backend: everything runs locally. It's made for God, not profit.

## Design rules (apply to EVERY change)
1. **Tightening is instant, loosening is delayed.** In this project, the only instant tightenings are a longer delay and cancelling a pending change. Every other change waits out the delay, or needs a partner code. The owner decided this; don't add new "instant" changes without asking.
2. **Fail closed.** If something breaks, the internet stays filtered or blocked, never unfiltered. If state can't be read, the service enters Safe-Locked mode and changes nothing.
3. **The service decides; the UI only asks.** Every rule lives in `GuardianAngel.Core` (`LockEngine`, `IChangeType`). The UI is untrusted.
4. **Monotonic time only** for delays and lockouts (`IMonotonicClock`, credited milliseconds persisted every 15 s). Never compute a delay from wall-clock dates. Off-time counts only when verified by TLS-authenticated time.
5. **No master key, backdoor or hidden bypass in Release builds.** The only bypass is `GA_DEBUG_BYPASS`, defined only in Debug. `scripts/Check-NoBypass.ps1` and a build-time check enforce this.
6. **Updates never open the lock.** State lives in `%ProgramData%\GuardianAngel`, which the installer never touches. MajorUpgrade replaces binaries only.
7. Plain language in every user-facing string. No jargon.

## Architecture
```
src/GuardianAngel.Core              Pure logic, any OS: LockEngine, ChangeQueue, change types, TOTP, firewall/browser/hosts
                                    planners, DNS probes and the connection test, IPC protocol, state store, accountability log.
src/GuardianAngel.Platform.Windows  Win32: WFP firewall (Native/Wfp.cs), DNS (SetInterfaceDnsSettings + netsh), browser
                                    policies, hosts guard, DPAPI (SYSTEM scope), ACLs, service hardening, guardian, MSI uninstaller.
src/GuardianAngel.Service           LocalSystem service: engine tick (1 s), reconcile (10 s + network/hosts events), IPC,
                                    watchdog guardian, reachability probe, trusted-time worker.
src/GuardianAngel.Watchdog          Second LocalSystem service: restores the main service (and the reverse).
src/GuardianAngel.App               WPF UI. Also the uninstall gate (`--uninstall`), which the Settings > Apps entry points to.
src/GuardianAngel.Installer         WiX v5 MSI (Windows-only build).
tests/GuardianAngel.Core.Tests      Unit tests (any OS).
tests/GuardianAngel.Windows.Tests   Interop layout + safe integration tests (Windows, admin; CI runs them).
tests/GuardianAngel.AttackTests     Bypass attempts that must fail. VM ONLY (GA_TEST_VM=1).
```
IPC: named pipe `\\.\pipe\GuardianAngel`, 4-byte length + JSON (`Core/Ipc`). Ops are listed in `Ops`.

### Adding a change type
Implement `IChangeType` in `Core/Policy`, register it in `ChangeTypeRegistry.CreateDefault()`, and add unit tests. Kinds are stored on disk, so never rename one.

## Build and test
- Any OS: `dotnet test tests/GuardianAngel.Core.Tests` (and `-c Release`).
- Whole solution builds on Linux too (`EnableWindowsTargeting`), except the installer.
- Windows: `./scripts/build.ps1 [-Configuration Debug]` → `artifacts/GuardianAngel-<ver>.msi`.
- VM: `./scripts/Invoke-VMTests.ps1` runs everything, including the attack tests. See `docs/VM-TESTING.md`.
- Every protection must have an entry in `docs/PROTECTIONS.md` and an automated test.

## Never change without asking the owner
- The tighten/loosen classification of any setting, the delay limits (`Policy/Limits.cs`), the TOTP window, or the lockout rules.
- Anything that could make Release builds contain a bypass, or weaken `Check-NoBypass.ps1`.
- The MSI `UpgradeCode` (`Package.wxs` and `MsiUninstaller.UpgradeCode`), service names, pipe name, WFP provider/sublayer GUIDs, or the state file format (add a migration instead).
- Where state is stored, or its encryption (SYSTEM-scope DPAPI + SYSTEM-only ACLs).
- Fail-closed behaviour, or anything that falls back to an unfiltered resolver.
- The signed-list public key (`Lists/SignedList.cs`), or signing/updater trust.
- License, donation links, or anything that adds a server, telemetry or an account.
