# Guardian Angel for Windows 11: Technical Plan

Status: **Milestone 1 built** (see "Decisions made during Milestone 1" at the end). Items marked **[verify in VM]** are behaviours I'm fairly but not fully sure of, and they get tested before we rely on them.

---

## 1. Key decisions

| Decision | Choice | Why |
|---|---|---|
| Runtime | **.NET 10 (LTS)**, not .NET 8 | .NET 8 support ended on 10 Nov 2026, so it no longer gets security fixes. .NET 10 is the current LTS (supported until Nov 2028). Moving later is trivial, so I can use .NET 8 if you prefer. |
| UI | **WPF** (with the open-source WPF-UI library for a Windows 11 Fluent look) | It's mature and stable, and it runs as a normal unpackaged .exe next to a Windows service with no Windows App SDK runtime to install or keep updated. It has the best tooling and docs, and it's easier for future contributors. WinUI 3 looks slightly more native, but it adds packaging/runtime complexity and has more rough edges. That's the wrong trade for a security tool. |
| Installer | **WiX Toolset v5 (MSI)** | It builds with plain `dotnet build` in GitHub Actions. It has first-class service install, conditions and custom actions, so it can **refuse uninstall unless one is due**. MajorUpgrade lets updates replace binaries without touching the lock state. |
| Interop | **CsWin32** source generator | Type-safe P/Invoke for WFP, IP Helper, DNS, NetAPI, DPAPI and ACLs, with no hand-written signatures. |
| Kernel driver | **None** | Everything uses documented user-mode APIs (WFP management API, IP Helper and so on). No driver means no driver signing and no blue-screen risk. |
| Tests | xUnit for logic (runs anywhere, including CI on Linux and Windows), plus Windows integration tests and VM-only **attack tests** (`scripts/Invoke-VMTests.ps1`, one command) | Covers every protection, as you asked. |

---

## 2. Architecture

```
          ┌──────────────────────── user session (standard user) ────────────────────────┐
          │  GuardianAngel.App (WPF)            GuardianAngel.Gate (uninstall gate)        │
          │   wizard · main screen · Learn       Settings › Apps › Uninstall points here   │
          └──────────────┬───────────────────────────────┬───────────────────────────────┘
                         │ named pipe \\.\pipe\GuardianAngel (JSON, versioned)
                         ▼
 ┌──────────────── LocalSystem ────────────────────────────────────────────────────────────┐
 │ GuardianAngel.Service                                                                    │
 │  ├─ IPC server (authenticates caller SID, validates every request)                       │
 │  ├─ Policy engine: classify Tighten / Loosen; Tighten applies now, Loosen → Change Queue │
 │  ├─ Change Queue + Delay Clock (monotonic, persisted, survives reboot)                   │
 │  ├─ TOTP verifier (partner) + lockout                                                    │
 │  ├─ Reconciler: desired state ↔ actual state, on events + every 10 s                     │
 │  │    DnsEnforcer · FirewallEnforcer(WFP) · BrowserPolicyEnforcer · HostsGuard · …       │
 │  ├─ State store (ProgramData, SYSTEM-only ACL, DPAPI, two generations + checksum)        │
 │  └─ Accountability log (hash-chained)                                                    │
 │                       ▲  private pipe \\.\pipe\GuardianAngel.wd (SYSTEM only)            │
 │                       ▼  heartbeat every 2 s                                              │
 │ GuardianAngel.Watchdog (2nd service): restarts, re-registers or restores the main service │
 │   from a hash-checked binary copy; the main service does the same for the watchdog        │
 └──────────────────────────────────────────────────────────────────────────────────────────┘
                         │ persistent + boot-time WFP filters live in the BFE (kernel)
                         ▼  → they keep blocking even if both services are stopped or deleted
```

### Folder structure

```
Guardian-Angel/
├─ CLAUDE.md                     purpose, rules, build/test, "never change without asking"
├─ README.md  LICENSE
├─ GuardianAngel.sln
├─ Directory.Build.props         shared settings; Release forbids the DEBUG bypass symbol
├─ src/
│  ├─ GuardianAngel.Core/              pure logic, no Windows calls: models, policy (tighten/loosen),
│  │                                   change queue, delay clock, TOTP, IPC contracts, log chain
│  ├─ GuardianAngel.Platform.Windows/  Win32 interop: WFP, DNS/IP Helper, registry, ACLs, DPAPI,
│  │                                   accounts (later), app control (later)
│  ├─ GuardianAngel.Service/           service host, enforcers, reconciler, IPC server
│  ├─ GuardianAngel.Watchdog/          watchdog service
│  ├─ GuardianAngel.App/               WPF UI (wizard, main screen, Learn tab, About)
│  ├─ GuardianAngel.Gate/              tiny uninstall gate exe
│  └─ GuardianAngel.Installer/         WiX v5 MSI
├─ data/lists/                   doh-resolvers.json, browsers.json, vpn-apps.json, tor.json (+ .sig)
├─ tools/GuardianAngel.Signer/   offline tool: signs lists and update manifests (Ed25519)
├─ tests/
│  ├─ GuardianAngel.Core.Tests/        unit tests (any OS)
│  ├─ GuardianAngel.Windows.Tests/     integration tests (Windows, admin, safe on CI runners)
│  └─ GuardianAngel.AttackTests/       bypass attempts that must fail (VM only, GA_TEST_VM=1)
├─ scripts/  build.ps1 · Install-Dev.ps1 · Invoke-VMTests.ps1 · Remove-DevLock.ps1 (DEBUG/VM only)
├─ docs/     PLAN.md · PROTECTIONS.md · VM-TESTING.md · CODE-SIGNING.md
└─ .github/workflows/  ci.yml · release.yml
```

---

## 3. How the parts talk to each other

**UI ↔ Service:** a named pipe `\\.\pipe\GuardianAngel`.
- Pipe ACL: SYSTEM gets full control. Interactive users can connect (read/write). Network logons are denied.
- Messages are length-prefixed JSON with a protocol version: `{ "v":1, "id":…, "op":"RequestChange", "body":{…} }`.
- The UI is **untrusted**. It only displays state and sends requests. Every rule (tighten vs loosen, delays, codes, lockouts) is enforced in the service. Patching or replacing the UI gains nothing.
- The service reads the caller's process ID and user SID from the pipe (`GetNamedPipeClientProcessId` plus impersonation) and logs them.
- Push updates: the UI subscribes, and the service streams state changes (countdowns, scan results) over the same pipe.

**Service ↔ Watchdog:**
- A second pipe, ACL'd to SYSTEM only, carries a heartbeat every 2 seconds.
- Each one also checks the other through the Service Control Manager: does it exist, are its config and binary path right, is it running.
- If the other is stopped, it's restarted. If its registration was deleted, it's recreated from a stored config. If its binary is missing or modified, it's restored from a hash-checked copy in `ProgramData\GuardianAngel\recovery\`.

**Hardening both services:**
- Start type Automatic (not delayed). Failure actions: restart, restart, restart (0 s / 0 s / 5 s).
- Registered under `SafeBoot\Minimal` and `SafeBoot\Network`.
- The service security descriptor gives Administrators and Users only `QUERY_STATUS` / `QUERY_CONFIG` / `INTERROGATE`. Only SYSTEM can stop, reconfigure or delete the service.
- `SERVICE_CONFIG_SERVICE_SID_INFO` is set so the files can be ACL'd to the service SID.

> **Honest note:** a real administrator can always eventually take ownership and remove anything. That's why Milestone 2 (managed admin, so the daily account is a *standard* user) is the core of the real protection. In Milestone 1 your account is still an admin, so M1 is tamper-*resistant*, not tamper-*proof*.

---

## 4. Change queue, delay clock, TOTP, Vault encryption

### 4.1 Change queue

```csharp
record ChangeRequest(
    Guid Id, string Kind, string SettingKey, JsonElement Parameters,
    DateTimeOffset RequestedAtUtc,        // display only
    TimeSpan RequiredDelay,               // delay in force at request time (strictest rule wins)
    TimeSpan Credited,                    // monotonic time already served
    ChangeStatus Status,                  // Pending | Applying | Applied | Cancelled | Superseded | Failed
    string? ExpeditedBy);                 // "partner" when a TOTP code was used

interface IChangeType {                   // one class per change type → easy to extend
    string Kind { get; }                  // "filter.change", "delay.change", "partner.remove", "uninstall"
    string SettingKey(JsonElement p);     // one pending change per key
    Direction Classify(LockState current, JsonElement p);   // Tighten | Loosen
    ValidationResult Validate(LockState current, JsonElement p);
    LockState Apply(LockState current, JsonElement p);      // pure: returns the new desired state
    string Describe(JsonElement p);       // plain-language text for the UI and log
}
```

- **Request flow:** UI → `Classify`.
  - **Tighten:** applied immediately and logged.
  - **Loosen:** the UI shows the reflection message and asks for the typed sentence. The service then queues the change. Any pending change with the same `SettingKey` becomes `Superseded`, so its countdown restarts.
- **Apply:** a 1-second scheduler finds due changes. Each one goes through these steps, written to disk at each step:
  1. Mark it `Applying`.
  2. Compute the new desired state.
  3. Reconcile (enforcers apply it).
  4. Verify.
  5. Mark it `Applied`.
  If verification fails, the previous (stricter) state is restored, and it retries. Fail closed.
- **Cancel** is always instant, because cancelling is tightening.
- M1 change types: `filter.change`, `delay.change`, `partner.remove`, `uninstall`. (Shortening the delay is loosening. Lengthening it is instant.)

### 4.2 Delay clock (cannot be fooled by the clock)

- Progress is measured in **credited seconds**, not by comparing wall-clock dates.
- Every tick, the service adds the elapsed time from `GetTickCount64`. That clock is monotonic, keeps running during sleep, and can't be changed by any user. The elapsed time is clamped to ≥ 0.
- `Credited` is saved to disk every 15 seconds and at shutdown (written atomically, then flushed).
- After a reboot, counting resumes from the saved value. Changing the date or time therefore has **no effect**.
- Time the PC spent switched off is the one open design choice (see **Question 5**). My recommendation: count off-time only when it can be checked against a trusted clock after boot. That clock would be the TLS-authenticated `Date` header of a few HTTPS sites, such as your filter provider's DoH endpoint. If the check isn't possible, only powered-on time counts. Fail closed: the delay can only ever take *longer*, never shorter.
- Unlock-window claim periods (M2) use the same clock.
- Time-of-day delay rules (M3) need local wall time to *choose* which delay applies.
  - Standard users can't change the system time (they lack `SeSystemtimePrivilege`), but they *can* change the time zone.
  - So the service uses the time zone saved at lock time, plus the strictest-rule-wins rule.

### 4.3 Partner TOTP (RFC 6238)

- **Secret:** 160 random bits from `RandomNumberGenerator`. HMAC-SHA1, 6 digits, 30-second step. This is the default every authenticator app supports.
- **Setup:** the service creates the secret and returns the `otpauth://totp/Guardian%20Angel:…?secret=…&issuer=Guardian%20Angel` URI **once**. The UI draws the QR code locally (QRCoder library), and the partner scans it. To confirm the scan worked, the partner then enters a valid code.
- After that, no API exists that returns the secret. It's stored encrypted (see 4.4).
- **Verification:** codes are computed for steps t-1, t and t+1 and compared in constant time. The last accepted step is saved, so **any code is accepted only once** (replay protection).
- **Lockout:** 5 wrong codes trigger a 1-hour lockout, counted on the monotonic clock and saved to disk. A reboot or clock change doesn't reset it.
- TOTP itself needs the real wall clock, but a standard user can't change it. If the clock is wrong, codes simply fail, so this also fails closed.

### 4.4 State and Vault encryption

- **A correction to the spec:** DPAPI *machine* scope (`CRYPTPROTECT_LOCAL_MACHINE`) lets **any process on the PC, run by any user,** decrypt the data. That isn't "only the service". So the plan is:
  - The service runs as LocalSystem and calls DPAPI in **user scope**, as SYSTEM. Only code running as SYSTEM can decrypt.
  - The encrypted files sit in `C:\ProgramData\GuardianAngel\state\`, with an ACL that gives SYSTEM full control and nobody else any access.
  - Each file is also HMAC-signed with a key that's itself DPAPI-protected, so changes are detected.
- State is written as two generations (A/B) with a counter. A corrupted file falls back to the other copy.
- If **both** copies are unreadable, the service enters **Safe-Locked** mode. The WFP filters stay as they are (they're persistent), all loosening is refused, and the UI tells you what happened. Fail closed.
- Trade-off to know: if Windows is reinstalled, the SYSTEM DPAPI keys are gone, so the Vault is gone too. That's correct (a wipe is the "hardest" bypass), but it's why the BitLocker key also goes on the partner's recovery sheet.

### 4.5 Accountability log (M2; the basic format starts in M1)

- An append-only JSON-lines file. Each entry is chained to the previous one: `entryHash = SHA256(prevHash ‖ entry)`.
- Each entry is also HMAC-signed with a service-only key, and the latest hash is copied to a second protected location.
- A break anywhere in the chain is detected and itself logged as tampering.
- Summary view is free. The full log needs a partner code.

---

## 5. Protections: how they work and which editions support them

| Protection | Mechanism (main Windows APIs) | Home | Pro | Ent/Edu | Level | Milestone |
|---|---|---|---|---|---|---|
| DNS lock, every adapter, IPv4 and IPv6 | `SetInterfaceDnsSettings` (IP Helper) per interface GUID. Re-applied on `NotifyIpInterfaceChange` / `NotifyUnicastIpAddressChange` / registry change notifications, plus every 10 s | ✅ | ✅ | ✅ | Guarded | 1 |
| Windows encrypted DNS (DoH) | DoH server registration (`DnsClientDohServerAddress` equivalent via the registry, `Dnscache\Parameters\DohWellKnownServers` + per-interface `DohInterfaceSettings`). Policy `DoHPolicy = 3` ("require DoH"), with no UDP fallback | ✅ | ✅ | ✅ | Locked + Guarded | 1 |
| DoT (DNS over TLS) | Native DoT exists only in newer Windows 11 builds **[verify in VM]**. Used if detected; otherwise DoH or plain DNS is offered | build-dependent | | | Locked | 1 |
| Firewall lock | **WFP** (`FwpmEngineOpen0`, own provider + sublayer, `FwpmFilterAdd0`) at `ALE_AUTH_CONNECT_V4/V6`. See the details below | ✅ | ✅ | ✅ | Locked | 1 |
| Browser secure-DNS off | HKLM policies: Chrome / Edge / Brave `DnsOverHttpsMode = off`; Firefox `DNSOverHTTPS {Enabled:false, Locked:true}`. Policy keys are guarded and re-written. New browsers come from a signed list | ✅ | ✅ | ✅ | Locked + Guarded | 1 |
| Incognito off / proxy-VPN extensions blocked (optional) | `IncognitoModeAvailability = 1`, `InPrivateModeAvailability = 1`, Firefox `DisablePrivateBrowsing`, `ExtensionInstallBlocklist` from the signed list. Chrome ignores *some* policies on PCs that aren't domain-joined **[verify in VM]** | ✅ | ✅ | ✅ | Locked | 1 (off by default) |
| Hosts guard | Watches the file (`FileSystemWatcher` + hash every 10 s) and the `Tcpip\Parameters\DataBasePath` value (which can redirect the hosts file). Lines that map to `0.0.0.0` / `127.0.0.1` are allowed, because they block (tightening). Lines that map a name to a real IP (loosening) are reverted to the last approved content | ✅ | ✅ | ✅ | Guarded | 1 |
| VPN / proxy detection | Adapter types and driver names (TAP, Wintun, WireGuard, PPP), WinHTTP and per-user proxy/PAC (the HKCU hive of each signed-in user). Warns, or blocks with WFP interface conditions | ✅ | ✅ | ✅ | Watched / Locked | 3 |
| Application control | **App Control for Business (WDAC)**: allow Windows- and Microsoft-signed code plus admin-only-writable paths (Program Files, Windows); everything else is denied. Rolled out in audit mode first, then enforced. **AppLocker** (Enterprise/Education; Pro support varies **[verify in VM]**). **SRP** fallback (all editions) | SRP (WDAC **[verify]**) | WDAC | WDAC / AppLocker | Locked | 3 |
| Block Hyper-V / Sandbox / WSL networking | Feature state checks plus a WFP block on vEthernet adapters | WSL only | ✅ | ✅ | Locked / Guarded | 3 |
| Managed admin, hidden accounts | `NetUserAdd`, `NetLocalGroup*Members`, `NetUserSetInfo` (rotation), `SpecialAccounts\UserList`, `NoLocalPasswordResetQuestions` policy, built-in Administrator disabled | ✅ | ✅ | ✅ | Locked | 2 |
| Vault | SYSTEM-scope DPAPI + ACLs (4.4). A reveal is a queued change | ✅ | ✅ | ✅ | Locked | 2 |
| BitLocker / Device Encryption | Reads status through WMI `Win32_EncryptableVolume`, then guides you | Device Encryption (hardware-dependent) | ✅ | ✅ | Manual + Watched | 3 |
| Turn off WinRE | `reagentc /disable`, re-checked on every scan | ✅ | ✅ | ✅ | Guarded | 3 |
| Protected apps | Install-folder ACLs, guarding the ARP uninstall key, process monitoring (WMI `Win32_ProcessStartTrace` / ETW) matched on path + Authenticode signer + hash | ✅ | ✅ | ✅ | Guarded | 4 |
| Uninstall gate | ARP `UninstallString` → `GuardianAngel.Gate.exe`. The MSI's own uninstall path has a custom action that asks the service and aborts unless an uninstall is *due* (upgrades are exempt) | ✅ | ✅ | ✅ | Locked | 1 |

### Firewall lock in detail (WFP)
- Our own provider and **sublayer with maximum weight**, filters at the `ALE_AUTH_CONNECT_V4/V6` and `ALE_AUTH_RECV_ACCEPT` layers:
  1. **Permit** UDP/TCP 53, TCP 853, UDP 853 (DoQ) and TCP 443 to the locked filter IPs, plus the Tailscale DNS on that path.
  2. **Block** UDP/TCP 53 and 853, and UDP 853 / 8853 / 784 (DoQ), to every other address.
  3. **Block** TCP/UDP 443 to the IPs of known public DoH resolvers and to Tor directory/relay IPs (signed, updatable list). Your own filter's IPs always win.
- The block filters are **hard blocks**: `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`. A "permit" rule anywhere else, including Windows Defender Firewall rules, can't override them, and switching off Windows Firewall doesn't touch them.
- Every filter is added twice: once **persistent** (kept by the Base Filtering Engine across reboots, service stops and even service deletion) and once **boot-time** (enforced by tcpip.sys before the BFE starts).
- **Layered fail-closed:** even if someone changes an adapter's DNS to 8.8.8.8 between checks, WFP drops the query. DNS stops working; it never goes unfiltered.
- "If no filter can be reached = block internet" adds a block-all-outbound filter. The only exceptions are the filter IPs, DHCP, loopback and the local subnet, so the connection test can keep retrying.

### A security note on plain DNS
Plain DNS (port 53) is **not authenticated**. Any device between you and the filter, such as a travel router, a phone hotspot or a reconfigured home router, can intercept a query sent to 185.228.168.168 and answer it from an unfiltered resolver. Windows would never know. Encrypted DNS (DoH with "no UDP fallback") verifies the server with TLS, which closes this. **I recommend encrypted DNS as the default whenever the filter offers it,** with plain DNS as a compatibility option (see Question 7).

---

## 6. Milestone 1 build steps (after your answers)

1. Solution skeleton, CI (build + unit tests on Windows and Linux), `CLAUDE.md`, `docs/PROTECTIONS.md`, license.
2. **Core:** state model, tighten/loosen policy, change queue with 4 change types, delay clock, TOTP, IPC contracts. Fully unit-tested, including fake-clock tests for reboots and clock changes.
3. **Service + watchdog:** hosting, mutual restore, hardened service descriptors, Safe Mode registration, protected state store, IPC server.
4. **DNS enforcer** (plain DNS + Windows DoH), reconcile loop.
5. **WFP firewall enforcer** (persistent + boot-time hard blocks), signed DoH/Tor list loader.
6. **Browser policy enforcer** and **hosts guard**.
7. **WPF app:** first-launch guide, Learn tab, Simple-path wizard with presets, connection test, delay + partner QR, reflection message, summary, Lock button; main screen with pending changes, countdowns, cancel, request change, expedite.
8. **Installer** (WiX) with the uninstall gate; service-performed uninstall.
9. **Tests:** integration tests and VM attack tests, for example: set DNS to 8.8.8.8 → must still be filtered; `nslookup x 8.8.8.8` → must fail; DoH to `dns.google` → must fail; edit hosts → reverted; `sc stop` / `sc delete` → restored, and filters still active; change the clock → countdown unaffected; reboot mid-delay → resumes; wrong code ×5 → lockout; `msiexec /x` → refused.
10. **VM guide:** Hyper-V / VirtualBox / VMware setup, checkpoints, a DEBUG-only `Remove-DevLock.ps1`, and ⚠️ markers on any step that could lock you out.

**DEBUG bypass:** compiled only when `GA_DEBUG_BYPASS` is defined, which happens only in the `Debug` configuration. A CI test scans the Release binaries and **fails the build** if the bypass operation's name or code appears anywhere in them.

---

## 7. Remaining bypasses, easiest → hardest (all milestones done, all protections on)

| # | Bypass | Why it still works / what limits it |
|---|---|---|
| 1 | **Another device** (an unlocked phone, a friend's PC, a work laptop, a library computer) | Outside this PC. The phone and router guides (M5) and your partner cover part of it. |
| 2 | **Content the filter itself allows** (web proxy sites, translators, cached pages, image search, content on allowed social/CDN domains) | Guardian Angel enforces *your* filter. It can't be stricter than the filter. Choose a filter that blocks proxy/VPN categories. |
| 3 | **Waiting out the delay or the unlock window** | This is the designed way out. Longer delays and time-of-day rules make it slower. |
| 4 | **Persuading the partner** | That's a human matter. The log shows every expedite. |
| 5 | **Remote desktop to an unfiltered machine** (browser-based remote desktop, an existing RDP client) | Works if the filter allows those domains. Block the remote-access category in your filter. App control stops new remote-desktop clients. |
| 6 | **Microsoft Store apps** (standard users can install them; some browsers have built-in VPNs or DoH) | Covered by new-browser detection + policies, the signed VPN-app list and WDAC package rules. Gaps are possible until the list is updated. Turning off the Store by policy works only on Enterprise/Education. |
| 7 | **Already-installed signed apps with their own DoH or proxy** (or DoH to an unknown, self-hosted endpoint on port 443) | 443 can't be blocked in general. Limited by app control (no new tools can run), the DoH resolver list and browser policies. |
| 8 | **DNS interception on the network** (travel router or reconfigured router answering "as" your filter) | Works only against plain DNS. **Closed by encrypted DNS with no fallback.** |
| 9 | **Abuse during a temporary-admin window** (creating another admin, a service, a task, removing filters) | A post-window audit removes unknown admins, flags new services and tasks, and re-reconciles every protection. Already-elevated processes are ended when the window closes. |
| 10 | **Booting another OS** (Linux USB, Windows installer, network boot) | Blocked by the BIOS password + USB/network boot off + Secure Boot. BitLocker makes offline file edits impossible. |
| 11 | **Reset from the recovery screen** ("Reset this PC" via Shift+Restart) | Closed by turning off WinRE, plus BitLocker and the BIOS password. |
| 12 | **An unknown Windows privilege-escalation exploit** | Rare and patched quickly. Keep Windows Update on. Report any found bypass. |
| 13 | **Clearing the BIOS password** (CMOS jumper or battery, a vendor master password, a service-centre reset) | Needs opening the case or vendor help. BitLocker still protects the data, so the only path left is wiping the drive. |
| 14 | **Physically opening the PC / wiping or replacing the drive** | This is the floor no software can stop. A full wipe means reinstalling Windows from scratch, which takes far longer than a weak moment. |

---

## 8. Code signing options (summary; full doc in M1)

- **SignPath Foundation:** free Authenticode signing for qualifying open-source projects. It signs from your GitHub Actions builds, and the private key lives in their HSM. **Best fit**, if the project is accepted.
- **Certum Open Source Code Signing:** a low-cost certificate for individual open-source developers (cloud-key option, roughly tens of euros a year).
- **Microsoft Azure Artifact (Trusted) Signing:** about US$10/month. Eligibility for individuals is limited to some countries, so check current terms.
- Regular OV certificates from commercial CAs cost hundreds per year and need an HSM token. (EV certificates no longer give instant SmartScreen reputation.)
- **Separately from Authenticode:** updates and block lists are signed with **your own Ed25519 key**. The public key is built into the app, and the private key stays offline. Guardian Angel installs or loads only files signed with that key, whatever Authenticode certificate you end up with.

---

## 9. Decisions made during Milestone 1
- **Instant changes:** only a longer delay, plus cancelling a pending change. Everything else waits out the delay (owner's decision).
- **Defaults chosen:** .NET 10 LTS, WPF, WiX v5, GPL-3.0-or-later, encrypted DNS by default, delays of 1 hour to 30 days (1 minute in Debug builds), a fixed confirmation sentence, English only.
- **Time while off** counts only when verified by two TLS-authenticated HTTPS `Date` headers (the earlier of the two is used), and only for changes requested before the PC was switched off.
- **ECDSA P-256** instead of Ed25519 for list/update signatures, because it's built into .NET, so there's no extra crypto dependency.
- **Hand-written P/Invoke** instead of CsWin32, with struct layouts asserted by tests.
- **The watchdog checks through the Service Control Manager** every 3 seconds (exists, configured, running, files intact) instead of a pipe heartbeat. That's simpler, and it can't be fooled by a fake pipe.
- **The uninstall gate is the app itself** (`GuardianAngel.App.exe --uninstall`), not a separate exe.
- **Boot-time WFP filters** go in the default sublayer without a provider (BFE objects don't exist at boot). **[verify in VM]**
