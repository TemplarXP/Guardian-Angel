# Protections

Each protection lists how it works, the Windows APIs it depends on, how to check it by hand in a VM, and the automated tests that cover it.

**Levels:** **Locked** = enforced by policy. **Guarded** = the service monitors it and reverts changes. **Watched** = detection and warning only. **Manual** = outside this PC.

Status: Milestone 1 protections only. Later milestones add their rows here.

---

## 1. Firewall lock (Locked)
**What:** Outbound DNS (53), DoT/DoQ (853, 784, 8853) and Tor ports are allowed only to the locked filter's servers. Known public resolvers and Tor directory authorities are blocked on every port. When encrypted DNS is chosen, even plain port 53 to the filter itself is blocked, so nothing on the network can intercept it.
- Block rules are **hard blocks** (`FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`): permits in other sublayers (Windows Defender Firewall included) can't override them.
- Each rule exists twice: **persistent** (`FWPM_FILTER_FLAG_PERSISTENT`, stays when the service is stopped or deleted) and **boot-time** (`FWPM_FILTER_FLAG_BOOTTIME`, active before the Base Filtering Engine starts).
- "Block the internet if no filter can be reached" adds a block-all rule. Only the filter, DHCP and loopback stay allowed.

**APIs:** `fwpuclnt.dll`: `FwpmEngineOpen0`, `FwpmTransactionBegin0/Commit0`, `FwpmProviderAdd0`, `FwpmSubLayerAdd0`, `FwpmFilterAdd0`, `FwpmFilterDeleteByKey0`, `FwpmFilterGetByKey0`. Layers `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6`. Code: `Core/Firewall/FirewallPlan.cs`, `Platform.Windows/Enforcement/WfpFirewall.cs`.

**Check by hand:**
1. `nslookup example.com 8.8.8.8` should time out.
2. `netsh wfp show filters` should list "Guardian Angel: ..." filters.
3. Turn Windows Firewall off: step 1 still times out.
4. `sc stop GuardianAngel` (Debug build): step 1 still times out.

**Tests:** `FirewallPlannerTests` (unit), `WindowsIntegrationTests.Wfp_*` (Windows), and the attack tests `Plain_dns_to_another_resolver_is_blocked`, `Dns_over_tls_to_another_resolver_is_blocked`, `Dns_over_https_to_public_resolvers_is_blocked`, `Windows_firewall_off_does_not_open_dns`, `Stopping_the_service_does_not_unlock_dns`.

**Editions:** all Windows 11 editions.

## 2. DNS lock (Guarded)
**What:** Sets the filter's servers on every adapter (except loopback), for IPv4 and IPv6. It re-applies on every network change and every 10 seconds. Windows 11 encrypted DNS is registered for each server (DoH template, or DoT host), with no UDP fallback and the `DoHPolicy = 3` ("require") policy.

**APIs:** `SetInterfaceDnsSettings` (iphlpapi), with a `netsh interface ipv4/ipv6 set dnsservers` fallback; `netsh dns add encryption`; HKLM `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DoHPolicy`; `NetworkChange` events; `DnsFlushResolverCache`. Code: `Platform.Windows/Enforcement/DnsEnforcer.cs`.

**Check by hand:**
1. `Get-DnsClientServerAddress` lists only your filter's servers.
2. Settings > Network > (adapter) > DNS shows "Encrypted only".
3. Set an adapter's DNS to 8.8.8.8: it's back within about 10 seconds.

**Tests:** attack tests `Changing_an_adapters_dns_is_reverted`, `The_locked_filter_itself_still_works`, `Blocked_domain_stays_blocked_through_the_system_resolver`; `InteropLayoutTests.DNS_INTERFACE_SETTINGS_matches`.

**Editions:** all Windows 11 editions. DoT needs a Windows build with native DoT **[verify in VM]**.

## 3. Browser secure-DNS policies (Locked + Guarded)
**What:** HKLM policies turn off built-in secure DNS in Chrome, Edge, Brave (`DnsOverHttpsMode = off`) and Firefox (`DNSOverHTTPS: Enabled=0, Locked=1`). Two optional settings, both off by default:
- turning off incognito/private windows;
- forcing browsers to connect directly, so no extension can set a proxy (Chromium `ProxySettings`, Firefox `Proxy`).

The service re-writes these policies if they change.

**APIs:** registry, `HKLM\SOFTWARE\Policies\...` (64-bit view). Code: `Core/Browser/BrowserPolicyPlan.cs`, `Platform.Windows/Enforcement/BrowserPolicyEnforcer.cs`.

**Check by hand:** `chrome://policy` and `edge://policy` show `DnsOverHttpsMode: off`. `about:policies` in Firefox shows DNSOverHTTPS.

**Tests:** `BrowserPolicyTests` (unit), `WindowsIntegrationTests.Browser_policies_are_written_restored_and_removed`, attack test `Browser_secure_dns_policy_is_restored`.

**Editions:** all. **[verify in VM]** that Chrome honours these policies on a PC that isn't in a domain.

## 4. Hosts file guard (Guarded)
**What:** Removes hosts lines that point a name at a real address. Lines pointing at `0.0.0.0`, `127.x` or `::1` only block things, so they're kept. Also keeps `Tcpip\Parameters\DataBasePath` (which can redirect the hosts file) at its default.

**APIs:** `FileSystemWatcher` + a check every 10 s; registry. Code: `Core/Hosts/HostsAnalyzer.cs`, `Platform.Windows/Enforcement/HostsGuard.cs`.

**Check by hand:** add `1.2.3.4 example.com` to the hosts file. It disappears within about 10 seconds.

**Tests:** `HostsAnalyzerTests`, attack tests `Hosts_file_redirects_are_removed`, `Hosts_file_location_redirect_is_reverted`.

## 5. Delay clock (Locked)
**What:** Delays count monotonic milliseconds (`GetTickCount64`), saved every 15 seconds, and keep counting after a reboot. Changing the clock has no effect. Time spent switched off counts only when two TLS-authenticated HTTPS `Date` headers agree after boot, and only for changes requested before the PC was switched off.

**Code:** `Core/Engine/LockEngine.cs` (`TickAsync`, `OnTrustedTimeAsync`), `Platform.Windows/Security/HttpsTrustedTime.cs`.

**Tests:** `LockEngineTests.Changing_the_wall_clock_does_not_speed_up_the_delay`, `Progress_survives_a_reboot_and_keeps_counting`, `Off_time_counts_only_when_verified_by_trusted_time`, `Setting_the_clock_forward_while_off_does_not_count_without_trusted_time`, `Changes_requested_after_an_unverified_boot_get_no_earlier_off_time`; attack test `Clock_changes_do_not_move_a_countdown`.

## 6. Change queue and reflection (Locked)
**What:** Loosening changes are queued with the delay that applied when they were requested. A longer delay raises every pending change to the new delay. There's one pending change per setting, and a new request restarts its countdown. Changes apply automatically when due, and cancelling is instant. Each request requires the reflection screen and the exact typed sentence, which the service checks itself. A filter change is tested before it's applied, and if the test fails the old filter stays.

**Tests:** `LockEngineTests` (queue, supersede, cancel, longer/shorter delay, failed filter test, power loss mid-apply).

## 7. Partner codes (Locked)
**What:** RFC 6238 TOTP (SHA-1, 6 digits, 30 s), accepting ±1 step. Each code is accepted only once. Five wrong codes cause a 1-hour lockout, counted monotonically, which survives reboots. The secret is shown once at setup and no API returns it afterwards.

**Code:** `Core/Totp/Totp.cs`. **Tests:** `TotpTests` (RFC vectors, window, replay, lockout), `LockEngineTests.Partner_*`, `Lockout_survives_a_reboot`, attack test `Wrong_partner_codes_lock_out` (opt-in).

## 8. Service + watchdog (Guarded)
**What:** Two LocalSystem services. Each one re-registers, reconfigures, restarts and restores the other from a recovery copy of the install files. Both restart on failure and are registered for Safe Mode. In Release builds, their security descriptor lets only SYSTEM stop, reconfigure or delete them. Both stand down during a due uninstall or a Windows Installer session (an upgrade).

**APIs:** SCM (`SetServiceObjectSecurity`, `sc.exe failure/create/config`), `ServiceController`, `SafeBoot\Minimal|Network` registry keys. Code: `Platform.Windows/Services/*`.

**Check by hand:** `sc sdshow GuardianAngel`. In a Release build, `sc stop GuardianAngel` should be refused with "Access is denied".

**Tests:** attack tests `Stopping_the_service_does_not_unlock_dns`, `Deleting_the_service_brings_it_back`.

## 9. Protected state (Locked)
**What:** State is encrypted with DPAPI in user scope as SYSTEM, so only SYSTEM can decrypt it. It's stored in `%ProgramData%\GuardianAngel` with an ACL that gives SYSTEM full control, Administrators read access, and Users nothing. Two generations are kept (A/B), with atomic writes. If both copies are unreadable, the service enters Safe-Locked mode.

**Tests:** `StateStoreTests`, `LockEngineTests.Unreadable_state_enters_safe_locked_mode_and_changes_nothing`, `WindowsIntegrationTests.Dpapi_round_trips`.

## 10. Uninstall gate (Locked)
**What:** Settings > Apps points to `GuardianAngel.App.exe --uninstall`, which only explains the process. The MSI refuses `REMOVE=ALL` while the service reports "locked" (`HKLM\SOFTWARE\GuardianAngel\UninstallAuthorized = 0`). When an uninstall change is due, the service removes every protection and then runs `msiexec /x` itself. Even if someone forces the MSI off, the persistent WFP filters stay. That's fail closed: DNS keeps going only to the filter.

**Tests:** `LockEngineTests.Uninstall_is_refused_until_due_then_removes_everything`, attack test `Msi_uninstall_is_refused_while_locked`.

## 11. Accountability log (Watched)
**What:** An append-only JSON-lines log. Each entry is HMAC-chained to the one before it, with a key only SYSTEM can read, so edits, deletions and reordering are detected. Milestone 1 writes the log. The partner-gated full view comes in Milestone 2.

**Tests:** `AccountabilityLogTests`.

## 12. Signed block lists (Locked)
**What:** Built-in resolver/Tor lists can be replaced by a newer list signed with the maintainer's offline ECDSA P-256 key. A list with a lower version number, a bad signature, or no configured key is ignored.

**Tests:** `SignedListTests`.
