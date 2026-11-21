using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using GuardianAngel.Core.Ipc;
using GuardianAngel.Core.Model;
using GuardianAngel.Platform.Windows.Native;
using Microsoft.Win32;

namespace GuardianAngel.Platform.Windows.Enforcement;

/// <summary>
/// Sets the locked filter's servers on EVERY network adapter (Wi-Fi, Ethernet, USB, tethering, new adapters),
/// for IPv4 and IPv6, and registers them with Windows 11's built-in encrypted DNS client.
/// Re-applied on every network change and about every 10 seconds. Even between checks, the firewall lock
/// drops DNS to any other server, so a changed setting can only break DNS, never unfilter it.
/// </summary>
public sealed class DnsEnforcer
{
    public const string DnsClientPolicyKey = @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";
    public const int DoHPolicyRequire = 3;

    private string? _registeredEncryptionFor;

    public EnforcementItemDto Apply(FilterConfig filter, IReadOnlyList<string> extraServers)
    {
        var problems = new List<string>();
        var v4 = filter.V4.Select(a => a.ToString()).ToList();
        var v6 = filter.V6.Select(a => a.ToString()).ToList();

        foreach (var nic in Adapters())
        {
            var ok = SetForAdapter(nic, v4, ipv6: false) & SetForAdapter(nic, v6, ipv6: true);
            if (!ok && nic.OperationalStatus == OperationalStatus.Up && nic.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
                problems.Add($"{nic.Name}: couldn't set DNS");
        }

        problems.AddRange(ApplyEncryption(filter));
        IpHelperApi.DnsFlushResolverCache();

        var drift = Verify(filter, extraServers);
        problems.AddRange(drift);
        return new EnforcementItemDto("DNS lock", problems.Count == 0,
            problems.Count == 0 ? $"All adapters use {filter.Name}." : string.Join("; ", problems));
    }

    /// <summary>Returns adapters whose effective DNS servers include anything other than the locked filter.</summary>
    public List<string> Verify(FilterConfig filter, IReadOnlyList<string> extraServers)
    {
        var allowed = filter.ParsedServers().Concat(extraServers.Select(IPAddress.Parse)).ToHashSet();
        var drift = new List<string>();
        foreach (var nic in Adapters().Where(n => n.OperationalStatus == OperationalStatus.Up))
        {
            var foreign = nic.GetIPProperties().DnsAddresses
                .Where(a => !a.IsIPv6SiteLocal || a.ScopeId == 0) // ignore fec0::/10 placeholders Windows shows on some adapters
                .Where(a => !allowed.Contains(StripScope(a)))
                .ToList();
            if (foreign.Count > 0) drift.Add($"{nic.Name} still lists {string.Join(", ", foreign)}");
        }
        return drift;
    }

    public void RemoveAll()
    {
        foreach (var nic in Adapters())
        {
            SetForAdapter(nic, [], ipv6: false);
            SetForAdapter(nic, [], ipv6: true);
        }
        using var policy = Registry.LocalMachine.OpenSubKey(DnsClientPolicyKey, writable: true);
        policy?.DeleteValue("DoHPolicy", throwOnMissingValue: false);
        IpHelperApi.DnsFlushResolverCache();
        _registeredEncryptionFor = null;
    }

    private static IEnumerable<NetworkInterface> Adapters() =>
        NetworkInterface.GetAllNetworkInterfaces().Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback);

    private static bool SetForAdapter(NetworkInterface nic, List<string> servers, bool ipv6)
    {
        if (!Guid.TryParse(nic.Id, out var guid)) return false;
        var list = Marshal(servers);
        try
        {
            var s = new DNS_INTERFACE_SETTINGS
            {
                Version = IpHelperApi.DNS_INTERFACE_SETTINGS_VERSION1,
                Flags = IpHelperApi.DNS_SETTING_NAMESERVER | (ipv6 ? IpHelperApi.DNS_SETTING_IPV6 : 0),
                NameServer = list,
            };
            if (IpHelperApi.SetInterfaceDnsSettings(guid, ref s) == 0) return true;
        }
        finally { System.Runtime.InteropServices.Marshal.FreeHGlobal(list); }

        // Fallback for adapters the API refuses: netsh, which every Windows edition has.
        var fam = ipv6 ? "ipv6" : "ipv4";
        if (servers.Count == 0)
            return ProcessRunner.Run("netsh.exe", $"interface {fam} set dnsservers name=\"{nic.Name}\" source=dhcp").ExitCode == 0;
        var ok = ProcessRunner.Run("netsh.exe", $"interface {fam} set dnsservers name=\"{nic.Name}\" source=static address={servers[0]} register=none validate=no").ExitCode == 0;
        for (int i = 1; i < servers.Count && ok; i++)
            ok = ProcessRunner.Run("netsh.exe", $"interface {fam} add dnsservers name=\"{nic.Name}\" address={servers[i]} index={i + 1} validate=no").ExitCode == 0;
        return ok;
    }

    // [verify in VM] The API takes a comma-separated list; an empty string returns the adapter to DHCP-provided DNS.
    private static IntPtr Marshal(List<string> servers) => System.Runtime.InteropServices.Marshal.StringToHGlobalUni(string.Join(",", servers));

    /// <summary>Registers each server with its DoH/DoT template and requires encrypted DNS (no plain fallback).</summary>
    private List<string> ApplyEncryption(FilterConfig f)
    {
        var problems = new List<string>();
        var key = $"{f.Encryption}|{f.DohTemplate}|{f.DotHost}|{string.Join(",", f.Servers)}";

        if (f.Encryption == EncryptionMode.None)
        {
            using var k = Registry.LocalMachine.OpenSubKey(DnsClientPolicyKey, writable: true);
            k?.DeleteValue("DoHPolicy", throwOnMissingValue: false);
            _registeredEncryptionFor = key;
            return problems;
        }

        if (_registeredEncryptionFor != key)
        {
            foreach (var ip in f.Servers)
            {
                var spec = f.Encryption == EncryptionMode.Doh
                    ? $"server={ip} dohtemplate={f.DohTemplate} autoupgrade=yes udpfallback=no"
                    : $"server={ip} dothost={f.DotHost}:853 autoupgrade=yes udpfallback=no";
                var add = ProcessRunner.Run("netsh.exe", $"dns add encryption {spec}");
                if (add.ExitCode != 0 && ProcessRunner.Run("netsh.exe", $"dns set encryption {spec}").ExitCode != 0)
                    problems.Add(f.Encryption == EncryptionMode.Dot
                        ? $"This Windows build doesn't support DNS over TLS for {ip}. Choose DoH instead."
                        : $"Couldn't register encrypted DNS for {ip}");
            }
            if (problems.Count == 0) _registeredEncryptionFor = key;
        }

        using (var k = Registry.LocalMachine.CreateSubKey(DnsClientPolicyKey, writable: true))
        {
            if (k.GetValue("DoHPolicy") is not int v || v != DoHPolicyRequire)
                k.SetValue("DoHPolicy", DoHPolicyRequire, RegistryValueKind.DWord);
        }
        return problems;
    }

    private static IPAddress StripScope(IPAddress a) =>
        a.AddressFamily == AddressFamily.InterNetworkV6 && a.ScopeId != 0 ? new IPAddress(a.GetAddressBytes()) : a;
}
