using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.ServiceProcess;
using GuardianAngel.Core.Dns;
using GuardianAngel.Core.Ipc;
using GuardianAngel.Core.Model;
using Microsoft.Win32;

namespace GuardianAngel.AttackTests;

/// <summary>Each test is a known bypass. Every one must FAIL to get around the filter.</summary>
[Collection("VM")]
public class BypassAttempts
{
    private static async Task<bool> Answers(IDnsProbe probe, string server, string name = "example.com")
    {
        try
        {
            var a = await probe.QueryAsync(IPAddress.Parse(server), name, DnsWire.TypeA, default).WaitAsync(TimeSpan.FromSeconds(6));
            return a.Addresses.Count > 0;
        }
        catch (Exception) { return false; }
    }

    [VmFact]
    public async Task Plain_dns_to_another_resolver_is_blocked()
    {
        await Vm.LockedStatusAsync();
        Assert.False(await Answers(new UdpDnsProbe(), "8.8.8.8"));
        Assert.False(await Answers(new UdpDnsProbe(), "9.9.9.9"));
        Assert.False(await Answers(new UdpDnsProbe(), "208.67.222.222"));
    }

    [VmFact]
    public async Task Dns_over_tls_to_another_resolver_is_blocked()
    {
        await Vm.LockedStatusAsync();
        Assert.False(await Answers(new DotProbe("one.one.one.one"), "1.1.1.1"));
    }

    [VmFact]
    public async Task Dns_over_https_to_public_resolvers_is_blocked()
    {
        await Vm.LockedStatusAsync();
        Assert.False(await Answers(new DohProbe("https://dns.google/dns-query"), "8.8.8.8"));
        Assert.False(await Answers(new DohProbe("https://cloudflare-dns.com/dns-query"), "1.1.1.1"));
        Assert.False(await Answers(new DohProbe("https://dns.quad9.net/dns-query"), "9.9.9.9"));
    }

    [VmFact]
    public async Task The_locked_filter_itself_still_works()
    {
        var s = await Vm.LockedStatusAsync();
        Assert.True(await Answers(ConnectionTester.DefaultProbe(s.Filter!), s.Filter!.Servers[0]));
    }

    [VmFact]
    public async Task Blocked_domain_stays_blocked_through_the_system_resolver()
    {
        await Vm.LockedStatusAsync();
        var domain = Environment.GetEnvironmentVariable("GA_TEST_BLOCKED_DOMAIN");
        if (string.IsNullOrWhiteSpace(domain)) return; // optional
        IPAddress[] addrs;
        try { addrs = await Dns.GetHostAddressesAsync(domain); } catch (SocketException) { return; } // NXDOMAIN = blocked
        Assert.All(addrs, a => Assert.True(IPAddress.IsLoopback(a) || a.Equals(IPAddress.Any) || a.Equals(IPAddress.IPv6Any)
            || Environment.GetEnvironmentVariable("GA_TEST_BLOCKPAGE_IPS")?.Split(',').Contains(a.ToString()) == true,
            $"{domain} resolved to {a}, which isn't a block answer."));
    }

    [VmFact]
    public async Task Changing_an_adapters_dns_is_reverted()
    {
        var s = await Vm.LockedStatusAsync();
        var nic = NetworkInterface.GetAllNetworkInterfaces().First(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback);
        Vm.Run("netsh.exe", $"interface ipv4 set dnsservers name=\"{nic.Name}\" source=static address=8.8.8.8 register=none validate=no");

        // Even before the revert, lookups must not go unfiltered: 8.8.8.8 is blocked by the firewall.
        Assert.False(await Answers(new UdpDnsProbe(), "8.8.8.8"));

        var allowed = s.Filter!.Servers.ToHashSet();
        Assert.True(await Vm.Eventually(() =>
            NetworkInterface.GetAllNetworkInterfaces().First(n => n.Id == nic.Id).GetIPProperties().DnsAddresses
                .Where(a => a.AddressFamily == AddressFamily.InterNetwork).All(a => allowed.Contains(a.ToString())),
            TimeSpan.FromSeconds(20)), "The adapter's DNS should be put back within about 10 seconds.");
    }

    [VmFact]
    public async Task Hosts_file_redirects_are_removed()
    {
        await Vm.LockedStatusAsync();
        var hosts = Path.Combine(Environment.SystemDirectory, "drivers", "etc", "hosts");
        File.AppendAllText(hosts, "\r\n93.184.215.14 ga-attack-test.example\r\n");
        Assert.True(await Vm.Eventually(() => !File.ReadAllText(hosts).Contains("ga-attack-test.example"), TimeSpan.FromSeconds(20)));
    }

    [VmFact]
    public async Task Hosts_file_location_redirect_is_reverted()
    {
        await Vm.LockedStatusAsync();
        using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", writable: true)!)
            k.SetValue("DataBasePath", @"C:\Users\Public", RegistryValueKind.ExpandString);
        Assert.True(await Vm.Eventually(() =>
        {
            using var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters")!;
            return ((string?)k.GetValue("DataBasePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames))?.Contains("drivers", StringComparison.OrdinalIgnoreCase) == true;
        }, TimeSpan.FromSeconds(20)));
    }

    [VmFact]
    public async Task Browser_secure_dns_policy_is_restored()
    {
        await Vm.LockedStatusAsync();
        using (var k = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Edge"))
            k.SetValue("DnsOverHttpsMode", "secure");
        Assert.True(await Vm.Eventually(() =>
        {
            using var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Edge")!;
            return (string?)k.GetValue("DnsOverHttpsMode") == "off";
        }, TimeSpan.FromSeconds(20)));
    }

    [VmFact]
    public async Task Stopping_the_service_does_not_unlock_dns()
    {
        await Vm.LockedStatusAsync();
        var stop = Vm.Run("sc.exe", "stop GuardianAngel");
        // Release builds: Administrators are refused (exit code 5 = access denied).
        // Debug builds: the stop succeeds, so check the firewall still blocks and the watchdog restarts it.
        Assert.False(await Answers(new UdpDnsProbe(), "8.8.8.8"));
        using var sc = new ServiceController("GuardianAngel");
        Assert.True(await Vm.Eventually(() => { sc.Refresh(); return sc.Status == ServiceControllerStatus.Running; }, TimeSpan.FromSeconds(30)),
            $"The watchdog should restart the service. sc said: {stop.Output}");
    }

    [VmFact]
    public async Task Deleting_the_service_brings_it_back()
    {
        await Vm.LockedStatusAsync();
        Vm.Run("sc.exe", "stop GuardianAngel");
        Vm.Run("sc.exe", "delete GuardianAngel");
        Assert.False(await Answers(new UdpDnsProbe(), "8.8.8.8"));
        Assert.True(await Vm.Eventually(() => ServiceController.GetServices().Any(s => s.ServiceName == "GuardianAngel" && s.Status == ServiceControllerStatus.Running),
            TimeSpan.FromSeconds(60)));
    }

    [VmFact]
    public async Task Windows_firewall_off_does_not_open_dns()
    {
        await Vm.LockedStatusAsync();
        Vm.Run("netsh.exe", "advfirewall set allprofiles state off");
        try { Assert.False(await Answers(new UdpDnsProbe(), "8.8.8.8")); }
        finally { Vm.Run("netsh.exe", "advfirewall set allprofiles state on"); }
    }

    [VmFact]
    public async Task Msi_uninstall_is_refused_while_locked()
    {
        await Vm.LockedStatusAsync();
        var r = Vm.Run(Path.Combine(Environment.SystemDirectory, "msiexec.exe"), "/x {PRODUCT} /qn".Replace("{PRODUCT}", FindProduct()));
        Assert.NotEqual(0, r.Code);
        Assert.Contains(ServiceController.GetServices(), s => s.ServiceName == "GuardianAngel");
    }

    [VmFact]
    public async Task Clock_changes_do_not_move_a_countdown()
    {
        var s = await Vm.LockedStatusAsync();
        // Queue a harmless loosening (a shorter delay), change the clock, then cancel it.
        var shorter = s.Delay - TimeSpan.FromMinutes(1);
        if (!s.DelayEnabled || shorter < s.MinDelay) return;
        var p = Json.ToElement(new GuardianAngel.Core.Policy.DelayChangeParams(true, shorter));
        var preview = await Vm.Client.CallAsync<ChangePreviewDto>(Ops.PreviewChange, new ChangeRequestDto("delay.change", p));
        var req = await Vm.Client.CallAsync<ChangeResultDto>(Ops.RequestChange, new ChangeRequestDto("delay.change", p, preview.ConfirmationPhrase));
        try
        {
            var before = (await Vm.Client.CallAsync<StatusDto>(Ops.GetStatus)).Pending.Single(x => x.Id == req.Id).RemainingMs!.Value;
            Vm.Run("powershell.exe", "-NoProfile -Command \"Set-Date -Date (Get-Date).AddDays(3)\"");
            await Task.Delay(3000);
            var after = (await Vm.Client.CallAsync<StatusDto>(Ops.GetStatus)).Pending.Single(x => x.Id == req.Id).RemainingMs!.Value;
            Assert.InRange(before - after, 0, 60_000);
        }
        finally
        {
            Vm.Run("powershell.exe", "-NoProfile -Command \"Set-Date -Date (Get-Date).AddDays(-3)\"");
            Vm.Run("w32tm.exe", "/resync /force");
            await Vm.Client.CallAsync(Ops.CancelChange, new IdRequest(req.Id!.Value));
        }
    }

    [VmFact]
    public async Task Wrong_partner_codes_lock_out()
    {
        var s = await Vm.LockedStatusAsync();
        if (!s.HasPartner || Environment.GetEnvironmentVariable("GA_TEST_ALLOW_LOCKOUT") != "1") return; // opt-in: it locks codes for an hour
        var p = Json.ToElement(new { });
        var preview = await Vm.Client.CallAsync<ChangePreviewDto>(Ops.PreviewChange, new ChangeRequestDto("uninstall", p));
        var req = await Vm.Client.CallAsync<ChangeResultDto>(Ops.RequestChange, new ChangeRequestDto("uninstall", p, preview.ConfirmationPhrase));
        try
        {
            ExpediteResult? last = null;
            for (int i = 0; i < 5; i++) last = await Vm.Client.CallAsync<ExpediteResult>(Ops.Expedite, new ExpediteRequest(req.Id!.Value, "000000"));
            Assert.Equal("LockedOut", last!.Result);
        }
        finally { await Vm.Client.CallAsync(Ops.CancelChange, new IdRequest(req.Id!.Value)); }
    }

    private static string FindProduct()
    {
        using var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")!;
        foreach (var name in k.GetSubKeyNames().Where(n => n.StartsWith('{')))
        {
            using var sub = k.OpenSubKey(name);
            if ((string?)sub?.GetValue("DisplayName") == "Guardian Angel") return name;
        }
        return "{00000000-0000-0000-0000-000000000000}";
    }
}
