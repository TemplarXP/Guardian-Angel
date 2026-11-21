using System.Net;
using System.Net.Sockets;
using GuardianAngel.Core.Browser;
using GuardianAngel.Core.Firewall;
using GuardianAngel.Core.Model;
using GuardianAngel.Platform.Windows.Enforcement;
using GuardianAngel.Platform.Windows.Security;
using Microsoft.Win32;

namespace GuardianAngel.Windows.Tests;

/// <summary>
/// Real Windows APIs, but harmless: the firewall test only blocks a TEST-NET address (192.0.2.53, which
/// is never used on the internet) and removes everything afterwards.
/// </summary>
[Collection("Machine state")]
public class WindowsIntegrationTests
{
    private static readonly IPAddress TestNet = IPAddress.Parse("192.0.2.53");

    [WindowsAdminFact]
    public void Wfp_block_rule_blocks_and_removal_unblocks()
    {
        var fw = new WfpFirewall(restrictToSystem: false);
        try
        {
            Assert.True(ConnectNotRefused(TestNet, 53), "Sending to TEST-NET should work before the rule exists.");
            var rules = new List<FirewallRule> { new("Test block", FilterAction.Block, 10, TestNet) };
            fw.Apply(rules);
            Assert.True(fw.VerifyPresent(rules));
            Assert.False(ConnectNotRefused(TestNet, 53), "The WFP block rule should refuse the packet.");
        }
        finally
        {
            fw.RemoveAll();
        }
        Assert.True(ConnectNotRefused(TestNet, 53), "After RemoveAll, traffic should flow again.");
    }

    [WindowsAdminFact]
    public void Wfp_rules_survive_a_new_engine_session()
    {
        var fw = new WfpFirewall(restrictToSystem: false);
        try
        {
            var rules = new List<FirewallRule> { new("Test block", FilterAction.Block, 10, TestNet, [Ports.Dns]) };
            fw.Apply(rules);
            Assert.True(new WfpFirewall(restrictToSystem: false).VerifyPresent(rules), "Persistent filters must exist independently of the process that added them.");
        }
        finally { fw.RemoveAll(); }
    }

    [WindowsAdminFact]
    public void Dpapi_round_trips()
    {
        var p = new DpapiProtector();
        var data = "secret"u8.ToArray();
        var enc = p.Protect(data);
        Assert.NotEqual(data, enc);
        Assert.Equal(data, p.Unprotect(enc));
    }

    [WindowsAdminFact]
    public void Browser_policies_are_written_restored_and_removed()
    {
        var b = new BrowserPolicyEnforcer();
        try
        {
            b.Apply(new BrowserOptions());
            using (var k = Registry.LocalMachine.OpenSubKey(BrowserPolicyPlanner.ChromeKey, writable: true)!)
            {
                Assert.Equal("off", k.GetValue("DnsOverHttpsMode"));
                k.SetValue("DnsOverHttpsMode", "automatic"); // simulate tampering
            }
            b.Apply(new BrowserOptions());
            using (var k = Registry.LocalMachine.OpenSubKey(BrowserPolicyPlanner.ChromeKey)!)
                Assert.Equal("off", k.GetValue("DnsOverHttpsMode"));
        }
        finally { b.RemoveAll(); }
        using var after = Registry.LocalMachine.OpenSubKey(BrowserPolicyPlanner.ChromeKey);
        Assert.Null(after?.GetValue("DnsOverHttpsMode"));
    }

    /// <summary>
    /// True unless WFP refuses the connection. TEST-NET is unroutable, so an allowed connect just times out,
    /// while a WFP block fails at once with "access denied" (WSAEACCES).
    /// </summary>
    private static bool ConnectNotRefused(IPAddress ip, int port)
    {
        using var s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            s.ConnectAsync(new IPEndPoint(ip, port)).Wait(TimeSpan.FromSeconds(2));
            return true;
        }
        catch (AggregateException ex) when (ex.InnerException is SocketException { SocketErrorCode: SocketError.AccessDenied }) { return false; }
        catch (AggregateException) { return true; }
    }
}
