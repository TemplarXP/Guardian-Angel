using System.Net;
using System.Security.Cryptography;
using System.Text;
using GuardianAngel.Core.Browser;
using GuardianAngel.Core.Dns;
using GuardianAngel.Core.Firewall;
using GuardianAngel.Core.Hosts;
using GuardianAngel.Core.Lists;
using GuardianAngel.Core.Log;
using GuardianAngel.Core.Model;
using GuardianAngel.Core.State;

namespace GuardianAngel.Core.Tests;

public class FirewallPlannerTests
{
    private static readonly IPAddress[] Resolvers = BuiltInLists.Resolvers.AllIps().ToArray();

    [Fact]
    public void Encrypted_filter_gets_no_plain_dns_permit()
    {
        var plan = FirewallPlanner.Plan(Harness.Filter, [], Resolvers, false);
        var permits = plan.Where(r => r.Action == FilterAction.Permit).ToList();
        Assert.Equal(Harness.Filter.Servers.Count, permits.Count);
        Assert.All(permits, p => Assert.DoesNotContain(Ports.Dns, p.RemotePorts!));
    }

    [Fact]
    public void Plain_filter_permits_53_only_to_the_filter_and_blocks_everything_else()
    {
        var f = Harness.Filter with { Encryption = EncryptionMode.None };
        var plan = FirewallPlanner.Plan(f, [], Resolvers, false);
        Assert.All(plan.Where(r => r.Action == FilterAction.Permit), p => Assert.Contains(Ports.Dns, p.RemotePorts!));
        var block53 = Assert.Single(plan, r => r.Action == FilterAction.Block && r.RemotePorts?.Contains(Ports.Dns) == true);
        Assert.Null(block53.RemoteAddress);
        Assert.True(block53.Weight < plan.First(r => r.Action == FilterAction.Permit).Weight);
    }

    [Fact]
    public void Known_resolvers_are_blocked_except_the_chosen_filter()
    {
        var f = FilterPresets.Find("adguard-family")!.Config;
        var extra = new[] { IPAddress.Parse("94.140.14.15") };
        var plan = FirewallPlanner.Plan(f, [], Resolvers.Concat(extra), false);
        Assert.Contains(plan, r => r.Action == FilterAction.Block && IPAddress.Parse("8.8.8.8").Equals(r.RemoteAddress));
        Assert.DoesNotContain(plan, r => r.Action == FilterAction.Block && IPAddress.Parse("94.140.14.15").Equals(r.RemoteAddress));
    }

    [Fact]
    public void Block_all_mode_still_allows_the_filter_dhcp_and_loopback()
    {
        var plan = FirewallPlanner.Plan(Harness.Filter, ["9.9.9.9"], Resolvers, true);
        var blockAll = Assert.Single(plan, r => r.Weight == Weights.BlockAll);
        Assert.Null(blockAll.RemoteAddress);
        Assert.Contains(plan, r => r.LoopbackOnly && r.Action == FilterAction.Permit);
        Assert.Contains(plan, r => r.Action == FilterAction.Permit && IPAddress.Parse("9.9.9.9").Equals(r.RemoteAddress));
        Assert.DoesNotContain(plan, r => r.Action == FilterAction.Block && IPAddress.Parse("9.9.9.9").Equals(r.RemoteAddress));
    }

    [Fact]
    public void Dns_port_blocks_outrank_loopback_permits()
    {
        var plan = FirewallPlanner.Plan(Harness.Filter, [], Resolvers, true);
        Assert.True(plan.First(r => r.Name.StartsWith("Block DNS")).Weight > plan.First(r => r.LoopbackOnly).Weight);
    }
}

public class BrowserPolicyTests
{
    [Fact]
    public void Secure_dns_is_always_turned_off_in_every_browser()
    {
        var p = BrowserPolicyPlanner.Plan(new BrowserOptions());
        foreach (var key in BrowserPolicyPlanner.ChromiumKeys)
            Assert.Contains(p, v => v.KeyPath == key && v.Name == "DnsOverHttpsMode" && (string)v.Value == "off");
        Assert.Contains(p, v => v.KeyPath.EndsWith(@"Firefox\DNSOverHTTPS") && v.Name == "Locked");
        Assert.DoesNotContain(p, v => v.Name.Contains("Incognito") || v.Name.Contains("Private"));
    }

    [Fact]
    public void Optional_policies_appear_only_when_chosen()
    {
        var p = BrowserPolicyPlanner.Plan(new BrowserOptions { DisablePrivateMode = true, BlockProxyExtensions = true }, ["abc"]);
        Assert.Contains(p, v => v.Name == "InPrivateModeAvailability" && v.KeyPath == BrowserPolicyPlanner.EdgeKey);
        Assert.Contains(p, v => v.Name == "IncognitoModeAvailability" && v.KeyPath == BrowserPolicyPlanner.ChromeKey);
        Assert.Contains(p, v => v.Name == "DisablePrivateBrowsing");
        Assert.Contains(p, v => v.Name == "ProxySettings");
        Assert.Contains(p, v => v.KeyPath.EndsWith("ExtensionInstallBlocklist") && (string)v.Value == "abc");
    }
}

public class HostsAnalyzerTests
{
    [Theory]
    [InlineData("1.2.3.4 blocked-site.com", true)]
    [InlineData("  104.16.1.1\twww.example.com # comment", true)]
    [InlineData("2606:4700::1 example.com", true)]
    [InlineData("0.0.0.0 ads.example.com", false)]
    [InlineData("127.0.0.1 localhost", false)]
    [InlineData("::1 localhost", false)]
    [InlineData("# 1.2.3.4 commented.com", false)]
    [InlineData("", false)]
    [InlineData("garbage line", true)]
    public void Detects_lines_that_redirect_names(string line, bool bypass) => Assert.Equal(bypass, HostsAnalyzer.IsBypassLine(line));

    [Fact]
    public void Sanitize_keeps_blocking_lines_and_removes_redirects()
    {
        var r = HostsAnalyzer.Sanitize("# hi\r\n0.0.0.0 bad.com\r\n5.6.7.8 good-looking.com\r\n");
        Assert.True(r.Changed);
        Assert.Contains("0.0.0.0 bad.com", r.SanitizedContent);
        Assert.DoesNotContain("5.6.7.8", r.SanitizedContent);
        Assert.False(HostsAnalyzer.Sanitize(HostsAnalyzer.DefaultWindowsHosts).Changed);
    }
}

public class DnsWireTests
{
    [Fact]
    public void Builds_and_parses_a_response()
    {
        var q = DnsWire.BuildQuery("example.com", DnsWire.TypeA, id: 0x1234);
        // Turn the query into a response with one A record (compression pointer to the question name).
        var resp = q.ToList();
        resp[2] = 0x81; resp[3] = 0x80; resp[7] = 1;
        resp.AddRange(new byte[] { 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34 });
        var a = DnsWire.Parse(resp.ToArray());
        Assert.Equal(0x1234, a.Id);
        Assert.Equal(DnsRcode.NoError, a.Rcode);
        Assert.Equal(IPAddress.Parse("93.184.216.34"), Assert.Single(a.Addresses));
    }

    [Fact]
    public void Rejects_garbage() => Assert.Throws<FormatException>(() => DnsWire.Parse(new byte[5]));
}

public class FilterConfigTests
{
    [Fact]
    public void Presets_are_valid() => Assert.All(FilterPresets.All.Where(p => !p.NeedsProfileId), p => Assert.Empty(p.Config.Validate()));

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("0.0.0.0")]
    [InlineData("not-an-ip")]
    [InlineData("224.0.0.1")]
    public void Rejects_unusable_servers(string server) =>
        Assert.NotEmpty((Harness.Filter with { Servers = [server] }).Validate());

    [Fact]
    public void Doh_requires_an_https_template() =>
        Assert.NotEmpty((Harness.Filter with { DohTemplate = "http://x.example/dns-query" }).Validate());

    [Fact]
    public void NextDns_profile_is_filled_in()
    {
        var p = FilterPresets.Find("nextdns")!;
        var f = FilterPresets.WithProfile(p.Config, "abc123");
        Assert.Equal("https://dns.nextdns.io/abc123", f.DohTemplate);
        Assert.Empty(f.Validate());
    }
}

public class StateStoreTests
{
    [Fact]
    public void Falls_back_to_the_other_copy_when_one_is_corrupt()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ga-store-" + Guid.NewGuid());
        var store = new FileStateStore(dir, new NullProtector());
        var s = new LockState { ReflectionMessage = "one" };
        store.Save(s);
        s.ReflectionMessage = "two";
        store.Save(s);
        // Corrupt the newest copy (generation 2 → slot A).
        File.WriteAllText(Path.Combine(dir, "state-a.bin"), "{broken");
        Assert.Equal("one", store.Load().ReflectionMessage);
        File.WriteAllText(Path.Combine(dir, "state-b.bin"), "{broken");
        Assert.Throws<StateCorruptException>(() => store.Load());
        Directory.Delete(dir, true);
    }

    [Fact]
    public void Empty_directory_gives_a_fresh_unlocked_state()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ga-store-" + Guid.NewGuid());
        var s = new FileStateStore(dir, new NullProtector()).Load();
        Assert.False(s.IsLocked);
        Directory.Delete(dir, true);
    }
}

public class AccountabilityLogTests
{
    [Fact]
    public void Detects_edits_and_deletions()
    {
        var path = Path.Combine(Path.GetTempPath(), "ga-log-" + Guid.NewGuid() + ".jsonl");
        var key = RandomNumberGenerator.GetBytes(32);
        var log = new AccountabilityLog(path, key);
        log.Append("request", "Uninstall requested");
        log.Append("cancel", "Uninstall cancelled");
        log.Append("lock", "Locked");
        Assert.Null(log.Verify());

        // Reopen continues the chain.
        new AccountabilityLog(path, key).Append("x", "y");
        Assert.Null(new AccountabilityLog(path, key).Verify());

        var lines = File.ReadAllLines(path).ToList();
        File.WriteAllLines(path, lines.Select(l => l.Replace("cancelled", "applied")));
        Assert.NotNull(new AccountabilityLog(path, key).Verify());

        lines.RemoveAt(1);
        File.WriteAllLines(path, lines);
        Assert.NotNull(new AccountabilityLog(path, key).Verify());
        File.Delete(path);
    }
}

public class SignedListTests
{
    [Fact]
    public void Only_lists_signed_with_the_key_and_newer_than_built_in_are_used()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pub = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());
        var dir = Path.Combine(Path.GetTempPath(), "ga-list-" + Guid.NewGuid());
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "resolvers.json");

        var newer = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new ResolverList(99, DateTimeOffset.UtcNow, ["203.0.113.9"], []), Json.Options);
        File.WriteAllBytes(path, newer);
        File.WriteAllBytes(path + ".sig", key.SignData(newer, HashAlgorithmName.SHA256));
        Assert.Equal(99, SignedList.LoadResolvers(path, pub).Version);

        // Tampered content → built-in list.
        File.WriteAllBytes(path, Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(newer).Replace("203.0.113.9", "203.0.113.8")));
        Assert.Equal(BuiltInLists.Resolvers.Version, SignedList.LoadResolvers(path, pub).Version);

        // Validly signed but OLDER list (replay of a weaker list) → built-in list.
        var older = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new ResolverList(0, DateTimeOffset.UtcNow, [], []), Json.Options);
        File.WriteAllBytes(path, older);
        File.WriteAllBytes(path + ".sig", key.SignData(older, HashAlgorithmName.SHA256));
        Assert.Equal(BuiltInLists.Resolvers.Version, SignedList.LoadResolvers(path, pub).Version);

        // No public key configured → built-in only.
        Assert.Equal(BuiltInLists.Resolvers.Version, SignedList.LoadResolvers(path, "").Version);
        Directory.Delete(dir, true);
    }
}
