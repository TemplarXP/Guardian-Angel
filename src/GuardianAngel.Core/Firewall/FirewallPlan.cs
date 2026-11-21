using System.Net;
using GuardianAngel.Core.Model;

namespace GuardianAngel.Core.Firewall;

public enum FilterAction { Permit, Block }

/// <summary>
/// One firewall rule in OS-neutral form. The Windows layer turns each spec into WFP filters
/// (persistent + boot-time, at ALE_AUTH_CONNECT for IPv4 and IPv6). Higher weight wins.
/// Conditions: all non-null fields must match (AND); multiple ports match any (OR).
/// </summary>
public sealed record FirewallRule(
    string Name,
    FilterAction Action,
    byte Weight,
    IPAddress? RemoteAddress = null,
    IReadOnlyList<ushort>? RemotePorts = null,
    byte? Protocol = null,
    bool LoopbackOnly = false)
{
    public bool IsV6Only => RemoteAddress?.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
    public bool IsV4Only => RemoteAddress?.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
}

public static class Ports
{
    public const ushort Dns = 53;
    public const ushort Https = 443;
    public const ushort DnsOverTls = 853;      // DoT (TCP) and DoQ (UDP)
    public const ushort DoqAlt1 = 784;
    public const ushort DoqAlt2 = 8853;
    public static readonly ushort[] TorRelay = [9001, 9030];
    public static readonly ushort[] TorSocks = [9050, 9150];
    public static readonly ushort[] Dhcp = [67, 68, 546, 547];
}

public static class Weights
{
    public const byte PermitFilter = 15;
    public const byte BlockDnsPorts = 14;
    public const byte BlockResolverIps = 13;
    public const byte PermitEssential = 12;
    public const byte BlockAll = 1;
}

/// <summary>Builds the complete firewall lock from the user's filter. Pure function, fully unit-tested.</summary>
public static class FirewallPlanner
{
    public static List<FirewallRule> Plan(FilterConfig filter, IEnumerable<string> extraAllowedServers,
        IEnumerable<IPAddress> blockedResolverIps, bool blockAllExceptFilter)
    {
        var rules = new List<FirewallRule>();
        var allowed = filter.ParsedServers()
            .Concat(extraAllowedServers.Select(s => IPAddress.TryParse(s, out var a) ? a : null).Where(a => a is not null)!)
            .Distinct().ToList();

        // 1. Permit the filter's own servers. If encryption is required, plain DNS (53) to them is NOT
        //    permitted, so a device on the network can't intercept and answer in their place.
        var filterPorts = new List<ushort> { Ports.Https, Ports.DnsOverTls };
        if (filter.Encryption == EncryptionMode.None) filterPorts.Insert(0, Ports.Dns);
        foreach (var ip in allowed)
            rules.Add(new FirewallRule($"Permit filter {ip}", FilterAction.Permit, Weights.PermitFilter, ip, filterPorts));

        // 2. Block every other DNS path, to any address (including loopback, so no local unfiltered proxy).
        rules.Add(new FirewallRule("Block DNS (53)", FilterAction.Block, Weights.BlockDnsPorts, RemotePorts: [Ports.Dns]));
        rules.Add(new FirewallRule("Block DoT/DoQ (853)", FilterAction.Block, Weights.BlockDnsPorts, RemotePorts: [Ports.DnsOverTls]));
        rules.Add(new FirewallRule("Block DoQ (784, 8853)", FilterAction.Block, Weights.BlockDnsPorts, RemotePorts: [Ports.DoqAlt1, Ports.DoqAlt2], Protocol: 17));
        rules.Add(new FirewallRule("Block Tor relay ports", FilterAction.Block, Weights.BlockDnsPorts, RemotePorts: Ports.TorRelay));
        rules.Add(new FirewallRule("Block Tor SOCKS ports", FilterAction.Block, Weights.BlockDnsPorts, RemotePorts: Ports.TorSocks));

        // 3. Block known public resolvers / Tor directory IPs on every port (their DoH runs on 443).
        foreach (var ip in blockedResolverIps.Distinct().Where(ip => !allowed.Contains(ip)))
            rules.Add(new FirewallRule($"Block resolver {ip}", FilterAction.Block, Weights.BlockResolverIps, ip));

        // 4. Fail closed: when no filter can be reached, block everything except the filter, DHCP and loopback.
        if (blockAllExceptFilter)
        {
            foreach (var ip in allowed)
                rules.Add(new FirewallRule($"Permit filter (all ports) {ip}", FilterAction.Permit, Weights.PermitEssential, ip));
            rules.Add(new FirewallRule("Permit DHCP", FilterAction.Permit, Weights.PermitEssential, RemotePorts: Ports.Dhcp, Protocol: 17));
            rules.Add(new FirewallRule("Permit loopback", FilterAction.Permit, Weights.PermitEssential, LoopbackOnly: true));
            rules.Add(new FirewallRule("Block all (no filter reachable)", FilterAction.Block, Weights.BlockAll));
        }
        return rules;
    }
}
