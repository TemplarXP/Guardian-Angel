using System.Net;
using GuardianAngel.Core.Model;

namespace GuardianAngel.Core.Dns;

public enum BlockCheck { NotTested, Blocked, ResolvedNormally, Failed }

public sealed record ServerResult(string Server, bool Ok, string Detail);

public sealed record ConnectionTestResult(
    bool NormalSitesResolve,
    IReadOnlyList<ServerResult> Servers,
    BlockCheck BlockedDomainResult,
    IReadOnlyList<string> BlockedDomainAnswers,
    string Summary)
{
    /// <summary>A filter may be locked only if this is true.</summary>
    public bool Passed(bool userConfirmedBlockPage) =>
        NormalSitesResolve && BlockedDomainResult switch
        {
            BlockCheck.NotTested or BlockCheck.Blocked => true,
            BlockCheck.ResolvedNormally => userConfirmedBlockPage,
            _ => false,
        };
}

public interface IConnectionTester
{
    Task<ConnectionTestResult> TestAsync(FilterConfig filter, string? blockedDomain, CancellationToken ct);
}

/// <summary>
/// Checks the filter really works, using the exact transport that will be locked in.
/// Run by the SERVICE (never trusted from the UI).
/// </summary>
public sealed class ConnectionTester(Func<FilterConfig, IDnsProbe>? probeFactory = null) : IConnectionTester
{
    public static readonly string[] NormalSites = ["example.com", "microsoft.com"];

    private readonly Func<FilterConfig, IDnsProbe> _probeFactory = probeFactory ?? DefaultProbe;

    public static IDnsProbe DefaultProbe(FilterConfig f) => f.Encryption switch
    {
        EncryptionMode.Doh => new DohProbe(f.DohTemplate!),
        EncryptionMode.Dot => new DotProbe(f.DotHost!),
        _ => new UdpDnsProbe(),
    };

    public async Task<ConnectionTestResult> TestAsync(FilterConfig filter, string? blockedDomain, CancellationToken ct)
    {
        var probe = _probeFactory(filter);
        var results = new List<ServerResult>();
        foreach (var server in filter.ParsedServers())
        {
            var ok = true;
            string detail = "Works";
            foreach (var site in NormalSites)
            {
                try
                {
                    var a = await WithTimeout(probe.QueryAsync(server, site, QType(server), ct), ct);
                    if (a.Rcode != DnsRcode.NoError || a.Addresses.Count == 0 || a.Addresses.All(IsSinkhole))
                    { ok = false; detail = $"{site} didn't resolve ({a.Rcode})"; break; }
                }
                catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
                { ok = false; detail = $"No answer: {Short(ex)}"; break; }
            }
            results.Add(new ServerResult(server.ToString(), ok, detail));
        }

        // The primary server must work. Fallbacks that fail are reported but don't block locking
        // (they might be IPv6 on an IPv4-only network).
        var normalOk = results.Count > 0 && results[0].Ok;

        var block = BlockCheck.NotTested;
        var blockAnswers = new List<string>();
        if (!string.IsNullOrWhiteSpace(blockedDomain) && normalOk)
        {
            var server = filter.ParsedServers().First();
            try
            {
                var a = await WithTimeout(probe.QueryAsync(server, blockedDomain.Trim(), QType(server), ct), ct);
                blockAnswers.AddRange(a.Addresses.Select(x => x.ToString()));
                block = a.Rcode is DnsRcode.NxDomain or DnsRcode.Refused || a.Addresses.Count == 0 || a.Addresses.All(IsSinkhole)
                    ? BlockCheck.Blocked : BlockCheck.ResolvedNormally;
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            { block = BlockCheck.Failed; blockAnswers.Add(Short(ex)); }
        }

        var summary = !normalOk ? "Your filter didn't answer, so it can't be locked yet."
            : block == BlockCheck.Blocked ? "Your filter works and blocked the test site."
            : block == BlockCheck.ResolvedNormally ? "Your filter works, but the test site was not clearly blocked. If these addresses are your filter's block page, confirm it."
            : block == BlockCheck.Failed ? "The blocked-site test failed. Try again."
            : "Your filter works.";
        return new ConnectionTestResult(normalOk, results, block, blockAnswers, summary);
    }

    private static ushort QType(IPAddress server) =>
        server.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? DnsWire.TypeAAAA : DnsWire.TypeA;

    private static bool IsSinkhole(IPAddress ip) => IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any);

    private static async Task<T> WithTimeout<T>(Task<T> t, CancellationToken ct) => await t.WaitAsync(TimeSpan.FromSeconds(8), ct);

    private static string Short(Exception ex) => ex is TimeoutException ? "timed out" : ex.GetBaseException().Message;
}
