using System.Net;
using System.Net.Sockets;

namespace GuardianAngel.Core.Model;

/// <summary>The DNS filter the user brought. Guardian Angel never filters by itself.</summary>
public sealed record FilterConfig
{
    public string Name { get; init; } = "";
    public string? PresetId { get; init; }

    /// <summary>Primary first, then fallbacks. IPv4 and/or IPv6 literals.</summary>
    public List<string> Servers { get; init; } = new();

    public EncryptionMode Encryption { get; init; } = EncryptionMode.Doh;

    /// <summary>RFC 8484 template, e.g. https://family.cloudflare-dns.com/dns-query</summary>
    public string? DohTemplate { get; init; }

    /// <summary>TLS host name for DNS over TLS, e.g. family-filter-dns.cleanbrowsing.org</summary>
    public string? DotHost { get; init; }

    public UnreachableBehavior WhenUnreachable { get; init; } = UnreachableBehavior.BlockInternet;

    public IEnumerable<IPAddress> ParsedServers() =>
        Servers.Select(s => IPAddress.TryParse(s, out var ip) ? ip : null).Where(ip => ip is not null)!;

    [System.Text.Json.Serialization.JsonIgnore]
    public IEnumerable<IPAddress> V4 => ParsedServers().Where(a => a.AddressFamily == AddressFamily.InterNetwork);
    [System.Text.Json.Serialization.JsonIgnore]
    public IEnumerable<IPAddress> V6 => ParsedServers().Where(a => a.AddressFamily == AddressFamily.InterNetworkV6);

    /// <summary>Returns a list of problems in plain language. Empty means valid.</summary>
    public List<string> Validate()
    {
        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(Name)) errors.Add("Give your filter a name.");
        if (Servers.Count == 0) errors.Add("Enter at least one DNS server address.");
        if (Servers.Count > 8) errors.Add("Use at most 8 server addresses.");
        foreach (var s in Servers)
        {
            if (!IPAddress.TryParse(s, out var ip))
            {
                errors.Add($"\"{s}\" isn't a valid IP address.");
                continue;
            }
            if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)
                || ip.Equals(IPAddress.Broadcast) || ip.IsIPv6Multicast
                || (ip.AddressFamily == AddressFamily.InterNetwork && ip.GetAddressBytes()[0] >= 224))
                errors.Add($"\"{s}\" can't be used as a DNS server.");
        }
        if (Servers.Distinct(StringComparer.OrdinalIgnoreCase).Count() != Servers.Count)
            errors.Add("The same address is listed twice.");

        switch (Encryption)
        {
            case EncryptionMode.Doh:
                if (!Uri.TryCreate(DohTemplate, UriKind.Absolute, out var u) || u.Scheme != Uri.UriSchemeHttps)
                    errors.Add("Encrypted DNS (DoH) needs an https:// template address.");
                break;
            case EncryptionMode.Dot:
                if (string.IsNullOrWhiteSpace(DotHost) || Uri.CheckHostName(DotHost) != UriHostNameType.Dns)
                    errors.Add("Encrypted DNS (DoT) needs a host name.");
                break;
        }
        return errors;
    }

    /// <summary>True when the two configs would enforce exactly the same thing.</summary>
    public bool SameAs(FilterConfig? other) =>
        other is not null
        && Servers.SequenceEqual(other.Servers, StringComparer.OrdinalIgnoreCase)
        && Encryption == other.Encryption
        && string.Equals(DohTemplate, other.DohTemplate, StringComparison.Ordinal)
        && string.Equals(DotHost, other.DotHost, StringComparison.OrdinalIgnoreCase)
        && WhenUnreachable == other.WhenUnreachable;
}
