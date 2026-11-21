using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using GuardianAngel.Core.Model;

namespace GuardianAngel.Core.Lists;

/// <summary>Public resolvers (blocked on every port, since their DoH runs on 443) and Tor directory IPs.</summary>
public sealed record ResolverList(int Version, DateTimeOffset Updated, List<string> Resolvers, List<string> Tor)
{
    public IEnumerable<IPAddress> AllIps() => Resolvers.Concat(Tor)
        .Select(s => IPAddress.TryParse(s, out var ip) ? ip : null).Where(ip => ip is not null)!;
}

/// <summary>
/// Lists can be updated without a new release, but only if signed with the project's offline key
/// (ECDSA P-256 / SHA-256, signature in a ".sig" file next to the JSON). A list with a lower version
/// than the built-in one is ignored, so an old (weaker) list can't be replayed.
/// </summary>
public static class SignedList
{
    /// <summary>
    /// The maintainer's public key (SubjectPublicKeyInfo, Base64). Empty until the maintainer runs
    /// `GuardianAngel.Signer new-key`. While empty, only the built-in list is used.
    /// </summary>
    public const string PublicKeyBase64 = "";

    public static bool Verify(byte[] data, byte[] signature, string publicKeyBase64 = PublicKeyBase64)
    {
        if (string.IsNullOrEmpty(publicKeyBase64)) return false;
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKeyBase64), out _);
        return ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256);
    }

    public static ResolverList LoadResolvers(string? updatedJsonPath, string publicKeyBase64 = PublicKeyBase64)
    {
        var builtIn = BuiltInLists.Resolvers;
        if (updatedJsonPath is null || !File.Exists(updatedJsonPath) || !File.Exists(updatedJsonPath + ".sig")) return builtIn;
        try
        {
            var data = File.ReadAllBytes(updatedJsonPath);
            var sig = File.ReadAllBytes(updatedJsonPath + ".sig");
            if (!Verify(data, sig, publicKeyBase64)) return builtIn;
            var list = JsonSerializer.Deserialize<ResolverList>(data, Json.Options);
            return list is not null && list.Version > builtIn.Version ? list : builtIn;
        }
        catch (Exception) { return builtIn; }
    }
}

public static class BuiltInLists
{
    public static readonly ResolverList Resolvers = new(1, new DateTimeOffset(2026, 11, 21, 0, 0, 0, TimeSpan.Zero),
        Resolvers:
        [
            // Google
            "8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844",
            // Cloudflare (unfiltered + malware-only)
            "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "2606:4700:4700::1111", "2606:4700:4700::1001",
            "2606:4700:4700::1112", "2606:4700:4700::1002",
            // Quad9
            "9.9.9.9", "149.112.112.112", "9.9.9.10", "149.112.112.10", "9.9.9.11", "149.112.112.11",
            "2620:fe::fe", "2620:fe::9", "2620:fe::10", "2620:fe::fe:10", "2620:fe::11", "2620:fe::fe:11",
            // OpenDNS / Cisco Umbrella (home, not FamilyShield)
            "208.67.222.222", "208.67.220.220", "2620:119:35::35", "2620:119:53::53",
            // AdGuard default + unfiltered
            "94.140.14.14", "94.140.15.15", "94.140.14.140", "94.140.14.141", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff",
            "2a10:50c0::1:ff", "2a10:50c0::2:ff",
            // Control D free resolvers
            "76.76.2.0", "76.76.10.0", "76.76.2.1", "2606:1a40::", "2606:1a40:1::",
            // Mullvad DNS
            "194.242.2.2", "194.242.2.3", "2a07:e340::2", "2a07:e340::3",
            // DNS.SB, Comodo, Yandex, Verisign, AliDNS, 114DNS, DNS.WATCH, Level3
            "185.222.222.222", "45.11.45.11", "8.26.56.26", "8.20.247.20", "77.88.8.8", "77.88.8.1",
            "64.6.64.6", "64.6.65.6", "223.5.5.5", "223.6.6.6", "114.114.114.114", "114.114.115.115",
            "84.200.69.80", "84.200.70.40", "4.2.2.1", "4.2.2.2", "4.2.2.3", "4.2.2.4", "4.2.2.5", "4.2.2.6",
            // CleanBrowsing security-only (not a content filter)
            "185.228.168.9", "185.228.169.9",
        ],
        Tor:
        [
            // Tor directory authorities (a seed only; full relay lists come via signed updates,
            // and application control in Milestone 3 is the real defense against Tor).
            "128.31.0.39", "86.59.21.38", "194.109.206.212", "199.58.81.140", "204.13.164.118",
            "171.25.193.9", "154.35.175.225", "131.188.40.189", "193.23.244.244", "45.66.33.45",
        ]);
}
