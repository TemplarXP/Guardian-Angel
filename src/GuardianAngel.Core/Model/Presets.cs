namespace GuardianAngel.Core.Model;

/// <summary>
/// Example filters, shown as a convenience only. Guardian Angel is not affiliated with any of them.
/// Addresses are as published by each provider; the connection test confirms them before locking.
/// </summary>
public static class FilterPresets
{
    public sealed record Preset(string Id, string Name, string Description, FilterConfig Config, bool NeedsProfileId = false);

    public static IReadOnlyList<Preset> All { get; } = new[]
    {
        new Preset("cleanbrowsing-family", "CleanBrowsing Family",
            "Blocks adult content, proxies and VPN sites, and enforces SafeSearch.",
            new FilterConfig
            {
                Name = "CleanBrowsing Family", PresetId = "cleanbrowsing-family",
                Servers = ["185.228.168.168", "185.228.169.168", "2a0d:2a00:1::", "2a0d:2a00:2::"],
                Encryption = EncryptionMode.Doh,
                DohTemplate = "https://doh.cleanbrowsing.org/doh/family-filter/",
                DotHost = "family-filter-dns.cleanbrowsing.org",
            }),
        new Preset("cleanbrowsing-adult", "CleanBrowsing Adult",
            "Blocks adult content and enforces SafeSearch. Less strict than Family.",
            new FilterConfig
            {
                Name = "CleanBrowsing Adult", PresetId = "cleanbrowsing-adult",
                Servers = ["185.228.168.10", "185.228.169.11", "2a0d:2a00:1::1", "2a0d:2a00:2::1"],
                Encryption = EncryptionMode.Doh,
                DohTemplate = "https://doh.cleanbrowsing.org/doh/adult-filter/",
                DotHost = "adult-filter-dns.cleanbrowsing.org",
            }),
        new Preset("cloudflare-families", "Cloudflare for Families",
            "Blocks malware and adult content.",
            new FilterConfig
            {
                Name = "Cloudflare for Families", PresetId = "cloudflare-families",
                Servers = ["1.1.1.3", "1.0.0.3", "2606:4700:4700::1113", "2606:4700:4700::1003"],
                Encryption = EncryptionMode.Doh,
                DohTemplate = "https://family.cloudflare-dns.com/dns-query",
                DotHost = "family.cloudflare-dns.com",
            }),
        new Preset("adguard-family", "AdGuard DNS Family",
            "Blocks ads, trackers and adult content, and enforces SafeSearch.",
            new FilterConfig
            {
                Name = "AdGuard DNS Family", PresetId = "adguard-family",
                Servers = ["94.140.14.15", "94.140.15.16", "2a10:50c0::bad1:ff", "2a10:50c0::bad2:ff"],
                Encryption = EncryptionMode.Doh,
                DohTemplate = "https://family.adguard-dns.com/dns-query",
                DotHost = "family.adguard-dns.com",
            }),
        new Preset("nextdns", "NextDNS (your profile)",
            "Your own NextDNS profile. Replace PROFILE with your profile ID. Encrypted DNS is required, because plain NextDNS addresses do not know which profile is yours.",
            new FilterConfig
            {
                Name = "NextDNS", PresetId = "nextdns",
                Servers = ["45.90.28.0", "45.90.30.0", "2a07:a8c0::", "2a07:a8c1::"],
                Encryption = EncryptionMode.Doh,
                DohTemplate = "https://dns.nextdns.io/PROFILE",
                DotHost = "PROFILE.dns.nextdns.io",
            }, NeedsProfileId: true),
    };

    public static Preset? Find(string id) => All.FirstOrDefault(p => p.Id == id);

    /// <summary>Fills in a NextDNS-style profile ID.</summary>
    public static FilterConfig WithProfile(FilterConfig cfg, string profileId) => cfg with
    {
        DohTemplate = cfg.DohTemplate?.Replace("PROFILE", profileId, StringComparison.Ordinal),
        DotHost = cfg.DotHost?.Replace("PROFILE", profileId, StringComparison.Ordinal),
        // NextDNS IPv6 addresses carry the profile ID in the low bits; keep only IPv4 + DoH for simplicity.
        Servers = cfg.PresetId == "nextdns" ? cfg.Servers.Where(s => !s.Contains(':')).ToList() : cfg.Servers,
    };
}
