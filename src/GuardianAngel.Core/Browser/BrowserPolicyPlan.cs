using GuardianAngel.Core.Model;

namespace GuardianAngel.Core.Browser;

public enum RegKind { String, DWord }

/// <summary>A machine-wide policy value (under HKLM). Standard users can't write HKLM; the service also guards it.</summary>
public sealed record PolicyValue(string KeyPath, string Name, RegKind Kind, object Value);

public static class BrowserPolicyPlanner
{
    public const string ChromeKey = @"SOFTWARE\Policies\Google\Chrome";
    public const string EdgeKey = @"SOFTWARE\Policies\Microsoft\Edge";
    public const string BraveKey = @"SOFTWARE\Policies\BraveSoftware\Brave";
    public const string FirefoxKey = @"SOFTWARE\Policies\Mozilla\Firefox";

    /// <summary>Every key Guardian Angel may write. Used for removal on uninstall.</summary>
    public static readonly string[] ChromiumKeys = [ChromeKey, EdgeKey, BraveKey];

    public static List<PolicyValue> Plan(BrowserOptions o, IReadOnlyList<string>? blockedExtensionIds = null)
    {
        var v = new List<PolicyValue>();
        foreach (var key in ChromiumKeys)
        {
            // Built-in secure DNS would send lookups straight to the browser's own resolver.
            v.Add(new(key, "DnsOverHttpsMode", RegKind.String, "off"));
            if (o.DisablePrivateMode)
                v.Add(new(key, key == EdgeKey ? "InPrivateModeAvailability" : "IncognitoModeAvailability", RegKind.DWord, 1));
            if (o.BlockProxyExtensions)
            {
                // Forcing "direct" means no extension can set a proxy (which would resolve names remotely).
                v.Add(new(key, "ProxySettings", RegKind.String, "{\"ProxyMode\":\"direct\"}"));
                var i = 1;
                foreach (var id in blockedExtensionIds ?? [])
                    v.Add(new(key + @"\ExtensionInstallBlocklist", (i++).ToString(), RegKind.String, id));
            }
        }

        v.Add(new(FirefoxKey + @"\DNSOverHTTPS", "Enabled", RegKind.DWord, 0));
        v.Add(new(FirefoxKey + @"\DNSOverHTTPS", "Locked", RegKind.DWord, 1));
        if (o.DisablePrivateMode) v.Add(new(FirefoxKey, "DisablePrivateBrowsing", RegKind.DWord, 1));
        if (o.BlockProxyExtensions)
        {
            v.Add(new(FirefoxKey + @"\Proxy", "Mode", RegKind.String, "none"));
            v.Add(new(FirefoxKey + @"\Proxy", "Locked", RegKind.DWord, 1));
        }
        return v;
    }

    /// <summary>Value names we own, per key, so removal never touches policies we didn't set.</summary>
    public static IEnumerable<(string Key, string Name)> AllPossible() =>
        Plan(new BrowserOptions { DisablePrivateMode = true, BlockProxyExtensions = true })
            .Where(p => !p.KeyPath.EndsWith("ExtensionInstallBlocklist", StringComparison.Ordinal))
            .Select(p => (p.KeyPath, p.Name));
}
