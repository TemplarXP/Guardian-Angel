using System.Net;

namespace GuardianAngel.Core.Hosts;

/// <summary>
/// The hosts file can make a name point anywhere, which gets around a DNS filter.
/// Entries that point a name at 0.0.0.0 / 127.x / ::1 only BLOCK things and are allowed.
/// Entries that point a name at any real address are removed.
/// </summary>
public static class HostsAnalyzer
{
    public sealed record Result(string SanitizedContent, IReadOnlyList<string> RemovedLines)
    {
        public bool Changed => RemovedLines.Count > 0;
    }

    public static Result Sanitize(string content)
    {
        var removed = new List<string>();
        var kept = new List<string>();
        foreach (var raw in content.Replace("\r\n", "\n").Split('\n'))
        {
            if (IsBypassLine(raw)) removed.Add(raw.Trim());
            else kept.Add(raw);
        }
        var text = string.Join("\r\n", kept);
        return new Result(text, removed);
    }

    public static bool IsBypassLine(string line)
    {
        var hash = line.IndexOf('#');
        var body = (hash >= 0 ? line[..hash] : line).Trim();
        if (body.Length == 0) return false;

        var parts = body.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2) return false;
        if (!IPAddress.TryParse(parts[0], out var ip)) return true; // malformed lines are removed too

        if (IsSinkhole(ip)) return false;
        return true;
    }

    private static bool IsSinkhole(IPAddress ip) =>
        IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any) || ip.Equals(IPAddress.IPv6None);

    public const string DefaultWindowsHosts =
        "# Copyright (c) 1993-2009 Microsoft Corp.\r\n#\r\n# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\r\n" +
        "#\r\n# localhost name resolution is handled within DNS itself.\r\n#\t127.0.0.1       localhost\r\n#\t::1             localhost\r\n";
}
