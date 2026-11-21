using GuardianAngel.Core.Time;

namespace GuardianAngel.Platform.Windows.Security;

/// <summary>
/// Reads the Date header from HTTPS servers. TLS authenticates the server, so nobody on this PC (without
/// admin rights to install a root certificate) can fake it. Two servers must agree within 2 minutes.
/// </summary>
public sealed class HttpsTrustedTime(Func<IEnumerable<string>> urls) : ITrustedTimeSource
{
    public async Task<DateTimeOffset?> GetTrustedUtcAsync(CancellationToken ct)
    {
        using var http = new HttpClient(new SocketsHttpHandler { UseProxy = false }) { Timeout = TimeSpan.FromSeconds(10) };
        var times = new List<DateTimeOffset>();
        foreach (var url in urls().Distinct())
        {
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Head, url);
                using var resp = await http.SendAsync(req, ct);
                if (resp.Headers.Date is { } d) times.Add(d);
            }
            catch (Exception) when (!ct.IsCancellationRequested) { /* try the next one */ }
            if (times.Count >= 2) break;
        }
        if (times.Count < 2 || (times.Max() - times.Min()) > TimeSpan.FromMinutes(2)) return null;
        return times.Min(); // the earlier one: never counts more off-time than really passed
    }
}
