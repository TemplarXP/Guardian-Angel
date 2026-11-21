using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;

namespace GuardianAngel.Core.Dns;

/// <summary>Sends one DNS query to one specific server using a specific transport.</summary>
public interface IDnsProbe
{
    Task<DnsAnswer> QueryAsync(IPAddress server, string name, ushort qtype, CancellationToken ct);
}

public sealed class UdpDnsProbe : IDnsProbe
{
    public async Task<DnsAnswer> QueryAsync(IPAddress server, string name, ushort qtype, CancellationToken ct)
    {
        var q = DnsWire.BuildQuery(name, qtype);
        using var udp = new UdpClient(server.AddressFamily);
        await udp.SendAsync(q, new IPEndPoint(server, 53), ct);
        while (true)
        {
            var r = await udp.ReceiveAsync(ct);
            if (!r.RemoteEndPoint.Address.Equals(server)) continue;
            var ans = DnsWire.Parse(r.Buffer);
            if (ans.Id == BitConverter.ToUInt16([q[1], q[0]])) return ans;
        }
    }
}

/// <summary>RFC 8484 DNS over HTTPS, connecting to the given IP while using the template's host name for TLS.</summary>
public sealed class DohProbe(string template) : IDnsProbe
{
    public async Task<DnsAnswer> QueryAsync(IPAddress server, string name, ushort qtype, CancellationToken ct)
    {
        var uri = new Uri(template);
        var handler = new SocketsHttpHandler
        {
            ConnectCallback = async (ctx, token) =>
            {
                var s = new Socket(server.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                try { await s.ConnectAsync(new IPEndPoint(server, uri.Port), token); return new NetworkStream(s, ownsSocket: true); }
                catch { s.Dispose(); throw; }
            },
            UseProxy = false,
        };
        using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(8) };
        var body = new ByteArrayContent(DnsWire.BuildQuery(name, qtype, id: 0)); // RFC 8484: ID 0
        body.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");
        using var req = new HttpRequestMessage(HttpMethod.Post, uri) { Content = body };
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-message"));
        using var resp = await http.SendAsync(req, ct);
        resp.EnsureSuccessStatusCode();
        return DnsWire.Parse(await resp.Content.ReadAsByteArrayAsync(ct));
    }
}

/// <summary>RFC 7858 DNS over TLS.</summary>
public sealed class DotProbe(string tlsHost) : IDnsProbe
{
    public async Task<DnsAnswer> QueryAsync(IPAddress server, string name, ushort qtype, CancellationToken ct)
    {
        using var tcp = new TcpClient(server.AddressFamily);
        await tcp.ConnectAsync(server, 853, ct);
        await using var ssl = new SslStream(tcp.GetStream());
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = tlsHost }, ct);
        var q = DnsWire.BuildQuery(name, qtype);
        var framed = new byte[q.Length + 2];
        framed[0] = (byte)(q.Length >> 8); framed[1] = (byte)q.Length;
        q.CopyTo(framed, 2);
        await ssl.WriteAsync(framed, ct);
        var lenBuf = new byte[2];
        await ssl.ReadExactlyAsync(lenBuf, ct);
        var resp = new byte[(lenBuf[0] << 8) | lenBuf[1]];
        await ssl.ReadExactlyAsync(resp, ct);
        return DnsWire.Parse(resp);
    }
}
