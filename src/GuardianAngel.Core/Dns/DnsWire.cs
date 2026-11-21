using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace GuardianAngel.Core.Dns;

public enum DnsRcode { NoError = 0, FormErr = 1, ServFail = 2, NxDomain = 3, NotImp = 4, Refused = 5 }

public sealed record DnsAnswer(ushort Id, DnsRcode Rcode, IReadOnlyList<IPAddress> Addresses);

/// <summary>Minimal DNS message encoder/decoder (RFC 1035), enough for A/AAAA lookups in the connection test.</summary>
public static class DnsWire
{
    public const ushort TypeA = 1, TypeAAAA = 28;

    public static byte[] BuildQuery(string name, ushort qtype, ushort? id = null)
    {
        var qid = id ?? BinaryPrimitives.ReadUInt16BigEndian(RandomNumberGenerator.GetBytes(2));
        var buf = new List<byte>(64);
        Span<byte> h = stackalloc byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(h, qid);
        h[2] = 0x01; // RD
        BinaryPrimitives.WriteUInt16BigEndian(h[4..], 1); // QDCOUNT
        buf.AddRange(h.ToArray());
        foreach (var label in name.TrimEnd('.').Split('.'))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            if (bytes.Length is 0 or > 63) throw new ArgumentException("Invalid domain name.", nameof(name));
            buf.Add((byte)bytes.Length);
            buf.AddRange(bytes);
        }
        buf.Add(0);
        buf.Add((byte)(qtype >> 8)); buf.Add((byte)qtype);
        buf.Add(0); buf.Add(1); // IN
        return buf.ToArray();
    }

    public static DnsAnswer Parse(ReadOnlySpan<byte> msg)
    {
        if (msg.Length < 12) throw new FormatException("DNS response too short.");
        var id = BinaryPrimitives.ReadUInt16BigEndian(msg);
        if ((msg[2] & 0x80) == 0) throw new FormatException("Not a DNS response.");
        var rcode = (DnsRcode)(msg[3] & 0x0F);
        int qd = BinaryPrimitives.ReadUInt16BigEndian(msg[4..]);
        int an = BinaryPrimitives.ReadUInt16BigEndian(msg[6..]);
        int pos = 12;
        for (int i = 0; i < qd; i++) { pos = SkipName(msg, pos); pos += 4; }
        var addrs = new List<IPAddress>();
        for (int i = 0; i < an; i++)
        {
            pos = SkipName(msg, pos);
            if (pos + 10 > msg.Length) throw new FormatException("Truncated answer.");
            var type = BinaryPrimitives.ReadUInt16BigEndian(msg[pos..]);
            var rdlen = BinaryPrimitives.ReadUInt16BigEndian(msg[(pos + 8)..]);
            pos += 10;
            if (pos + rdlen > msg.Length) throw new FormatException("Truncated record.");
            if (type == TypeA && rdlen == 4) addrs.Add(new IPAddress(msg.Slice(pos, 4)));
            else if (type == TypeAAAA && rdlen == 16) addrs.Add(new IPAddress(msg.Slice(pos, 16)));
            pos += rdlen;
        }
        return new DnsAnswer(id, rcode, addrs);
    }

    private static int SkipName(ReadOnlySpan<byte> msg, int pos)
    {
        for (int guard = 0; guard < 128; guard++)
        {
            if (pos >= msg.Length) throw new FormatException("Bad name.");
            var len = msg[pos];
            if (len == 0) return pos + 1;
            if ((len & 0xC0) == 0xC0) return pos + 2; // compression pointer ends the name
            pos += 1 + len;
        }
        throw new FormatException("Name too long.");
    }
}
