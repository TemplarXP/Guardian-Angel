using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using GuardianAngel.Core.Model;

namespace GuardianAngel.Core.Log;

public sealed record LogEntry(long Seq, DateTimeOffset Utc, string Kind, string Message, string Prev, string Mac);

public interface IAccountabilityLog
{
    void Append(string kind, string message);
}

/// <summary>
/// Append-only, tamper-evident log. Each line carries an HMAC over (previous MAC + this entry),
/// keyed with a secret only the service can read, so editing, deleting or reordering lines is detected.
/// (Milestone 1 writes the log; the partner-gated full view arrives in Milestone 2.)
/// </summary>
public sealed class AccountabilityLog : IAccountabilityLog
{
    private readonly string _path;
    private readonly byte[] _key;
    private readonly Func<DateTimeOffset> _now;
    private readonly object _gate = new();
    private long _seq;
    private string _prev = "genesis";

    public AccountabilityLog(string path, byte[] key, Func<DateTimeOffset>? now = null)
    {
        _path = path;
        _key = key;
        _now = now ?? (() => DateTimeOffset.UtcNow);
        var last = ReadAll().LastOrDefault();
        if (last is not null) { _seq = last.Seq; _prev = last.Mac; }
    }

    public void Append(string kind, string message)
    {
        lock (_gate)
        {
            var seq = _seq + 1;
            var utc = _now();
            var mac = ComputeMac(seq, utc, kind, message, _prev);
            var line = JsonSerializer.Serialize(new LogEntry(seq, utc, kind, message, _prev, mac), Json.Options);
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            using (var fs = new FileStream(_path, FileMode.Append, FileAccess.Write, FileShare.Read))
            using (var w = new StreamWriter(fs, new UTF8Encoding(false)))
                w.WriteLine(line);
            _seq = seq;
            _prev = mac;
        }
    }

    public IEnumerable<LogEntry> ReadAll()
    {
        if (!File.Exists(_path)) yield break;
        foreach (var line in File.ReadLines(_path))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            LogEntry? e;
            try { e = JsonSerializer.Deserialize<LogEntry>(line, Json.Options); } catch (JsonException) { e = null; }
            if (e is not null) yield return e;
        }
    }

    /// <summary>Returns null if the whole chain is intact, otherwise a description of the first break.</summary>
    public string? Verify()
    {
        var prev = "genesis";
        long expectSeq = 1;
        foreach (var e in ReadAll())
        {
            if (e.Seq != expectSeq) return $"Entry {expectSeq} is missing.";
            if (e.Prev != prev) return $"Entry {e.Seq} doesn't follow the previous entry.";
            if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(ComputeMac(e.Seq, e.Utc, e.Kind, e.Message, e.Prev)), Encoding.ASCII.GetBytes(e.Mac)))
                return $"Entry {e.Seq} was changed.";
            prev = e.Mac;
            expectSeq++;
        }
        return null;
    }

    private string ComputeMac(long seq, DateTimeOffset utc, string kind, string message, string prev)
    {
        var data = Encoding.UTF8.GetBytes($"{seq}\n{utc:O}\n{kind}\n{message}\n{prev}");
        return Convert.ToHexString(HMACSHA256.HashData(_key, data));
    }
}

public sealed class NullLog : IAccountabilityLog
{
    public List<(string Kind, string Message)> Entries { get; } = new();
    public void Append(string kind, string message) => Entries.Add((kind, message));
}
