using System.Text.Json;
using GuardianAngel.Core.Model;

namespace GuardianAngel.Core.State;

/// <summary>Encrypts/decrypts at rest. On Windows: DPAPI under the SYSTEM account (only SYSTEM can decrypt).</summary>
public interface IDataProtector
{
    byte[] Protect(byte[] plain);
    byte[] Unprotect(byte[] cipher);
}

public interface IStateStore
{
    /// <summary>Returns the newest readable copy, a fresh state if none exists, or throws <see cref="StateCorruptException"/>.</summary>
    LockState Load();
    void Save(LockState state);
}

public sealed class StateCorruptException(string message) : Exception(message);

/// <summary>
/// Keeps two copies (A/B) and always overwrites the older one, so a crash or power cut mid-write
/// still leaves the previous good copy. Each write is atomic (temp file + replace) and flushed.
/// </summary>
public sealed class FileStateStore(string directory, IDataProtector protector, Action<string>? hardenFile = null) : IStateStore
{
    private string PathFor(int slot) => Path.Combine(directory, slot == 0 ? "state-a.bin" : "state-b.bin");

    public LockState Load()
    {
        Directory.CreateDirectory(directory);
        var candidates = new List<LockState>();
        var anyFile = false;
        for (int slot = 0; slot < 2; slot++)
        {
            var p = PathFor(slot);
            if (!File.Exists(p)) continue;
            anyFile = true;
            try
            {
                var json = protector.Unprotect(File.ReadAllBytes(p));
                var s = JsonSerializer.Deserialize<LockState>(json, Json.Options);
                if (s is not null) candidates.Add(s);
            }
            catch (Exception) { /* fall through to the other copy */ }
        }
        if (candidates.Count > 0) return candidates.MaxBy(s => s.Generation)!;
        if (anyFile) throw new StateCorruptException("Guardian Angel's saved settings couldn't be read.");
        return new LockState();
    }

    public void Save(LockState state)
    {
        Directory.CreateDirectory(directory);
        state.Generation++;
        var target = PathFor((int)(state.Generation % 2));
        var tmp = target + ".tmp";
        var bytes = protector.Protect(JsonSerializer.SerializeToUtf8Bytes(state, Json.Options));
        using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
        {
            fs.Write(bytes);
            fs.Flush(flushToDisk: true);
        }
        hardenFile?.Invoke(tmp);
        File.Move(tmp, target, overwrite: true);
    }
}

/// <summary>For tests only.</summary>
public sealed class InMemoryStateStore : IStateStore
{
    private string? _json;
    public int Saves { get; private set; }
    public LockState Load() => _json is null ? new LockState() : JsonSerializer.Deserialize<LockState>(_json, Json.Options)!;
    public void Save(LockState state) { state.Generation++; _json = JsonSerializer.Serialize(state, Json.Options); Saves++; }
}

public sealed class NullProtector : IDataProtector
{
    public byte[] Protect(byte[] plain) => plain;
    public byte[] Unprotect(byte[] cipher) => cipher;
}
