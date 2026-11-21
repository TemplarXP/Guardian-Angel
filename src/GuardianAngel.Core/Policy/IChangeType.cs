using System.Text.Json;
using GuardianAngel.Core.Model;

namespace GuardianAngel.Core.Policy;

/// <summary>
/// One kind of change the user can request. To add a new change type, implement this interface
/// and register it in <see cref="ChangeTypeRegistry.CreateDefault"/>. The engine handles queuing,
/// delays, partner codes, logging and persistence for you.
/// </summary>
public interface IChangeType
{
    /// <summary>Stable identifier, stored on disk. Never rename an existing one.</summary>
    string Kind { get; }

    /// <summary>Only one pending change per setting key: a new request replaces the old one.</summary>
    string SettingKey(JsonElement parameters);

    /// <summary>Tighten = applied now; Loosen = queued behind the delay.</summary>
    Direction Classify(LockState current, JsonElement parameters);

    /// <summary>Plain-language problems; empty if the request is acceptable.</summary>
    IReadOnlyList<string> Validate(LockState current, JsonElement parameters);

    /// <summary>Returns the new desired state. Must not have side effects (enforcers apply it).</summary>
    void Apply(LockState state, JsonElement parameters);

    /// <summary>Plain-language description, e.g. "Change filter to CleanBrowsing Family".</summary>
    string Describe(LockState current, JsonElement parameters);

    /// <summary>When true, the engine tests the new configuration before committing it.</summary>
    bool NeedsConnectionTest => false;
}

public sealed class ChangeTypeRegistry
{
    private readonly Dictionary<string, IChangeType> _types = new(StringComparer.Ordinal);

    public void Register(IChangeType type) => _types.Add(type.Kind, type);
    public IChangeType? Find(string kind) => _types.GetValueOrDefault(kind);
    public IEnumerable<IChangeType> All => _types.Values;

    public static ChangeTypeRegistry CreateDefault()
    {
        var r = new ChangeTypeRegistry();
        r.Register(new FilterChange());
        r.Register(new DelayChange());
        r.Register(new PartnerRemove());
        r.Register(new UninstallChange());
        return r;
    }
}
