using System.Text.Json;
using GuardianAngel.Core.Engine;
using GuardianAngel.Core.Model;

namespace GuardianAngel.Core.Policy;

/// <summary>Change or remove the locked filter. Always loosening: Guardian Angel can't judge which filter is stricter.</summary>
public sealed class FilterChange : IChangeType
{
    public string Kind => "filter.change";
    public string SettingKey(JsonElement p) => "filter";
    public Direction Classify(LockState current, JsonElement p) => Direction.Loosen;
    public bool NeedsConnectionTest => true;

    public IReadOnlyList<string> Validate(LockState current, JsonElement p)
    {
        var f = Json.FromElement<FilterConfig>(p);
        if (f is null) return ["No filter given."];
        var errors = f.Validate();
        if (f.SameAs(current.Filter)) errors.Add("That's the filter you already have.");
        return errors;
    }

    public void Apply(LockState state, JsonElement p) => state.Filter = Json.FromElement<FilterConfig>(p);

    public string Describe(LockState current, JsonElement p)
    {
        var f = Json.FromElement<FilterConfig>(p);
        return $"Change filter from \"{current.Filter?.Name}\" to \"{f?.Name}\"";
    }
}

public sealed record DelayChangeParams(bool DelayEnabled, TimeSpan Delay);

/// <summary>Longer delay = instant. Shorter delay = waits out the CURRENT (longer) delay.</summary>
public sealed class DelayChange : IChangeType
{
    public string Kind => "delay.change";
    public string SettingKey(JsonElement p) => "delay";

    public Direction Classify(LockState current, JsonElement p)
    {
        var np = Json.FromElement<DelayChangeParams>(p)!;
        var proposed = np.DelayEnabled ? np.Delay : (TimeSpan?)null;
        return DelayMath.IsAtLeastAsStrict(proposed, current.Unlock.EffectiveDelay) ? Direction.Tighten : Direction.Loosen;
    }

    public IReadOnlyList<string> Validate(LockState current, JsonElement p)
    {
        var np = Json.FromElement<DelayChangeParams>(p);
        if (np is null) return ["No delay given."];
        var errors = new List<string>();
        if (np.DelayEnabled && (np.Delay < Limits.MinDelay || np.Delay > Limits.MaxDelay))
            errors.Add($"The delay must be between {DelayMath.Describe(Limits.MinDelay)} and {DelayMath.Describe(Limits.MaxDelay)}.");
        if (!np.DelayEnabled && current.Partner is null)
            errors.Add("You can only turn the delay off when you have an accountability partner.");
        var proposed = np.DelayEnabled ? np.Delay : (TimeSpan?)null;
        if (proposed == current.Unlock.EffectiveDelay) errors.Add("That's the delay you already have.");
        return errors;
    }

    public void Apply(LockState state, JsonElement p)
    {
        var np = Json.FromElement<DelayChangeParams>(p)!;
        state.Unlock = state.Unlock with { DelayEnabled = np.DelayEnabled, Delay = np.DelayEnabled ? np.Delay : state.Unlock.Delay };
    }

    public string Describe(LockState current, JsonElement p)
    {
        var np = Json.FromElement<DelayChangeParams>(p)!;
        return np.DelayEnabled
            ? $"Change the delay from {DelayMath.Describe(current.Unlock.EffectiveDelay)} to {DelayMath.Describe(np.Delay)}"
            : "Turn the delay off (partner code only)";
    }
}

public sealed class PartnerRemove : IChangeType
{
    public string Kind => "partner.remove";
    public string SettingKey(JsonElement p) => "partner";
    public Direction Classify(LockState current, JsonElement p) => Direction.Loosen;

    public IReadOnlyList<string> Validate(LockState current, JsonElement p)
    {
        if (current.Partner is null) return ["You don't have an accountability partner."];
        if (!current.Unlock.DelayEnabled)
            return ["Turn on a time delay first. Without a delay or a partner, nothing could ever be unlocked."];
        return [];
    }

    public void Apply(LockState state, JsonElement p) => state.Partner = null;
    public string Describe(LockState current, JsonElement p) => "Remove your accountability partner";
}

public sealed class UninstallChange : IChangeType
{
    public string Kind => "uninstall";
    public string SettingKey(JsonElement p) => "uninstall";
    public Direction Classify(LockState current, JsonElement p) => Direction.Loosen;
    public IReadOnlyList<string> Validate(LockState current, JsonElement p) => [];

    public void Apply(LockState state, JsonElement p)
    {
        state.UninstallAuthorized = true;
        state.IsLocked = false;
    }

    public string Describe(LockState current, JsonElement p) => "Uninstall Guardian Angel";
}
