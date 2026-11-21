using System.Text.Json;

namespace GuardianAngel.Core.Model;

/// <summary>
/// Everything Guardian Angel knows. Stored only by the service, encrypted, in ProgramData.
/// The UI never sees this object directly (it gets a <see cref="Ipc.StatusDto"/>).
/// </summary>
public sealed class LockState
{
    public int SchemaVersion { get; set; } = 1;

    /// <summary>Increases on every save; used to pick the newest of the two copies on disk.</summary>
    public long Generation { get; set; }

    public bool IsLocked { get; set; }
    public DateTimeOffset? LockedAtUtc { get; set; }

    public FilterConfig? Filter { get; set; }
    public UnlockPolicy Unlock { get; set; } = new();
    public PartnerState? Partner { get; set; }
    public string ReflectionMessage { get; set; } = "";
    public BrowserOptions Browser { get; set; } = new();

    /// <summary>Pending changes plus recent history (trimmed).</summary>
    public List<ChangeRequest> Changes { get; set; } = new();

    public ClockState Clock { get; set; } = new();

    /// <summary>Set only when an uninstall change has been applied (or before the first Lock).</summary>
    public bool UninstallAuthorized { get; set; } = true;

    /// <summary>
    /// While a filter change is being tested at apply time, the new servers are allowed through the
    /// firewall together with the old ones. Never persisted as "the" filter.
    /// </summary>
    public List<string> TransitionalServers { get; set; } = new();

    public LockState Clone()
    {
        var json = JsonSerializer.Serialize(this, Json.Options);
        return JsonSerializer.Deserialize<LockState>(json, Json.Options)!;
    }
}

public sealed record UnlockPolicy
{
    /// <summary>When false, loosening is only possible with a partner code.</summary>
    public bool DelayEnabled { get; init; } = true;
    public TimeSpan Delay { get; init; } = TimeSpan.FromHours(24);

    /// <summary>Null means "infinite": only a partner code can approve.</summary>
    public TimeSpan? EffectiveDelay => DelayEnabled ? Delay : null;
}

public sealed class PartnerState
{
    /// <summary>The TOTP secret. Never sent to the UI after setup. Protected by the state file's encryption.</summary>
    public byte[] Secret { get; set; } = [];
    public DateTimeOffset AddedUtc { get; set; }
    /// <summary>Last accepted 30-second step; codes for this step or earlier are rejected (replay protection).</summary>
    public long LastUsedStep { get; set; } = -1;
    public int FailedAttempts { get; set; }
    /// <summary>Monotonic milliseconds of lockout still to serve. Counted down only while the PC runs.</summary>
    public long LockoutRemainingMs { get; set; }
}

public sealed record BrowserOptions
{
    /// <summary>Always on: built-in secure DNS in browsers would get around the filter.</summary>
    public bool DisableBrowserSecureDns { get; init; } = true;
    public bool DisablePrivateMode { get; init; }
    public bool BlockProxyExtensions { get; init; }
}

public sealed class ChangeRequest
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Kind { get; set; } = "";
    public string SettingKey { get; set; } = "";
    public JsonElement Parameters { get; set; }
    public string Description { get; set; } = "";
    public DateTimeOffset RequestedAtUtc { get; set; }

    /// <summary>Delay that applied when requested (may be raised later, never lowered). Null = partner code only.</summary>
    public long? RequiredMs { get; set; }
    /// <summary>Monotonic time already served.</summary>
    public long CreditedMs { get; set; }
    /// <summary>Boot counter when requested; time spent switched off only counts for earlier boots.</summary>
    public long RequestedBoot { get; set; }

    public ChangeStatus Status { get; set; } = ChangeStatus.Pending;
    public DateTimeOffset? FinishedAtUtc { get; set; }
    public string? ExpeditedBy { get; set; }
    public string? FailureReason { get; set; }

    public long? RemainingMs => RequiredMs is null ? null : Math.Max(0, RequiredMs.Value - CreditedMs);
    public bool IsDue => Status == ChangeStatus.Pending && RequiredMs is not null && CreditedMs >= RequiredMs.Value;
}

public sealed class ClockState
{
    /// <summary>Incremented every time the service starts.</summary>
    public long BootCounter { get; set; }

    /// <summary>Best estimate of the real (trusted) time at the last save, or null if never verified.</summary>
    public DateTimeOffset? LastTrustedEstimateUtc { get; set; }

    /// <summary>Monotonic time credited since <see cref="LastTrustedEstimateUtc"/> was recorded.</summary>
    public long CreditedSinceEstimateMs { get; set; }

    /// <summary>Boot counter when <see cref="LastTrustedEstimateUtc"/> was last updated.</summary>
    public long EstimateBoot { get; set; }
}
