namespace GuardianAngel.Core.Time;

/// <summary>
/// A clock that only moves forward and cannot be changed by any user.
/// On Windows this is GetTickCount64 (keeps counting during sleep, resets at boot).
/// Delays are measured with this clock, never with the wall clock.
/// </summary>
public interface IMonotonicClock
{
    /// <summary>Milliseconds since an arbitrary point (boot). Never decreases within one boot.</summary>
    long NowMs { get; }
}

public sealed class SystemMonotonicClock : IMonotonicClock
{
    public long NowMs => Environment.TickCount64;
}

/// <summary>The ordinary system clock. Used for display, TOTP and time-of-day rules only.</summary>
public interface IWallClock
{
    DateTimeOffset UtcNow { get; }
}

public sealed class SystemWallClock : IWallClock
{
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}

/// <summary>
/// A time source that cannot be changed from this PC (for example the TLS-authenticated
/// Date header of an HTTPS server). Used only to decide whether time spent switched off
/// may count toward a delay. Returns null when no trusted time is available.
/// </summary>
public interface ITrustedTimeSource
{
    Task<DateTimeOffset?> GetTrustedUtcAsync(CancellationToken ct);
}
