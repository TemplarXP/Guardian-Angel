namespace GuardianAngel.Core.Policy;

public static class Limits
{
#if GA_DEBUG_BYPASS
    // Debug builds only: allow 1-minute delays so testing in a VM is practical.
    public static readonly TimeSpan MinDelay = TimeSpan.FromMinutes(1);
#else
    public static readonly TimeSpan MinDelay = TimeSpan.FromHours(1);
#endif
    public static readonly TimeSpan MaxDelay = TimeSpan.FromDays(30);

    public const int ReflectionMaxLength = 2000;
    public const int MaxFailedCodes = 5;
    public static readonly TimeSpan CodeLockout = TimeSpan.FromHours(1);

    /// <summary>How many finished changes to keep in state for display (the log keeps everything).</summary>
    public const int HistoryToKeep = 50;
}
