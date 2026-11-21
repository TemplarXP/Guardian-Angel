namespace GuardianAngel.Core.Engine;

public static class DelayMath
{
    /// <summary>Null = infinite (partner code only), which is the strictest.</summary>
    public static bool IsAtLeastAsStrict(TimeSpan? proposed, TimeSpan? current) =>
        proposed is null || (current is not null && proposed.Value >= current.Value);

    public static TimeSpan? Max(TimeSpan? a, TimeSpan? b) => a is null || b is null ? null : (a > b ? a : b);

    public static string Describe(TimeSpan? d)
    {
        if (d is null) return "partner code only";
        var t = d.Value;
        if (t.TotalDays >= 1 && t.TotalHours % 24 == 0) return Plural((int)t.TotalDays, "day");
        if (t.TotalHours >= 1 && t.TotalMinutes % 60 == 0) return Plural((int)t.TotalHours, "hour");
        if (t.TotalMinutes >= 1 && t.TotalSeconds % 60 == 0) return Plural((int)t.TotalMinutes, "minute");
        if (t.TotalHours >= 1) return $"{Plural((int)t.TotalHours, "hour")} {Plural(t.Minutes, "minute")}";
        return Plural((int)Math.Ceiling(t.TotalSeconds), "second");
    }

    /// <summary>Countdown text, e.g. "11 h 59 min", "4 min 03 s".</summary>
    public static string Countdown(long? remainingMs)
    {
        if (remainingMs is null) return "Waiting for partner code";
        var t = TimeSpan.FromMilliseconds(remainingMs.Value);
        if (t.TotalDays >= 1) return $"{(int)t.TotalDays} d {t.Hours} h";
        if (t.TotalHours >= 1) return $"{(int)t.TotalHours} h {t.Minutes:00} min";
        return $"{t.Minutes} min {t.Seconds:00} s";
    }

    private static string Plural(int n, string unit) => n == 1 ? $"1 {unit}" : $"{n} {unit}s";
}

/// <summary>The typed confirmation sentence. The service checks it, not just the UI.</summary>
public static class Confirmation
{
    public static string PhraseFor(TimeSpan? delay) => delay is null
        ? "I choose to ask my partner for this change."
        : $"I choose to wait {DelayMath.Describe(delay)} for this change.";

    public static bool Matches(string expected, string? typed) =>
        typed is not null && string.Equals(Normalize(expected), Normalize(typed), StringComparison.OrdinalIgnoreCase);

    private static string Normalize(string s) => string.Join(' ', s.Trim().TrimEnd('.').Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
}
