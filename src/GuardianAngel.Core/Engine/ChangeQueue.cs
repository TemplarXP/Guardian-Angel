using System.Text.Json;
using GuardianAngel.Core.Model;
using GuardianAngel.Core.Policy;

namespace GuardianAngel.Core.Engine;

/// <summary>
/// The queue of loosening requests. Operates on <see cref="LockState.Changes"/> so it is
/// persisted with everything else. All time is monotonic credit, never wall-clock math.
/// </summary>
public sealed class ChangeQueue(LockState state)
{
    public IEnumerable<ChangeRequest> Pending => state.Changes.Where(c => c.Status == ChangeStatus.Pending);

    /// <summary>Adds a request. A pending request for the same setting is superseded (its countdown restarts).</summary>
    public ChangeRequest Enqueue(IChangeType type, JsonElement parameters, TimeSpan? delay, DateTimeOffset nowUtc, long bootCounter)
    {
        var key = type.SettingKey(parameters);
        foreach (var old in Pending.Where(c => c.SettingKey == key).ToList())
        {
            old.Status = ChangeStatus.Superseded;
            old.FinishedAtUtc = nowUtc;
        }

        var req = new ChangeRequest
        {
            Kind = type.Kind,
            SettingKey = key,
            Parameters = parameters.Clone(),
            Description = type.Describe(state, parameters),
            RequestedAtUtc = nowUtc,
            RequiredMs = delay is null ? null : (long)delay.Value.TotalMilliseconds,
            RequestedBoot = bootCounter,
        };
        state.Changes.Add(req);
        Trim();
        return req;
    }

    public bool Cancel(Guid id, DateTimeOffset nowUtc)
    {
        var c = Pending.FirstOrDefault(x => x.Id == id);
        if (c is null) return false;
        c.Status = ChangeStatus.Cancelled;
        c.FinishedAtUtc = nowUtc;
        return true;
    }

    /// <summary>Credits served time to every pending change. Negative or absurd values are ignored.</summary>
    public void Credit(long elapsedMs, Func<ChangeRequest, bool>? filter = null)
    {
        if (elapsedMs <= 0) return;
        foreach (var c in Pending)
            if (filter is null || filter(c))
                c.CreditedMs = checked(c.CreditedMs + elapsedMs);
    }

    public List<ChangeRequest> Due() => Pending.Where(c => c.IsDue).ToList();

    /// <summary>
    /// When the user makes the delay longer, every pending request must now wait at least the new delay
    /// (minus time already served). This keeps "longer delay" a true tightening.
    /// </summary>
    public void RaiseRequiredDelays(TimeSpan? newDelay)
    {
        foreach (var c in Pending)
        {
            c.RequiredMs = newDelay is null ? null
                : c.RequiredMs is null ? null
                : Math.Max(c.RequiredMs.Value, (long)newDelay.Value.TotalMilliseconds);
        }
    }

    private void Trim()
    {
        var finished = state.Changes.Where(c => c.Status != ChangeStatus.Pending && c.Status != ChangeStatus.Applying)
            .OrderByDescending(c => c.FinishedAtUtc ?? c.RequestedAtUtc).Skip(Limits.HistoryToKeep).ToList();
        foreach (var f in finished) state.Changes.Remove(f);
    }
}
