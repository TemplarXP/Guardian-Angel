using System.Text.Json;
using GuardianAngel.Core.Dns;
using GuardianAngel.Core.Ipc;
using GuardianAngel.Core.Log;
using GuardianAngel.Core.Model;
using GuardianAngel.Core.Policy;
using GuardianAngel.Core.State;
using GuardianAngel.Core.Time;
using GuardianAngel.Core.Totp;

namespace GuardianAngel.Core.Engine;

/// <summary>
/// The brain of the service. Every rule lives here: tighten vs loosen, delays, partner codes,
/// lockouts, the queue and persistence. The UI only asks; this class decides.
/// It has no Windows dependencies, so it is unit-tested with fake clocks and fake enforcers.
/// </summary>
public sealed class LockEngine
{
    public static readonly TimeSpan PersistInterval = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan MaxOfflineCredit = TimeSpan.FromDays(400);

    private readonly IStateStore _store;
    private readonly IEnforcement _enforcement;
    private readonly IConnectionTester _tester;
    private readonly ChangeTypeRegistry _types;
    private readonly IMonotonicClock _mono;
    private readonly IWallClock _wall;
    private readonly IAccountabilityLog _log;
    private readonly IUninstaller _uninstaller;
    private readonly SemaphoreSlim _gate = new(1, 1);

    private LockState _state = new();
    private long _lastTickMs;
    private long _lastPersistMs;
    private bool _started;
    private (DateTimeOffset Trusted, long Mono)? _anchor;
    private byte[]? _pendingPartnerSecret;
    private bool _filterReachable = true;
    private IReadOnlyList<EnforcementItemDto> _lastReport = [];

    public bool SafeLocked { get; private set; }
    public string? SafeLockedReason { get; private set; }

    public LockEngine(IStateStore store, IEnforcement enforcement, IConnectionTester tester, ChangeTypeRegistry types,
        IMonotonicClock mono, IWallClock wall, IAccountabilityLog log, IUninstaller uninstaller)
    {
        _store = store; _enforcement = enforcement; _tester = tester; _types = types;
        _mono = mono; _wall = wall; _log = log; _uninstaller = uninstaller;
    }

    /// <summary>Snapshot for tests and diagnostics.</summary>
    public LockState StateSnapshot() => _state.Clone();

    // ------------------------------------------------------------------ lifecycle

    public async Task StartAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            try
            {
                _state = _store.Load();
            }
            catch (StateCorruptException ex)
            {
                // Fail closed: we can't read our settings, so we change NOTHING on the machine.
                // The persistent firewall filters stay exactly as they are, and every loosening is refused.
                SafeLocked = true;
                SafeLockedReason = ex.Message + " Protection stays as it was, and no change can be made until this is fixed.";
                _state = new LockState { IsLocked = true, UninstallAuthorized = false };
                _log.Append("tamper", "Saved state could not be read; entered Safe-Locked mode.");
                _started = true;
                _lastTickMs = _lastPersistMs = _mono.NowMs;
                return;
            }

            _state.Clock.BootCounter++;
            _lastTickMs = _lastPersistMs = _mono.NowMs;
            _started = true;

            // A change that was mid-apply when the PC lost power is simply applied again (applying is idempotent).
            foreach (var c in _state.Changes.Where(c => c.Status == ChangeStatus.Applying))
                c.Status = ChangeStatus.Pending;

            PersistLocked();
            _log.Append("service-start", $"Service started (boot {_state.Clock.BootCounter}).");
        }
        finally { _gate.Release(); }
        await ReconcileAsync(ct);
    }

    /// <summary>Called about once a second by the service host.</summary>
    public async Task TickAsync(CancellationToken ct)
    {
        List<ChangeRequest> due;
        await _gate.WaitAsync(ct);
        try
        {
            if (!_started || SafeLocked) return;
            var now = _mono.NowMs;
            var elapsed = Math.Max(0, now - _lastTickMs);
            _lastTickMs = now;

            new ChangeQueue(_state).Credit(elapsed);
            _state.Clock.CreditedSinceEstimateMs += elapsed;
            PartnerVerifier.CountDownLockout(_state.Partner, elapsed);

            if (now - _lastPersistMs >= PersistInterval.TotalMilliseconds) PersistLocked();
            due = _state.IsLocked ? new ChangeQueue(_state).Due() : [];
        }
        finally { _gate.Release(); }

        foreach (var c in due) await ApplyQueuedAsync(c.Id, expeditedBy: null, ct);
    }

    /// <summary>Called on network changes and about every 10 seconds.</summary>
    public async Task ReconcileAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try { await ReconcileLockedAsync(ct); }
        finally { _gate.Release(); }
    }

    public void SetFilterReachable(bool reachable)
    {
        if (_filterReachable == reachable) return;
        _filterReachable = reachable;
        _log.Append("filter-reachability", reachable ? "Filter reachable again." : "No filter server can be reached.");
    }

    /// <summary>
    /// Called by the host after it obtained a time it cannot have been fooled about (TLS-authenticated).
    /// If the PC was switched off, the off-time is credited to changes requested before it was switched off.
    /// </summary>
    public async Task OnTrustedTimeAsync(DateTimeOffset trustedUtc, CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            if (!_started || SafeLocked) return;
            var clock = _state.Clock;
            if (_anchor is null && clock.LastTrustedEstimateUtc is { } last)
            {
                var offline = trustedUtc - last - TimeSpan.FromMilliseconds(clock.CreditedSinceEstimateMs);
                if (offline > TimeSpan.FromSeconds(1))
                {
                    if (offline > MaxOfflineCredit) offline = MaxOfflineCredit;
                    var estimateBoot = clock.EstimateBoot;
                    new ChangeQueue(_state).Credit((long)offline.TotalMilliseconds, c => c.RequestedBoot <= estimateBoot);
                    _log.Append("offline-credit", $"Counted {DelayMath.Describe(TimeSpan.FromSeconds(Math.Floor(offline.TotalSeconds)))} while the PC was off (verified time).");
                }
            }
            _anchor = (trustedUtc, _mono.NowMs);
            UpdateEstimate();
            PersistLocked();
        }
        finally { _gate.Release(); }
    }

    // ------------------------------------------------------------------ IPC

    public async Task<IpcResponse> HandleAsync(IpcRequest req, CancellationToken ct)
    {
        if (SafeLocked && req.Op != Ops.GetStatus && req.Op != Ops.UninstallStatus)
            return IpcResponse.Fail(SafeLockedReason ?? "Guardian Angel is in Safe-Locked mode.");

        return req.Op switch
        {
            Ops.GetStatus => await Locked(() => IpcResponse.Success(BuildStatus()), ct),
            Ops.TestFilter => await TestFilterAsync(Body<TestFilterRequest>(req), ct),
            Ops.PartnerBegin => await Locked(PartnerBegin, ct),
            Ops.PartnerConfirm => await Locked(() => PartnerConfirm(Body<CodeRequest>(req)), ct),
            Ops.PartnerClear => await Locked(PartnerClear, ct),
            Ops.Lock => await LockAsync(Body<LockRequest>(req), ct),
            Ops.PreviewChange => await Locked(() => Preview(Body<ChangeRequestDto>(req)), ct),
            Ops.RequestChange => await RequestChangeAsync(Body<ChangeRequestDto>(req), ct),
            Ops.CancelChange => await Locked(() => Cancel(Body<IdRequest>(req)), ct),
            Ops.Expedite => await ExpediteAsync(Body<ExpediteRequest>(req), ct),
            Ops.UninstallStatus => await Locked(UninstallStatus, ct),
#if GA_DEBUG_BYPASS
            DebugOps.UnlockAll => await DebugUnlockAllAsync(ct),
#endif
            _ => IpcResponse.Fail("Unknown request."),
        };
    }

    private static T Body<T>(IpcRequest r) => Json.FromElement<T>(r.Body) ?? throw new InvalidDataException("Missing request body.");

    private async Task<IpcResponse> Locked(Func<IpcResponse> f, CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try { return f(); }
        finally { _gate.Release(); }
    }

    private StatusDto BuildStatus()
    {
        static PendingChangeDto Dto(ChangeRequest c) => new(c.Id, c.Kind, c.Description, c.RequestedAtUtc, c.RemainingMs, c.RequiredMs, c.Status, c.FailureReason);
        return new StatusDto(
            _state.IsLocked, _state.LockedAtUtc, _state.Filter,
            _state.Unlock.DelayEnabled, _state.Unlock.Delay,
            _state.Partner is not null, _state.Partner?.LockoutRemainingMs ?? 0,
            _state.ReflectionMessage, _state.Browser,
            _state.Changes.Where(c => c.Status is ChangeStatus.Pending or ChangeStatus.Applying).Select(Dto).ToList(),
            _state.Changes.Where(c => c.Status is not (ChangeStatus.Pending or ChangeStatus.Applying))
                .OrderByDescending(c => c.FinishedAtUtc).Take(10).Select(Dto).ToList(),
            _lastReport, SafeLocked, SafeLockedReason,
#if GA_DEBUG_BYPASS
            IsDebugBuild: true,
#else
            IsDebugBuild: false,
#endif
            Limits.MinDelay, Limits.MaxDelay);
    }

    // ---------------- setup (only before Lock)

    private async Task<IpcResponse> TestFilterAsync(TestFilterRequest r, CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            if (_state.IsLocked) return IpcResponse.Fail("Already locked. Request a filter change instead.");
        }
        finally { _gate.Release(); }
        var errors = r.Filter.Validate();
        if (errors.Count > 0) return IpcResponse.Fail(string.Join(" ", errors));
        return IpcResponse.Success(await _tester.TestAsync(r.Filter, r.BlockedDomain, ct));
    }

    private IpcResponse PartnerBegin()
    {
        if (_state.IsLocked) return IpcResponse.Fail("Adding a partner after locking arrives in a later version.");
        _pendingPartnerSecret = Totp.Totp.NewSecret();
        return IpcResponse.Success(new PartnerBeginResponse(Totp.Totp.OtpAuthUri(_pendingPartnerSecret), Base32.Encode(_pendingPartnerSecret)));
    }

    private IpcResponse PartnerConfirm(CodeRequest r)
    {
        if (_state.IsLocked) return IpcResponse.Fail("Already locked.");
        if (_pendingPartnerSecret is null) return IpcResponse.Fail("Start partner setup first.");
        var candidate = new PartnerState { Secret = _pendingPartnerSecret, AddedUtc = _wall.UtcNow };
        var result = PartnerVerifier.Verify(candidate, r.Code, _wall.UtcNow);
        if (result != CodeResult.Accepted)
            return IpcResponse.Fail("That code didn't match. Check the partner's phone clock is right, and try the newest code.");
        candidate.FailedAttempts = 0;
        candidate.LockoutRemainingMs = 0;
        _state.Partner = candidate;
        _pendingPartnerSecret = null; // the secret can never be shown again
        PersistLocked();
        _log.Append("partner-added", "Accountability partner added.");
        return IpcResponse.Success();
    }

    private IpcResponse PartnerClear()
    {
        if (_state.IsLocked) return IpcResponse.Fail("Removing a partner after locking is a queued change.");
        _state.Partner = null;
        _pendingPartnerSecret = null;
        PersistLocked();
        return IpcResponse.Success();
    }

    private async Task<IpcResponse> LockAsync(LockRequest r, CancellationToken ct)
    {
        var errors = r.Filter.Validate();
        if (r.DelayEnabled && (r.Delay < Limits.MinDelay || r.Delay > Limits.MaxDelay))
            errors.Add($"The delay must be between {DelayMath.Describe(Limits.MinDelay)} and {DelayMath.Describe(Limits.MaxDelay)}.");
        if ((r.ReflectionMessage ?? "").Length > Limits.ReflectionMaxLength) errors.Add("The reflection message is too long.");

        await _gate.WaitAsync(ct);
        try
        {
            if (_state.IsLocked) return IpcResponse.Fail("Already locked.");
            if (!r.DelayEnabled && _state.Partner is null) errors.Add("Choose a time delay, an accountability partner, or both.");
        }
        finally { _gate.Release(); }

        var test = await _tester.TestAsync(r.Filter, r.BlockedTestDomain, ct);
        if (!test.Passed(r.UserConfirmedBlockPage)) errors.Add(test.Summary);
        if (errors.Count > 0) return IpcResponse.Success(new LockResponse(false, test, errors));

        await _gate.WaitAsync(ct);
        try
        {
            if (_state.IsLocked) return IpcResponse.Fail("Already locked.");
            _state.Filter = r.Filter;
            _state.Unlock = new UnlockPolicy { DelayEnabled = r.DelayEnabled, Delay = r.DelayEnabled ? r.Delay : TimeSpan.FromHours(24) };
            _state.ReflectionMessage = r.ReflectionMessage ?? "";
            _state.Browser = r.Browser with { DisableBrowserSecureDns = true };
            _state.IsLocked = true;
            _state.LockedAtUtc = _wall.UtcNow;
            _state.UninstallAuthorized = false;
            PersistLocked();
            _log.Append("lock", $"Locked to \"{r.Filter.Name}\" with delay {DelayMath.Describe(_state.Unlock.EffectiveDelay)}{(_state.Partner is null ? "" : " and a partner")}.");
            await ReconcileLockedAsync(ct);
        }
        finally { _gate.Release(); }
        return IpcResponse.Success(new LockResponse(true, test, []));
    }

    // ---------------- changes

    private IpcResponse Preview(ChangeRequestDto r)
    {
        if (!_state.IsLocked) return IpcResponse.Fail("Not locked yet.");
        var type = _types.Find(r.Kind);
        if (type is null) return IpcResponse.Fail("Unknown change type.");
        var errors = type.Validate(_state, r.Parameters);
        var direction = errors.Count == 0 ? type.Classify(_state, r.Parameters) : Direction.Loosen;
        var delay = _state.Unlock.EffectiveDelay;
        return IpcResponse.Success(new ChangePreviewDto(direction, errors.Count == 0 ? type.Describe(_state, r.Parameters) : "",
            errors, delay, Confirmation.PhraseFor(delay), _state.ReflectionMessage));
    }

    private async Task<IpcResponse> RequestChangeAsync(ChangeRequestDto r, CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            if (!_state.IsLocked) return IpcResponse.Fail("Not locked yet.");
            var type = _types.Find(r.Kind);
            if (type is null) return IpcResponse.Fail("Unknown change type.");
            var errors = type.Validate(_state, r.Parameters);
            if (errors.Count > 0) return IpcResponse.Success(new ChangeResultDto(false, false, null, errors));

            var queue = new ChangeQueue(_state);
            if (type.Classify(_state, r.Parameters) == Direction.Tighten)
            {
                // Tightening: applied immediately. It also replaces any pending change to the same setting.
                var description = type.Describe(_state, r.Parameters);
                foreach (var old in queue.Pending.Where(c => c.SettingKey == type.SettingKey(r.Parameters)).ToList())
                { old.Status = ChangeStatus.Superseded; old.FinishedAtUtc = _wall.UtcNow; }
                type.Apply(_state, r.Parameters);
                if (type.Kind == "delay.change") queue.RaiseRequiredDelays(_state.Unlock.EffectiveDelay);
                PersistLocked();
                _log.Append("tighten", description + " (applied immediately).");
                await ReconcileLockedAsync(ct);
                return IpcResponse.Success(new ChangeResultDto(true, false, null, []));
            }

            var delay = _state.Unlock.EffectiveDelay;
            if (!Confirmation.Matches(Confirmation.PhraseFor(delay), r.Confirmation))
                return IpcResponse.Success(new ChangeResultDto(false, false, null, ["Type the confirmation sentence exactly as shown."]));

            var req = queue.Enqueue(type, r.Parameters, delay, _wall.UtcNow, _state.Clock.BootCounter);
            PersistLocked();
            _log.Append("request", $"{req.Description} requested; waits {DelayMath.Describe(delay)}.");
            return IpcResponse.Success(new ChangeResultDto(false, true, req.Id, []));
        }
        finally { _gate.Release(); }
    }

    private IpcResponse Cancel(IdRequest r)
    {
        var change = _state.Changes.FirstOrDefault(c => c.Id == r.Id);
        if (!new ChangeQueue(_state).Cancel(r.Id, _wall.UtcNow)) return IpcResponse.Fail("That change isn't pending.");
        PersistLocked();
        _log.Append("cancel", $"{change?.Description} cancelled.");
        return IpcResponse.Success();
    }

    private async Task<IpcResponse> ExpediteAsync(ExpediteRequest r, CancellationToken ct)
    {
        CodeResult result;
        long lockout;
        await _gate.WaitAsync(ct);
        try
        {
            var change = new ChangeQueue(_state).Pending.FirstOrDefault(c => c.Id == r.Id);
            if (change is null) return IpcResponse.Fail("That change isn't pending.");
            result = PartnerVerifier.Verify(_state.Partner, r.Code, _wall.UtcNow);
            PersistLocked(); // failed-attempt counters and replay protection survive reboots
            switch (result)
            {
                case CodeResult.Accepted: _log.Append("expedite", $"Partner code accepted for: {change.Description}."); break;
                case CodeResult.LockedOut: _log.Append("lockout", "Too many wrong partner codes; locked out for 1 hour."); break;
                case CodeResult.NoPartner: break;
                default: _log.Append("wrong-code", $"Wrong partner code for: {change.Description}."); break;
            }
            lockout = _state.Partner?.LockoutRemainingMs ?? 0;
        }
        finally { _gate.Release(); }

        if (result == CodeResult.Accepted) await ApplyQueuedAsync(r.Id, "partner", ct);
        return IpcResponse.Success(new ExpediteResult(result.ToString(), lockout));
    }

    private IpcResponse UninstallStatus()
    {
        var allowed = !_state.IsLocked || _state.UninstallAuthorized;
        return IpcResponse.Success(new UninstallStatusDto(allowed, allowed
            ? "Guardian Angel can be uninstalled."
            : "Uninstalling is a queued change. Open Guardian Angel and choose Request change → Uninstall. When the delay ends, Guardian Angel removes itself."));
    }

    private async Task ApplyQueuedAsync(Guid id, string? expeditedBy, CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            var c = _state.Changes.FirstOrDefault(x => x.Id == id && x.Status == ChangeStatus.Pending);
            if (c is null) return;
            var type = _types.Find(c.Kind);
            if (type is null) { Fail(c, "This version doesn't know this change type."); return; }

            var errors = type.Validate(_state, c.Parameters);
            if (errors.Count > 0) { Fail(c, string.Join(" ", errors)); return; }

            c.Status = ChangeStatus.Applying;
            c.ExpeditedBy = expeditedBy;
            PersistLocked();

            if (type.NeedsConnectionTest && c.Kind == "filter.change")
            {
                // Test the new filter before switching. Both old and new servers are allowed while testing.
                var newFilter = Json.FromElement<FilterConfig>(c.Parameters)!;
                _state.TransitionalServers = newFilter.Servers.ToList();
                await ReconcileLockedAsync(ct);
                ConnectionTestResult test;
                try { test = await _tester.TestAsync(newFilter, null, ct); }
                finally { _state.TransitionalServers = []; }
                if (!test.NormalSitesResolve)
                {
                    Fail(c, "The new filter didn't answer, so your current filter stays. " + test.Summary);
                    await ReconcileLockedAsync(ct);
                    return;
                }
            }

            type.Apply(_state, c.Parameters);
            c.Status = ChangeStatus.Applied;
            c.FinishedAtUtc = _wall.UtcNow;
            PersistLocked();
            _log.Append("applied", $"{c.Description} applied{(expeditedBy is null ? " after the delay" : " with a partner code")}.");

            if (c.Kind == "uninstall")
            {
                await _enforcement.RemoveAllAsync(ct);
                _lastReport = [];
                _uninstaller.Start();
            }
            else
            {
                await ReconcileLockedAsync(ct);
            }
        }
        finally { _gate.Release(); }
    }

    private void Fail(ChangeRequest c, string reason)
    {
        c.Status = ChangeStatus.Failed;
        c.FailureReason = reason;
        c.FinishedAtUtc = _wall.UtcNow;
        PersistLocked();
        _log.Append("failed", $"{c.Description} could not be applied: {reason}");
    }

#if GA_DEBUG_BYPASS
    // DEBUG BUILDS ONLY. This method does not exist in Release builds (see Directory.Build.props).
    private async Task<IpcResponse> DebugUnlockAllAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            _state.IsLocked = false;
            _state.UninstallAuthorized = true;
            foreach (var c in new ChangeQueue(_state).Pending.ToList()) c.Status = ChangeStatus.Cancelled;
            PersistLocked();
            _log.Append("debug-bypass", DebugOps.Marker + ": everything unlocked by the debug bypass.");
            await _enforcement.RemoveAllAsync(ct);
            _lastReport = [];
            return IpcResponse.Success();
        }
        finally { _gate.Release(); }
    }
#endif

    // ------------------------------------------------------------------ helpers (call with _gate held)

    private async Task ReconcileLockedAsync(CancellationToken ct)
    {
        if (!_started || SafeLocked) return;
        var desired = new DesiredEnforcement(
            Active: _state.IsLocked && _state.Filter is not null,
            Filter: _state.Filter,
            ExtraAllowedServers: _state.TransitionalServers,
            Browser: _state.Browser,
            BlockAllExceptFilter: !_filterReachable && _state.Filter?.WhenUnreachable == UnreachableBehavior.BlockInternet);
        if (!desired.Active) { _lastReport = []; return; }
        _lastReport = await _enforcement.ReconcileAsync(desired, ct);
    }

    private void UpdateEstimate()
    {
        if (_anchor is not { } a) return;
        _state.Clock.LastTrustedEstimateUtc = a.Trusted + TimeSpan.FromMilliseconds(_mono.NowMs - a.Mono);
        _state.Clock.CreditedSinceEstimateMs = 0;
        _state.Clock.EstimateBoot = _state.Clock.BootCounter;
    }

    private void PersistLocked()
    {
        UpdateEstimate();
        _store.Save(_state);
        _lastPersistMs = _mono.NowMs;
    }
}

#if GA_DEBUG_BYPASS
public static class DebugOps
{
    public const string UnlockAll = "debug.unlockAll";
    /// <summary>CI fails if this string appears in any Release binary.</summary>
    public const string Marker = "GA-DEBUG-BYPASS-PRESENT";
}
#endif
