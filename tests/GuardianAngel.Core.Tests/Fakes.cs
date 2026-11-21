using GuardianAngel.Core.Dns;
using GuardianAngel.Core.Engine;
using GuardianAngel.Core.Ipc;
using GuardianAngel.Core.Log;
using GuardianAngel.Core.Model;
using GuardianAngel.Core.Policy;
using GuardianAngel.Core.State;
using GuardianAngel.Core.Time;

namespace GuardianAngel.Core.Tests;

public sealed class FakeMono : IMonotonicClock
{
    public long NowMs { get; set; } = 1_000_000;
    public void Advance(TimeSpan t) => NowMs += (long)t.TotalMilliseconds;
}

public sealed class FakeWall : IWallClock
{
    public DateTimeOffset UtcNow { get; set; } = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
}

public sealed class FakeTester : IConnectionTester
{
    public bool Works { get; set; } = true;
    public Func<FilterConfig, bool>? WorksFor { get; set; }
    public int Calls { get; private set; }
    public Task<ConnectionTestResult> TestAsync(FilterConfig filter, string? blockedDomain, CancellationToken ct)
    {
        Calls++;
        var ok = WorksFor?.Invoke(filter) ?? Works;
        return Task.FromResult(new ConnectionTestResult(ok, [new ServerResult(filter.Servers[0], ok, ok ? "Works" : "No answer")],
            blockedDomain is null ? BlockCheck.NotTested : BlockCheck.Blocked, [], ok ? "Your filter works." : "Your filter didn't answer."));
    }
}

public sealed class FakeEnforcement : IEnforcement
{
    public List<DesiredEnforcement> Reconciles { get; } = new();
    public int Removals { get; private set; }
    public DesiredEnforcement? Last => Reconciles.LastOrDefault();
    public Task<IReadOnlyList<EnforcementItemDto>> ReconcileAsync(DesiredEnforcement desired, CancellationToken ct)
    {
        Reconciles.Add(desired);
        return Task.FromResult<IReadOnlyList<EnforcementItemDto>>([new("DNS lock", true, "ok")]);
    }
    public Task RemoveAllAsync(CancellationToken ct) { Removals++; return Task.CompletedTask; }
}

/// <summary>Builds an engine with fakes, sharing a store so "reboots" can be simulated.</summary>
public sealed class Harness
{
    public FakeMono Mono { get; } = new();
    public FakeWall Wall { get; } = new();
    public FakeTester Tester { get; } = new();
    public FakeEnforcement Enforcement { get; } = new();
    public NullLog Log { get; } = new();
    public NoopUninstaller Uninstaller { get; } = new();
    public IStateStore Store { get; }
    public LockEngine Engine { get; private set; } = null!;

    public static readonly FilterConfig Filter = FilterPresets.Find("cloudflare-families")!.Config;

    public Harness(IStateStore? store = null) { Store = store ?? new InMemoryStateStore(); }

    public async Task<Harness> StartAsync()
    {
        Engine = new LockEngine(Store, Enforcement, Tester, ChangeTypeRegistry.CreateDefault(), Mono, Wall, Log, Uninstaller);
        await Engine.StartAsync(default);
        return this;
    }

    /// <summary>Simulates a reboot: the monotonic clock restarts near zero, a new engine loads the saved state.</summary>
    public async Task RebootAsync(TimeSpan? offFor = null)
    {
        Mono.NowMs = 5_000;
        if (offFor is not null) Wall.UtcNow += offFor.Value;
        await StartAsync();
    }

    public async Task<IpcResponse> Call(string op, object? body = null) =>
        await Engine.HandleAsync(new IpcRequest(Framing.ProtocolVersion, op, body is null ? null : Json.ToElement(body)), default);

    public async Task<T> Call<T>(string op, object? body = null)
    {
        var r = await Call(op, body);
        Assert.True(r.Ok, r.Error);
        return Json.FromElement<T>(r.Body)!;
    }

    public async Task LockAsync(TimeSpan delay, bool delayEnabled = true)
    {
        var r = await Call<LockResponse>(Ops.Lock, new LockRequest(Filter, delayEnabled, delay, "Remember why.", new BrowserOptions(), null, false));
        Assert.True(r.Locked, string.Join(" ", r.Errors));
    }

    public async Task<ChangeResultDto> RequestAsync(string kind, object? parameters)
    {
        var p = Json.ToElement(parameters ?? new { });
        var preview = await Call<ChangePreviewDto>(Ops.PreviewChange, new ChangeRequestDto(kind, p));
        return await Call<ChangeResultDto>(Ops.RequestChange, new ChangeRequestDto(kind, p, preview.ConfirmationPhrase));
    }

    public async Task TickFor(TimeSpan total, TimeSpan? step = null)
    {
        var s = step ?? TimeSpan.FromMinutes(1);
        for (var t = TimeSpan.Zero; t < total; t += s)
        {
            Mono.Advance(s);
            Wall.UtcNow += s;
            await Engine.TickAsync(default);
        }
    }

    public Task<StatusDto> Status() => Call<StatusDto>(Ops.GetStatus);
}
