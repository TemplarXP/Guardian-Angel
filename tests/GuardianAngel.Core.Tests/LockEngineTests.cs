using GuardianAngel.Core.Engine;
using GuardianAngel.Core.Ipc;
using GuardianAngel.Core.Model;
using GuardianAngel.Core.Policy;
using GuardianAngel.Core.State;
using T = GuardianAngel.Core.Totp.Totp;

namespace GuardianAngel.Core.Tests;

public class LockEngineTests
{
    private static readonly FilterConfig OtherFilter = FilterPresets.Find("cleanbrowsing-family")!.Config;

    [Fact]
    public async Task Lock_refuses_a_filter_that_does_not_work()
    {
        var h = await new Harness().StartAsync();
        h.Tester.Works = false;
        var r = await h.Call<LockResponse>(Ops.Lock, new LockRequest(Harness.Filter, true, TimeSpan.FromHours(2), "", new(), null, false));
        Assert.False(r.Locked);
        Assert.False((await h.Status()).IsLocked);
        Assert.Empty(h.Enforcement.Reconciles);
    }

    [Fact]
    public async Task Lock_applies_enforcement_and_requires_a_delay_or_partner()
    {
        var h = await new Harness().StartAsync();
        var bad = await h.Call<LockResponse>(Ops.Lock, new LockRequest(Harness.Filter, false, TimeSpan.Zero, "", new(), null, false));
        Assert.False(bad.Locked);

        await h.LockAsync(TimeSpan.FromHours(2));
        var s = await h.Status();
        Assert.True(s.IsLocked);
        Assert.True(h.Enforcement.Last!.Active);
        Assert.True(h.Enforcement.Last.Browser.DisableBrowserSecureDns);
        Assert.Equal("cloudflare-families", h.Enforcement.Last.Filter!.PresetId);
    }

    [Fact]
    public async Task Delay_outside_limits_is_refused()
    {
        var h = await new Harness().StartAsync();
        var r = await h.Call<LockResponse>(Ops.Lock, new LockRequest(Harness.Filter, true, TimeSpan.FromDays(31), "", new(), null, false));
        Assert.False(r.Locked);
    }

    [Fact]
    public async Task Loosening_is_queued_and_applies_automatically_after_the_delay()
    {
        var h = await new Harness().StartAsync();
        await h.LockAsync(TimeSpan.FromHours(2));

        var r = await h.RequestAsync("filter.change", OtherFilter);
        Assert.True(r.Queued);
        Assert.False(r.Applied);

        await h.TickFor(TimeSpan.FromMinutes(119));
        Assert.Equal("cloudflare-families", h.Engine.StateSnapshot().Filter!.PresetId);
        var pending = Assert.Single((await h.Status()).Pending);
        Assert.InRange(pending.RemainingMs!.Value, 1, 60_000);

        await h.TickFor(TimeSpan.FromMinutes(2));
        Assert.Equal("cleanbrowsing-family", h.Engine.StateSnapshot().Filter!.PresetId);
        Assert.Empty((await h.Status()).Pending);
        Assert.Contains(h.Log.Entries, e => e.Kind == "applied");
    }

    [Fact]
    public async Task Loosening_requires_the_exact_confirmation_sentence()
    {
        var h = await new Harness().StartAsync();
        await h.LockAsync(TimeSpan.FromHours(2));
        var r = await h.Call<ChangeResultDto>(Ops.RequestChange, new ChangeRequestDto("uninstall", Json.ToElement(new { }), "yes"));
        Assert.False(r.Queued);
        Assert.NotEmpty(r.Errors);

        var preview = await h.Call<ChangePreviewDto>(Ops.PreviewChange, new ChangeRequestDto("uninstall", Json.ToElement(new { })));
        Assert.Equal("I choose to wait 2 hours for this change.", preview.ConfirmationPhrase);
        Assert.Equal("Remember why.", preview.ReflectionMessage);
    }

    [Fact]
    public async Task Changing_the_wall_clock_does_not_speed_up_the_delay()
    {
        var h = await new Harness().StartAsync();
        await h.LockAsync(TimeSpan.FromHours(2));
        await h.RequestAsync("uninstall", null);

        h.Wall.UtcNow += TimeSpan.FromDays(365); // someone sets the clock a year ahead
        h.Mono.Advance(TimeSpan.FromSeconds(1));
        await h.Engine.TickAsync(default);

        Assert.Single((await h.Status()).Pending);
        Assert.Equal(0, h.Uninstaller.Started);
    }

    [Fact]
    public async Task Progress_survives_a_reboot_and_keeps_counting()
    {
        var h = await new Harness().StartAsync();
        await h.LockAsync(TimeSpan.FromHours(2));
        await h.RequestAsync("uninstall", null);
        await h.TickFor(TimeSpan.FromMinutes(90));

        await h.RebootAsync(); // no trusted time: off-time is NOT counted
        var p = Assert.Single((await h.Status()).Pending);
        Assert.InRange(p.RemainingMs!.Value, TimeSpan.FromMinutes(30).TotalMilliseconds - 15_000 - 60_000, TimeSpan.FromMinutes(30).TotalMilliseconds + 60_000);

        await h.TickFor(TimeSpan.FromMinutes(32));
        Assert.Equal(1, h.Uninstaller.Started);
        Assert.Equal(1, h.Enforcement.Removals);
    }

    [Fact]
    public async Task Off_time_counts_only_when_verified_by_trusted_time()
    {
        var h = await new Harness().StartAsync();
        await h.Engine.OnTrustedTimeAsync(h.Wall.UtcNow, default);
        await h.LockAsync(TimeSpan.FromHours(10));
        await h.RequestAsync("uninstall", null);
        await h.TickFor(TimeSpan.FromHours(1));

        await h.RebootAsync(offFor: TimeSpan.FromHours(8));
        // The real time after boot is verified: 8 hours really passed.
        await h.Engine.OnTrustedTimeAsync(h.Wall.UtcNow, default);
        var p = Assert.Single((await h.Status()).Pending);
        Assert.InRange(p.RemainingMs!.Value, TimeSpan.FromMinutes(55).TotalMilliseconds, TimeSpan.FromMinutes(65).TotalMilliseconds);
    }

    [Fact]
    public async Task Setting_the_clock_forward_while_off_does_not_count_without_trusted_time()
    {
        var h = await new Harness().StartAsync();
        await h.Engine.OnTrustedTimeAsync(h.Wall.UtcNow, default);
        await h.LockAsync(TimeSpan.FromHours(10));
        await h.RequestAsync("uninstall", null);
        var realNow = h.Wall.UtcNow;

        await h.RebootAsync(offFor: TimeSpan.FromDays(3)); // the system clock was moved forward, but...
        await h.Engine.OnTrustedTimeAsync(realNow + TimeSpan.FromMinutes(1), default); // ...trusted time says 1 minute
        var p = Assert.Single((await h.Status()).Pending);
        Assert.True(p.RemainingMs > TimeSpan.FromHours(9.9).TotalMilliseconds);
    }

    [Fact]
    public async Task Changes_requested_after_an_unverified_boot_get_no_earlier_off_time()
    {
        var h = await new Harness().StartAsync();
        await h.Engine.OnTrustedTimeAsync(h.Wall.UtcNow, default);
        await h.LockAsync(TimeSpan.FromHours(10));
        await h.RebootAsync(offFor: TimeSpan.FromHours(5)); // boot without trusted time
        await h.RequestAsync("uninstall", null);            // requested AFTER that off period
        await h.Engine.OnTrustedTimeAsync(h.Wall.UtcNow, default);
        var p = Assert.Single((await h.Status()).Pending);
        Assert.True(p.RemainingMs > TimeSpan.FromHours(9.9).TotalMilliseconds);
    }

    [Fact]
    public async Task A_new_request_for_the_same_setting_replaces_the_old_one_and_restarts()
    {
        var h = await new Harness().StartAsync();
        await h.LockAsync(TimeSpan.FromHours(2));
        await h.RequestAsync("filter.change", OtherFilter);
        await h.TickFor(TimeSpan.FromMinutes(100));
        var other2 = FilterPresets.Find("adguard-family")!.Config;
        await h.RequestAsync("filter.change", other2);

        var p = Assert.Single((await h.Status()).Pending);
        Assert.Equal((long)TimeSpan.FromHours(2).TotalMilliseconds, p.RemainingMs);
        Assert.Contains(h.Engine.StateSnapshot().Changes, c => c.Status == ChangeStatus.Superseded);
    }

    [Fact]
    public async Task Cancel_is_instant()
    {
        var h = await new Harness().StartAsync();
        await h.LockAsync(TimeSpan.FromHours(2));
        var r = await h.RequestAsync("uninstall", null);
        Assert.True((await h.Call(Ops.CancelChange, new IdRequest(r.Id!.Value))).Ok);
        await h.TickFor(TimeSpan.FromHours(3));
        Assert.Equal(0, h.Uninstaller.Started);
    }

    [Fact]
    public async Task Longer_delay_is_instant_and_pending_changes_move_to_it()
    {
        var h = await new Harness().StartAsync();
        await h.LockAsync(TimeSpan.FromHours(2));
        await h.RequestAsync("uninstall", null);
        await h.TickFor(TimeSpan.FromHours(1));

        var r = await h.RequestAsync("delay.change", new DelayChangeParams(true, TimeSpan.FromHours(12)));
        Assert.True(r.Applied);
        var s = await h.Status();
        Assert.Equal(TimeSpan.FromHours(12), s.Delay);
        var p = Assert.Single(s.Pending);
        Assert.Equal((long)TimeSpan.FromHours(11).TotalMilliseconds, p.RemainingMs);
    }

    [Fact]
    public async Task Shorter_delay_waits_out_the_current_delay()
    {
        var h = await new Harness().StartAsync();
        await h.LockAsync(TimeSpan.FromHours(12));
        var r = await h.RequestAsync("delay.change", new DelayChangeParams(true, TimeSpan.FromHours(1)));
        Assert.True(r.Queued);
        await h.TickFor(TimeSpan.FromHours(11), TimeSpan.FromMinutes(10));
        Assert.Equal(TimeSpan.FromHours(12), (await h.Status()).Delay);
        await h.TickFor(TimeSpan.FromHours(1) + TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(10));
        Assert.Equal(TimeSpan.FromHours(1), (await h.Status()).Delay);
    }

    [Fact]
    public async Task Filter_change_that_fails_its_test_keeps_the_current_filter()
    {
        var h = await new Harness().StartAsync();
        await h.LockAsync(TimeSpan.FromHours(1));
        h.Tester.WorksFor = f => f.PresetId != OtherFilter.PresetId;
        await h.RequestAsync("filter.change", OtherFilter);
        await h.TickFor(TimeSpan.FromMinutes(61));

        Assert.Equal("cloudflare-families", h.Engine.StateSnapshot().Filter!.PresetId);
        Assert.Contains(h.Engine.StateSnapshot().Changes, c => c.Status == ChangeStatus.Failed);
        Assert.Empty(h.Enforcement.Last!.ExtraAllowedServers);
        // While testing, both old and new servers were allowed.
        Assert.Contains(h.Enforcement.Reconciles, d => d.ExtraAllowedServers.Count > 0);
    }

    [Fact]
    public async Task Partner_code_expedites_and_wrong_codes_lock_out()
    {
        var h = await new Harness().StartAsync();
        var begin = await h.Call<PartnerBeginResponse>(Ops.PartnerBegin);
        var secret = Totp.Base32.Decode(begin.SecretForManualEntry);
        Assert.True((await h.Call(Ops.PartnerConfirm, new CodeRequest(T.Code(secret, T.StepAt(h.Wall.UtcNow))))).Ok);
        await h.LockAsync(TimeSpan.FromHours(24));

        var r = await h.RequestAsync("uninstall", null);
        for (int i = 0; i < 4; i++)
            Assert.Equal("Wrong", (await h.Call<ExpediteResult>(Ops.Expedite, new ExpediteRequest(r.Id!.Value, "000000"))).Result);
        Assert.Equal("LockedOut", (await h.Call<ExpediteResult>(Ops.Expedite, new ExpediteRequest(r.Id!.Value, "000000"))).Result);

        await h.TickFor(TimeSpan.FromMinutes(61));
        h.Wall.UtcNow += TimeSpan.FromMinutes(1); // next TOTP step (the setup code's step was used)
        var ok = await h.Call<ExpediteResult>(Ops.Expedite, new ExpediteRequest(r.Id!.Value, T.Code(secret, T.StepAt(h.Wall.UtcNow))));
        Assert.Equal("Accepted", ok.Result);
        Assert.Equal(1, h.Uninstaller.Started);
    }

    [Fact]
    public async Task Lockout_survives_a_reboot()
    {
        var h = await new Harness().StartAsync();
        var begin = await h.Call<PartnerBeginResponse>(Ops.PartnerBegin);
        var secret = Totp.Base32.Decode(begin.SecretForManualEntry);
        await h.Call(Ops.PartnerConfirm, new CodeRequest(T.Code(secret, T.StepAt(h.Wall.UtcNow))));
        await h.LockAsync(TimeSpan.FromHours(24));
        var r = await h.RequestAsync("uninstall", null);
        for (int i = 0; i < 5; i++) await h.Call(Ops.Expedite, new ExpediteRequest(r.Id!.Value, "000000"));

        await h.RebootAsync(offFor: TimeSpan.FromHours(3));
        h.Wall.UtcNow += TimeSpan.FromMinutes(1);
        var res = await h.Call<ExpediteResult>(Ops.Expedite, new ExpediteRequest(r.Id!.Value, T.Code(secret, T.StepAt(h.Wall.UtcNow))));
        Assert.Equal("LockedOut", res.Result);
    }

    [Fact]
    public async Task Partner_only_mode_never_applies_without_a_code()
    {
        var h = await new Harness().StartAsync();
        var begin = await h.Call<PartnerBeginResponse>(Ops.PartnerBegin);
        var secret = Totp.Base32.Decode(begin.SecretForManualEntry);
        await h.Call(Ops.PartnerConfirm, new CodeRequest(T.Code(secret, T.StepAt(h.Wall.UtcNow))));
        await h.LockAsync(TimeSpan.Zero, delayEnabled: false);
        var r = await h.RequestAsync("uninstall", null);
        Assert.True(r.Queued);
        await h.TickFor(TimeSpan.FromDays(60), TimeSpan.FromHours(6));
        Assert.Equal(0, h.Uninstaller.Started);
        Assert.Null((await h.Status()).Pending[0].RemainingMs);
    }

    [Fact]
    public async Task Partner_removal_is_refused_when_it_would_leave_no_way_to_unlock()
    {
        var h = await new Harness().StartAsync();
        var begin = await h.Call<PartnerBeginResponse>(Ops.PartnerBegin);
        var secret = Totp.Base32.Decode(begin.SecretForManualEntry);
        await h.Call(Ops.PartnerConfirm, new CodeRequest(T.Code(secret, T.StepAt(h.Wall.UtcNow))));
        await h.LockAsync(TimeSpan.Zero, delayEnabled: false);
        var r = await h.RequestAsync("partner.remove", null);
        Assert.False(r.Queued);
        Assert.NotEmpty(r.Errors);
    }

    [Fact]
    public async Task Setup_operations_are_refused_after_lock()
    {
        var h = await new Harness().StartAsync();
        await h.LockAsync(TimeSpan.FromHours(1));
        Assert.False((await h.Call(Ops.PartnerBegin)).Ok);
        Assert.False((await h.Call(Ops.PartnerClear)).Ok);
        Assert.False((await h.Call(Ops.TestFilter, new TestFilterRequest(OtherFilter, null))).Ok);
        Assert.False((await h.Call(Ops.Lock, new LockRequest(OtherFilter, true, TimeSpan.FromHours(1), "", new(), null, false))).Ok);
    }

    [Fact]
    public async Task Uninstall_is_refused_until_due_then_removes_everything()
    {
        var h = await new Harness().StartAsync();
        Assert.True((await h.Call<UninstallStatusDto>(Ops.UninstallStatus)).Allowed); // before Lock: free
        await h.LockAsync(TimeSpan.FromHours(1));
        Assert.False((await h.Call<UninstallStatusDto>(Ops.UninstallStatus)).Allowed);
        await h.RequestAsync("uninstall", null);
        await h.TickFor(TimeSpan.FromMinutes(61));
        Assert.True((await h.Call<UninstallStatusDto>(Ops.UninstallStatus)).Allowed);
        Assert.Equal(1, h.Enforcement.Removals);
        Assert.Equal(1, h.Uninstaller.Started);
    }

    [Fact]
    public async Task Unreadable_state_enters_safe_locked_mode_and_changes_nothing()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ga-test-" + Guid.NewGuid());
        var store = new FileStateStore(dir, new NullProtector());
        var h = await new Harness(store).StartAsync();
        await h.LockAsync(TimeSpan.FromHours(1));
        var before = h.Enforcement.Reconciles.Count;

        foreach (var f in Directory.GetFiles(dir)) File.WriteAllBytes(f, [1, 2, 3]);
        await h.RebootAsync();

        Assert.True(h.Engine.SafeLocked);
        Assert.Equal(before, h.Enforcement.Reconciles.Count); // no reconcile, no removal
        Assert.Equal(0, h.Enforcement.Removals);
        Assert.False((await h.Call<UninstallStatusDto>(Ops.UninstallStatus)).Allowed);
        Assert.False((await h.Call(Ops.RequestChange, new ChangeRequestDto("uninstall", Json.ToElement(new { }), "x"))).Ok);
        Directory.Delete(dir, true);
    }

    [Fact]
    public async Task Block_all_when_unreachable_only_if_chosen()
    {
        var h = await new Harness().StartAsync();
        await h.LockAsync(TimeSpan.FromHours(1));
        h.Engine.SetFilterReachable(false);
        await h.Engine.ReconcileAsync(default);
        Assert.True(h.Enforcement.Last!.BlockAllExceptFilter);
        h.Engine.SetFilterReachable(true);
        await h.Engine.ReconcileAsync(default);
        Assert.False(h.Enforcement.Last!.BlockAllExceptFilter);
    }

    [Fact]
    public async Task Change_mid_apply_at_power_loss_is_retried_after_boot()
    {
        var store = new InMemoryStateStore();
        var h = await new Harness(store).StartAsync();
        await h.LockAsync(TimeSpan.FromHours(1));
        await h.RequestAsync("delay.change", new DelayChangeParams(true, TimeSpan.FromHours(1) + TimeSpan.FromMinutes(1))); // tighten
        await h.RequestAsync("filter.change", OtherFilter);
        var s = h.Engine.StateSnapshot();
        s.Changes.First(c => c.Status == ChangeStatus.Pending).Status = ChangeStatus.Applying;
        store.Save(s);
        await h.RebootAsync();
        Assert.Single((await h.Status()).Pending);
    }
}
