using System.Net.NetworkInformation;
using System.Security.Cryptography;
using GuardianAngel.Core.Dns;
using GuardianAngel.Core.Engine;
using GuardianAngel.Core.Ipc;
using GuardianAngel.Core.Log;
using GuardianAngel.Core.Policy;
using GuardianAngel.Core.State;
using GuardianAngel.Core.Time;
using GuardianAngel.Platform.Windows.Enforcement;
using GuardianAngel.Platform.Windows.Security;
using GuardianAngel.Platform.Windows.Services;
using GuardianAngel.Service;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(o => o.ServiceName = ServiceNames.Main);

// ---- protected storage
Paths.HardenDirectory(Paths.DataRoot);
var protector = new DpapiProtector();
var log = new AccountabilityLog(Paths.LogPath, LogKey.LoadOrCreate(protector));
var enforcement = new WindowsEnforcement(log);
var engine = new LockEngine(
    new FileStateStore(Paths.StateDir, protector, Paths.HardenFile),
    enforcement,
    new ConnectionTester(),
    ChangeTypeRegistry.CreateDefault(),
    new SystemMonotonicClock(),
    new SystemWallClock(),
    log,
    new MsiUninstaller(log));

builder.Services.AddSingleton(engine);
builder.Services.AddSingleton<IAccountabilityLog>(log);
builder.Services.AddSingleton(enforcement);
builder.Services.AddHostedService<EngineWorker>();
builder.Services.AddHostedService<IpcWorker>();
builder.Services.AddHostedService<GuardianWorker>();
builder.Services.AddHostedService<ReachabilityWorker>();
builder.Services.AddHostedService<TrustedTimeWorker>();
builder.Build().Run();

namespace GuardianAngel.Service
{
    internal static class LogKey
    {
        public static byte[] LoadOrCreate(IDataProtector protector)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Paths.LogKeyPath)!);
            if (File.Exists(Paths.LogKeyPath)) return protector.Unprotect(File.ReadAllBytes(Paths.LogKeyPath));
            var key = RandomNumberGenerator.GetBytes(32);
            File.WriteAllBytes(Paths.LogKeyPath, protector.Protect(key));
            return key;
        }
    }

    /// <summary>Ticks the delay clock every second; reconciles every 10 s and on every network or hosts change.</summary>
    internal sealed class EngineWorker(LockEngine engine, WindowsEnforcement enforcement, ILogger<EngineWorker> logger) : BackgroundService
    {
        private int _reconcileRequested = 1;

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            await engine.StartAsync(ct);
            Maintenance.SetUninstallAuthorized(engine.UninstallAllowed);

            NetworkChange.NetworkAddressChanged += (_, _) => Interlocked.Exchange(ref _reconcileRequested, 1);
            NetworkChange.NetworkAvailabilityChanged += (_, _) => Interlocked.Exchange(ref _reconcileRequested, 1);
            enforcement.Hosts.Changed += () => Interlocked.Exchange(ref _reconcileRequested, 1);

            var lastReconcile = DateTime.MinValue;
            var lastUninstallFlag = engine.UninstallAllowed;
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await engine.TickAsync(ct);
                    if (Interlocked.Exchange(ref _reconcileRequested, 0) == 1 || DateTime.UtcNow - lastReconcile > TimeSpan.FromSeconds(10))
                    {
                        await engine.ReconcileAsync(ct);
                        lastReconcile = DateTime.UtcNow;
                    }
                    if (engine.UninstallAllowed != lastUninstallFlag)
                    {
                        lastUninstallFlag = engine.UninstallAllowed;
                        Maintenance.SetUninstallAuthorized(lastUninstallFlag);
                    }
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
                catch (Exception ex) { logger.LogError(ex, "Engine tick failed"); }
                await Task.Delay(1000, ct).ContinueWith(_ => { });
            }
        }
    }

    internal sealed class IpcWorker(LockEngine engine, ILogger<IpcWorker> logger) : BackgroundService
    {
        protected override Task ExecuteAsync(CancellationToken ct) =>
            new IpcServer(() => PipeSecurityFactory.CreateUiPipe(), (req, _) => engine.HandleAsync(req, ct),
                ex => logger.LogDebug(ex, "IPC error")).RunAsync(ct);
    }

    /// <summary>Keeps the watchdog alive (the watchdog does the same for this service).</summary>
    internal sealed class GuardianWorker(ILogger<GuardianWorker> logger) : BackgroundService
    {
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            try
            {
                ServiceHardening.Harden(ServiceNames.Main);
                ServiceGuardian.RefreshRecoveryCopy();
            }
            catch (Exception ex) { logger.LogWarning(ex, "Hardening failed"); }

            var guardian = new ServiceGuardian(ServiceNames.Watchdog, ServiceNames.WatchdogDisplay, ServiceNames.WatchdogExe, m => logger.LogWarning("{Message}", m));
            while (!ct.IsCancellationRequested)
            {
                try { guardian.CheckOnce(); } catch (Exception ex) { logger.LogError(ex, "Guardian check failed"); }
                await Task.Delay(TimeSpan.FromSeconds(3), ct).ContinueWith(_ => { });
            }
        }
    }

    /// <summary>Checks the filter answers. After 3 failures in a row, "block internet" mode kicks in if chosen.</summary>
    internal sealed class ReachabilityWorker(LockEngine engine) : BackgroundService
    {
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            var failures = 0;
            while (!ct.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromSeconds(10), ct).ContinueWith(_ => { });
                var filter = engine.CurrentFilter;
                if (filter is null) { failures = 0; continue; }
                var ok = false;
                foreach (var server in filter.ParsedServers())
                {
                    try
                    {
                        var a = await ConnectionTester.DefaultProbe(filter).QueryAsync(server, "example.com", DnsWire.TypeA, ct).WaitAsync(TimeSpan.FromSeconds(5), ct);
                        if (a.Rcode == DnsRcode.NoError) { ok = true; break; }
                    }
                    catch (Exception) when (!ct.IsCancellationRequested) { }
                }
                failures = ok ? 0 : failures + 1;
                engine.SetFilterReachable(failures < 3);
            }
        }
    }

    /// <summary>Gets TLS-verified time so that time spent switched off can count toward delays.</summary>
    internal sealed class TrustedTimeWorker(LockEngine engine, ILogger<TrustedTimeWorker> logger) : BackgroundService
    {
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            var source = new HttpsTrustedTime(() =>
            {
                var urls = new List<string>();
                if (engine.CurrentFilter?.DohTemplate is { } t && Uri.TryCreate(t, UriKind.Absolute, out var u)) urls.Add($"https://{u.Host}/");
                urls.AddRange(["https://www.microsoft.com/", "https://www.cloudflare.com/", "https://www.google.com/"]);
                return urls;
            });
            var delay = TimeSpan.FromSeconds(20);
            while (!ct.IsCancellationRequested)
            {
                await Task.Delay(delay, ct).ContinueWith(_ => { });
                try
                {
                    if (await source.GetTrustedUtcAsync(ct) is { } trusted)
                    {
                        await engine.OnTrustedTimeAsync(trusted, ct);
                        delay = TimeSpan.FromHours(1);
                    }
                    else delay = TimeSpan.FromMinutes(1);
                }
                catch (Exception ex) when (!ct.IsCancellationRequested) { logger.LogDebug(ex, "Trusted time failed"); delay = TimeSpan.FromMinutes(1); }
            }
        }
    }
}
