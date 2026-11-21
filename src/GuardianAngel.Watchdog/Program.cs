using GuardianAngel.Platform.Windows.Services;

// The watchdog keeps the main service registered, configured and running. The main service does the same for
// the watchdog. Both are LocalSystem services that only SYSTEM can stop or delete (Release builds).
var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(o => o.ServiceName = ServiceNames.Watchdog);
builder.Services.AddHostedService<WatchdogWorker>();
builder.Build().Run();

internal sealed class WatchdogWorker(ILogger<WatchdogWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        try { ServiceHardening.Harden(ServiceNames.Watchdog); } catch (Exception ex) { logger.LogWarning(ex, "Hardening failed"); }
        var guardian = new ServiceGuardian(ServiceNames.Main, ServiceNames.MainDisplay, ServiceNames.MainExe, m => logger.LogWarning("{Message}", m));
        while (!ct.IsCancellationRequested)
        {
            try { guardian.CheckOnce(); }
            catch (Exception ex) { logger.LogError(ex, "Guardian check failed"); }
            await Task.Delay(TimeSpan.FromSeconds(3), ct).ContinueWith(_ => { });
        }
    }
}
