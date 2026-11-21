using System.Security.Cryptography;
using System.ServiceProcess;
using GuardianAngel.Platform.Windows.Enforcement;
using GuardianAngel.Platform.Windows.Security;

namespace GuardianAngel.Platform.Windows.Services;

/// <summary>
/// Keeps another Guardian Angel service alive. The main service guards the watchdog and the watchdog guards
/// the main service, so stopping or deleting one brings it back within seconds.
/// </summary>
public sealed class ServiceGuardian(string serviceName, string displayName, string exeName, Action<string> log)
{
    public string ExpectedBinary => Path.Combine(Paths.InstallDir, exeName);

    /// <summary>Copies the install folder to the protected recovery folder (once per version).</summary>
    public static void RefreshRecoveryCopy()
    {
        var marker = Path.Combine(Paths.RecoveryDir, "version.txt");
        var version = typeof(ServiceGuardian).Assembly.GetName().Version?.ToString() ?? "0";
        if (File.Exists(marker) && File.ReadAllText(marker) == version) return;
        Paths.HardenDirectory(Paths.RecoveryDir);
        foreach (var file in Directory.EnumerateFiles(Paths.InstallDir, "*", SearchOption.AllDirectories))
        {
            var rel = Path.GetRelativePath(Paths.InstallDir, file);
            var dest = Path.Combine(Paths.RecoveryDir, rel);
            Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
            File.Copy(file, dest, overwrite: true);
        }
        File.WriteAllText(marker, version);
    }

    public void CheckOnce()
    {
        if (Maintenance.ShouldStandDown()) return;
        RestoreMissingFiles();

        ServiceController? sc = ServiceController.GetServices().FirstOrDefault(s => s.ServiceName.Equals(serviceName, StringComparison.OrdinalIgnoreCase));
        if (sc is null)
        {
            log($"{displayName} was deleted; registering it again.");
            var bin = ExpectedBinary;
            ProcessRunner.Run("sc.exe", $"create {serviceName} binPath= \"{bin}\" start= auto obj= LocalSystem DisplayName= \"{displayName}\"");
            ServiceHardening.Harden(serviceName);
            sc = new ServiceController(serviceName);
        }

        using (sc)
        {
            if (sc.StartType != ServiceStartMode.Automatic)
            {
                log($"{displayName} start type was changed; setting it back to automatic.");
                ProcessRunner.Run("sc.exe", $"config {serviceName} start= auto");
            }
            if (sc.Status is ServiceControllerStatus.Stopped or ServiceControllerStatus.StopPending or ServiceControllerStatus.Paused)
            {
                log($"{displayName} was not running; starting it.");
                try
                {
                    if (sc.Status == ServiceControllerStatus.Paused) sc.Continue();
                    else { sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(10)); sc.Start(); }
                }
                catch (Exception ex) { log($"Couldn't start {displayName}: {ex.Message}"); }
            }
        }
    }

    /// <summary>Puts back install files that were deleted or modified, from the hash-checked recovery copy.</summary>
    private void RestoreMissingFiles()
    {
        if (!Directory.Exists(Paths.RecoveryDir)) return;
        foreach (var src in Directory.EnumerateFiles(Paths.RecoveryDir, "*", SearchOption.AllDirectories))
        {
            var rel = Path.GetRelativePath(Paths.RecoveryDir, src);
            if (rel == "version.txt") continue;
            var dest = Path.Combine(Paths.InstallDir, rel);
            if (File.Exists(dest) && Same(src, dest)) continue;
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
                File.Copy(src, dest, overwrite: true);
                log($"Restored {rel}.");
            }
            catch (IOException) { /* in use: it's present, fine */ }
            catch (UnauthorizedAccessException) { }
        }
    }

    private static bool Same(string a, string b)
    {
        var fa = new FileInfo(a); var fb = new FileInfo(b);
        if (fa.Length != fb.Length) return false;
        using var sa = fa.OpenRead(); using var sb = new FileStream(b, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return SHA256.HashData(sa).AsSpan().SequenceEqual(SHA256.HashData(sb));
    }
}
