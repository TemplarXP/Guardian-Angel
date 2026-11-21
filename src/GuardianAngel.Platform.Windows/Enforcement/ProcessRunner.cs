using System.Diagnostics;

namespace GuardianAngel.Platform.Windows.Enforcement;

internal static class ProcessRunner
{
    /// <summary>Runs a system tool from System32 (never from PATH) and returns exit code and output.</summary>
    public static (int ExitCode, string Output) Run(string exeName, string arguments, int timeoutMs = 30_000)
    {
        var exe = Path.Combine(Environment.SystemDirectory, exeName);
        var psi = new ProcessStartInfo(exe, arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        using var p = Process.Start(psi)!;
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(timeoutMs))
        {
            try { p.Kill(true); } catch { /* already gone */ }
            return (-1, "timed out");
        }
        return (p.ExitCode, stdout.Result + stderr.Result);
    }
}
