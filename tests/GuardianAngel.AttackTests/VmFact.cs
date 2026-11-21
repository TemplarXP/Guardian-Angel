using GuardianAngel.Core.Ipc;

namespace GuardianAngel.AttackTests;

/// <summary>Runs only when GA_TEST_VM=1 (set by scripts\Invoke-VMTests.ps1 inside the VM).</summary>
public sealed class VmFactAttribute : FactAttribute
{
    public VmFactAttribute()
    {
        if (!OperatingSystem.IsWindows() || Environment.GetEnvironmentVariable("GA_TEST_VM") != "1")
            Skip = "Attack tests run only inside a test VM (GA_TEST_VM=1).";
    }
}

internal static class Vm
{
    public static readonly IpcClient Client = new();

    public static async Task<StatusDto> LockedStatusAsync()
    {
        var s = await Client.CallAsync<StatusDto>(Ops.GetStatus);
        Assert.True(s.IsLocked, "Lock Guardian Angel in the VM before running the attack tests.");
        return s;
    }

    /// <summary>Polls until the condition holds or the timeout passes.</summary>
    public static async Task<bool> Eventually(Func<bool> condition, TimeSpan timeout)
    {
        var until = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < until)
        {
            if (condition()) return true;
            await Task.Delay(500);
        }
        return condition();
    }

    public static (int Code, string Output) Run(string exe, string args)
    {
        var psi = new System.Diagnostics.ProcessStartInfo(exe, args) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        using var p = System.Diagnostics.Process.Start(psi)!;
        var o = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit(120_000);
        return (p.ExitCode, o);
    }
}
