using GuardianAngel.Platform.Windows.Enforcement;
using GuardianAngel.Platform.Windows.Native;
using Microsoft.Win32;

namespace GuardianAngel.Platform.Windows.Services;

/// <summary>Applied by each service to itself and to its partner service at every start.</summary>
public static class ServiceHardening
{
#if GA_DEBUG_BYPASS
    // Debug builds: Administrators keep stop/start rights so a developer can iterate in a VM.
    public const string Sddl = "D:(A;;CCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPWPDTLOCRSDRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)";
#else
    // Release: only SYSTEM may stop, reconfigure or delete the services. Others may only query them.
    public const string Sddl = "D:(A;;CCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)";
#endif

    public static void Harden(string serviceName)
    {
        SetSecurityDescriptor(serviceName);
        // Restart immediately on failure, forever (reset counter after a day).
        ProcessRunner.Run("sc.exe", $"failure {serviceName} reset= 86400 actions= restart/0/restart/0/restart/5000");
        ProcessRunner.Run("sc.exe", $"failureflag {serviceName} 1");
        // Start in Safe Mode too.
        foreach (var mode in new[] { "Minimal", "Network" })
        {
            using var k = Registry.LocalMachine.CreateSubKey($@"SYSTEM\CurrentControlSet\Control\SafeBoot\{mode}\{serviceName}");
            k.SetValue("", "Service");
        }
    }

    public static void RemoveSafeBoot(string serviceName)
    {
        foreach (var mode in new[] { "Minimal", "Network" })
            Registry.LocalMachine.DeleteSubKeyTree($@"SYSTEM\CurrentControlSet\Control\SafeBoot\{mode}\{serviceName}", throwOnMissingSubKey: false);
    }

    private static void SetSecurityDescriptor(string serviceName)
    {
        var scm = ServiceApi.OpenSCManagerW(null, null, ServiceApi.SC_MANAGER_CONNECT);
        if (scm == IntPtr.Zero) return;
        try
        {
            var svc = ServiceApi.OpenServiceW(scm, serviceName, ServiceApi.WRITE_DAC | ServiceApi.READ_CONTROL);
            if (svc == IntPtr.Zero) return;
            try
            {
                using var sd = Enforcement.SecurityDescriptorHandle.FromSddl(Sddl);
                ServiceApi.SetServiceObjectSecurity(svc, ServiceApi.DACL_SECURITY_INFORMATION, sd.Ptr);
            }
            finally { ServiceApi.CloseServiceHandle(svc); }
        }
        finally { ServiceApi.CloseServiceHandle(scm); }
    }
}
