using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;

namespace GuardianAngel.Platform.Windows.Services;

/// <summary>
/// Signals that tell the guardians to stand down: a due uninstall, or a Windows Installer
/// session (an upgrade replaces files and restarts the services itself).
/// </summary>
public static class Maintenance
{
    public const string RegKey = @"SOFTWARE\GuardianAngel";
    public const string UninstallValue = "UninstallAuthorized";
    private static DateTime? _msiSeenSince;

    /// <summary>Written only by the service. The MSI's uninstall check reads this value.</summary>
    public static void SetUninstallAuthorized(bool allowed)
    {
        using var k = Registry.LocalMachine.CreateSubKey(RegKey, writable: true);
        k.SetValue(UninstallValue, allowed ? 1 : 0, RegistryValueKind.DWord);
        try
        {
            var sec = new RegistrySecurity();
            sec.SetAccessRuleProtection(true, false);
            sec.AddAccessRule(new RegistryAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), RegistryRights.FullControl,
                InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Allow));
            sec.AddAccessRule(new RegistryAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), RegistryRights.ReadKey,
                InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Allow));
            sec.AddAccessRule(new RegistryAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), RegistryRights.ReadKey,
                InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Allow));
            k.SetAccessControl(sec);
        }
        catch (UnauthorizedAccessException) { }
    }

    public static bool IsUninstallAuthorized()
    {
        using var k = Registry.LocalMachine.OpenSubKey(RegKey);
        return k?.GetValue(UninstallValue) is int v && v == 1;
    }

    /// <summary>True while Windows Installer is running, for at most 30 minutes in a row.</summary>
    public static bool IsInstallerRunning()
    {
        var running = Mutex.TryOpenExisting(@"Global\_MSIExecute", out var m);
        m?.Dispose();
        if (!running) { _msiSeenSince = null; return false; }
        _msiSeenSince ??= DateTime.UtcNow;
        return DateTime.UtcNow - _msiSeenSince < TimeSpan.FromMinutes(30);
    }

    public static bool ShouldStandDown() => IsUninstallAuthorized() || IsInstallerRunning();
}
