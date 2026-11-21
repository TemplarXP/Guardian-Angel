using System.Security.AccessControl;
using System.Security.Principal;

namespace GuardianAngel.Platform.Windows.Security;

public static class Paths
{
    public static string DataRoot => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "GuardianAngel");
    public static string StateDir => Path.Combine(DataRoot, "state");
    public static string LogPath => Path.Combine(DataRoot, "log", "accountability.jsonl");
    public static string LogKeyPath => Path.Combine(DataRoot, "state", "log.key");
    public static string ListsDir => Path.Combine(DataRoot, "lists");
    public static string RecoveryDir => Path.Combine(DataRoot, "recovery");
    public static string InstallDir => AppContext.BaseDirectory;

    /// <summary>
    /// SYSTEM: full control. Administrators: read only (they could still take ownership, which is why
    /// Milestone 2 makes the daily account a standard user). Users: no access at all.
    /// </summary>
    public static void HardenDirectory(string dir)
    {
        Directory.CreateDirectory(dir);
        var sec = new DirectorySecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        var inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            FileSystemRights.ReadAndExecute, inherit, PropagationFlags.None, AccessControlType.Allow));
        sec.SetOwner(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
        new DirectoryInfo(dir).SetAccessControl(sec);
    }

    public static void HardenFile(string file)
    {
        var sec = new FileSecurity();
        sec.SetAccessRuleProtection(true, false);
        sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            FileSystemRights.FullControl, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            FileSystemRights.Read, AccessControlType.Allow));
        new FileInfo(file).SetAccessControl(sec);
    }
}
