using System.Runtime.InteropServices;

namespace GuardianAngel.Platform.Windows.Native;

internal static class ServiceApi
{
    public const uint SC_MANAGER_CONNECT = 0x0001;
    public const uint READ_CONTROL = 0x00020000, WRITE_DAC = 0x00040000;
    public const uint DACL_SECURITY_INFORMATION = 0x4;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr OpenSCManagerW(string? machine, string? database, uint access);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr OpenServiceW(IntPtr scm, string name, uint access);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool SetServiceObjectSecurity(IntPtr service, uint securityInformation, IntPtr sd);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool CloseServiceHandle(IntPtr handle);
}
