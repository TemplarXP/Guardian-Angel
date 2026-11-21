using System.Security.Principal;

namespace GuardianAngel.Windows.Tests;

/// <summary>Runs only on Windows, as Administrator (GitHub's Windows runners qualify).</summary>
public sealed class WindowsAdminFactAttribute : FactAttribute
{
    public WindowsAdminFactAttribute()
    {
        if (!OperatingSystem.IsWindows()) Skip = "Windows only";
        else if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)) Skip = "Needs Administrator";
    }
}
