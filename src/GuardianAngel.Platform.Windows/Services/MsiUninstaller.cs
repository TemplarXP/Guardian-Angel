using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using GuardianAngel.Core.Engine;
using GuardianAngel.Core.Log;

namespace GuardianAngel.Platform.Windows.Services;

/// <summary>
/// Performs a DUE uninstall. Protections have already been removed by the engine. This marks the uninstall
/// as authorized (the MSI checks it), stops guarding, and starts the Windows Installer removal as SYSTEM.
/// </summary>
public sealed class MsiUninstaller(IAccountabilityLog log) : IUninstaller
{
    /// <summary>Must match the UpgradeCode in src/GuardianAngel.Installer/Package.wxs. Never change it.</summary>
    public const string UpgradeCode = "{4B0C2E8A-7D3F-4F6B-9C21-5E8A1D3B7C90}";

    public void Start()
    {
        Maintenance.SetUninstallAuthorized(true);
        ServiceHardening.RemoveSafeBoot(ServiceNames.Main);
        ServiceHardening.RemoveSafeBoot(ServiceNames.Watchdog);

        var product = FindProductCode();
        if (product is null)
        {
            log.Append("uninstall", "Uninstall is authorized, but the installed package wasn't found. Remove it from Settings > Apps.");
            return;
        }
        log.Append("uninstall", "Starting uninstall.");
        var logFile = Path.Combine(Path.GetTempPath(), "GuardianAngel-uninstall.log");
        Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "msiexec.exe"),
            $"/x {product} /qn /norestart /l*v \"{logFile}\"") { UseShellExecute = false, CreateNoWindow = true });
    }

    public static string? FindProductCode()
    {
        var sb = new StringBuilder(39);
        return MsiEnumRelatedProductsW(UpgradeCode, 0, 0, sb) == 0 ? sb.ToString() : null;
    }

    [DllImport("msi.dll", CharSet = CharSet.Unicode)]
    private static extern uint MsiEnumRelatedProductsW(string upgradeCode, uint reserved, uint index, StringBuilder productBuf);
}
