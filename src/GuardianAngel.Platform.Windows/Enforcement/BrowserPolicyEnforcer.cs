using GuardianAngel.Core.Browser;
using GuardianAngel.Core.Ipc;
using GuardianAngel.Core.Model;
using Microsoft.Win32;

namespace GuardianAngel.Platform.Windows.Enforcement;

/// <summary>
/// Writes browser policies under HKLM\SOFTWARE\Policies (standard users can't change these), re-writes them
/// if anything changes them, and removes values for options the user turned off.
/// </summary>
public sealed class BrowserPolicyEnforcer
{
    public EnforcementItemDto Apply(BrowserOptions options, IReadOnlyList<string>? blockedExtensionIds = null)
    {
        var plan = BrowserPolicyPlanner.Plan(options, blockedExtensionIds);
        var reverted = 0;
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);

        foreach (var v in plan)
        {
            using var key = hklm.CreateSubKey(v.KeyPath, writable: true);
            var current = key.GetValue(v.Name);
            var wanted = v.Kind == RegKind.DWord ? (object)Convert.ToInt32(v.Value) : (string)v.Value;
            if (current is null || !current.Equals(wanted))
            {
                key.SetValue(v.Name, wanted, v.Kind == RegKind.DWord ? RegistryValueKind.DWord : RegistryValueKind.String);
                if (current is not null) reverted++;
            }
        }

        // Remove values we own that the current options no longer want.
        var wantedSet = plan.Select(p => (p.KeyPath, p.Name)).ToHashSet();
        foreach (var (keyPath, name) in BrowserPolicyPlanner.AllPossible().Where(x => !wantedSet.Contains(x)))
        {
            using var key = hklm.OpenSubKey(keyPath, writable: true);
            key?.DeleteValue(name, throwOnMissingValue: false);
        }

        return new EnforcementItemDto("Browser secure DNS off", true,
            reverted == 0 ? "Chrome, Edge, Brave and Firefox use your filter." : $"Restored {reverted} browser setting(s) that had been changed.");
    }

    public void RemoveAll()
    {
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        foreach (var (keyPath, name) in BrowserPolicyPlanner.AllPossible())
        {
            using var key = hklm.OpenSubKey(keyPath, writable: true);
            key?.DeleteValue(name, throwOnMissingValue: false);
        }
    }
}
