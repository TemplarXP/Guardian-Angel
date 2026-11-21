using GuardianAngel.Core.Ipc;
using GuardianAngel.Core.Model;

namespace GuardianAngel.Core.Engine;

/// <summary>What the enforcers should make true on the machine.</summary>
public sealed record DesiredEnforcement(
    bool Active,
    FilterConfig? Filter,
    IReadOnlyList<string> ExtraAllowedServers,
    BrowserOptions Browser,
    bool BlockAllExceptFilter);

/// <summary>Implemented by the Windows layer (DNS, WFP firewall, browser policies, hosts guard).</summary>
public interface IEnforcement
{
    /// <summary>Makes the machine match <paramref name="desired"/>. Must be idempotent and fail closed.</summary>
    Task<IReadOnlyList<EnforcementItemDto>> ReconcileAsync(DesiredEnforcement desired, CancellationToken ct);

    /// <summary>Removes every protection. Called only when an uninstall is due.</summary>
    Task RemoveAllAsync(CancellationToken ct);
}

/// <summary>Starts the real uninstall (msiexec) once an uninstall change has been applied.</summary>
public interface IUninstaller
{
    void Start();
}

public sealed class NoopUninstaller : IUninstaller
{
    public int Started { get; private set; }
    public void Start() => Started++;
}
