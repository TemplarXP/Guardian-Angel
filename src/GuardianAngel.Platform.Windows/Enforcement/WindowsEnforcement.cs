using GuardianAngel.Core.Engine;
using GuardianAngel.Core.Firewall;
using GuardianAngel.Core.Ipc;
using GuardianAngel.Core.Lists;
using GuardianAngel.Core.Log;
using GuardianAngel.Platform.Windows.Security;

namespace GuardianAngel.Platform.Windows.Enforcement;

/// <summary>
/// Combines all Milestone 1 enforcers. Order matters: the firewall goes first, so that while adapters are being
/// changed DNS can only reach the filter (fail closed).
/// </summary>
public sealed class WindowsEnforcement(IAccountabilityLog log) : IEnforcement
{
    private readonly WfpFirewall _firewall = new();
    private readonly DnsEnforcer _dns = new();
    private readonly BrowserPolicyEnforcer _browsers = new();
    public HostsGuard Hosts { get; } = new();

    private ResolverList Resolvers => SignedList.LoadResolvers(Path.Combine(Paths.ListsDir, "resolvers.json"));

    public Task<IReadOnlyList<EnforcementItemDto>> ReconcileAsync(DesiredEnforcement d, CancellationToken ct)
    {
        var items = new List<EnforcementItemDto>();
        if (!d.Active || d.Filter is null) return Task.FromResult<IReadOnlyList<EnforcementItemDto>>(items);

        items.Add(Guard("Firewall lock", () =>
        {
            var rules = FirewallPlanner.Plan(d.Filter, d.ExtraAllowedServers, Resolvers.AllIps(), d.BlockAllExceptFilter);
            _firewall.Apply(rules);
            var detail = d.BlockAllExceptFilter
                ? "No filter can be reached, so the internet is blocked until it can."
                : $"DNS can only reach {d.Filter.Name}. {rules.Count} rules active.";
            if (WfpFirewall.BootTimeFailures > 0) detail += " (Boot-time copies could not all be added; see the log.)";
            return new EnforcementItemDto("Firewall lock", true, detail);
        }));
        items.Add(Guard("DNS lock", () => _dns.Apply(d.Filter, d.ExtraAllowedServers)));
        items.Add(Guard("Browser secure DNS off", () => _browsers.Apply(d.Browser)));
        items.Add(Guard("Hosts file guard", () =>
        {
            Hosts.StartWatching();
            var (item, removed) = Hosts.Apply();
            foreach (var line in removed) log.Append("bypass-attempt", $"Hosts file: removed \"{line}\".");
            return item;
        }));
        return Task.FromResult<IReadOnlyList<EnforcementItemDto>>(items);
    }

    public Task RemoveAllAsync(CancellationToken ct)
    {
        // Reverse order: DNS back to automatic first, then open the firewall.
        Try(_browsers.RemoveAll);
        Try(_dns.RemoveAll);
        Try(_firewall.RemoveAll);
        log.Append("removed", "All protections removed for uninstall.");
        return Task.CompletedTask;
    }

    private EnforcementItemDto Guard(string name, Func<EnforcementItemDto> f)
    {
        try { return f(); }
        catch (Exception ex)
        {
            log.Append("enforcement-error", $"{name}: {ex.Message}");
            return new EnforcementItemDto(name, false, "Problem: " + ex.Message + " (the previous protection stays in place)");
        }
    }

    private void Try(Action a)
    {
        try { a(); } catch (Exception ex) { log.Append("enforcement-error", ex.Message); }
    }
}
