using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using GuardianAngel.Core.Firewall;
using GuardianAngel.Platform.Windows.Native;
using static GuardianAngel.Platform.Windows.Native.WfpConst;

namespace GuardianAngel.Platform.Windows.Enforcement;

/// <summary>
/// Installs the firewall lock as Windows Filtering Platform filters in Guardian Angel's own provider and sublayer.
///
/// Every rule is added twice:
///  * PERSISTENT: kept by the Base Filtering Engine across reboots, and even if our service is stopped or deleted.
///  * BOOTTIME:   enforced by the TCP/IP stack at boot, before the Base Filtering Engine starts.
/// Block rules clear the "action right", so no permit rule in any other sublayer (including Windows Defender
/// Firewall rules) can override them, and turning Windows Firewall off doesn't affect them.
///
/// Filter keys are deterministic (derived from the rule index), so the set can always be found and replaced
/// atomically inside one WFP transaction.
/// </summary>
public sealed class WfpFirewall(bool restrictToSystem = true)
{
    public static readonly Guid ProviderKey = new("6f0c3c5e-6a2b-4d7e-9a51-0e7c1a5b9f10");
    public static readonly Guid SubLayerKey = new("6f0c3c5e-6a2b-4d7e-9a51-0e7c1a5b9f11");

    /// <summary>Upper bound on rules; used to clean up keys from older, larger rule sets.</summary>
    public const int MaxRules = 1024;

    /// <summary>Only SYSTEM may change our objects; Administrators may read them.</summary>
    private const string SystemOnlySddl = "D:P(A;;GA;;;SY)(A;;GR;;;BA)";

    /// <summary>
    /// The service (SYSTEM) restricts our WFP objects so Administrators can't delete them through the WFP API.
    /// Integration tests run as Administrator and use Windows' default descriptor instead.
    /// </summary>
    private string? ObjectSddl => restrictToSystem ? SystemOnlySddl : null;

    private string? _appliedSignature;
    public int AppliedCount { get; private set; }

    public static string Signature(IReadOnlyList<FirewallRule> rules) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\n", rules.Select(r =>
            $"{r.Action}|{r.Weight}|{r.RemoteAddress}|{string.Join(',', r.RemotePorts ?? [])}|{r.Protocol}|{r.LoopbackOnly}")))));

    /// <summary>Applies the rule set if it changed or if any of our filters went missing.</summary>
    public void Apply(IReadOnlyList<FirewallRule> rules)
    {
        var sig = Signature(rules);
        if (sig == _appliedSignature && VerifyPresent(rules)) return;

        using var engine = WfpEngine.Open();
        engine.InTransaction(() =>
        {
            EnsureProviderAndSublayer(engine, ObjectSddl);
            DeleteOurFilters(engine);
            var index = 0;
            foreach (var rule in rules)
                foreach (var layer in LayersFor(rule))
                {
                    AddFilter(engine, rule, layer, index, bootTime: false, ObjectSddl);
                    AddFilter(engine, rule, layer, index, bootTime: true, ObjectSddl);
                    index++;
                }
            AppliedCount = index;
        });
        _appliedSignature = sig;
    }

    /// <summary>True when every expected persistent filter exists.</summary>
    public bool VerifyPresent(IReadOnlyList<FirewallRule> rules)
    {
        using var engine = WfpEngine.Open();
        var index = 0;
        foreach (var rule in rules)
            foreach (var _ in LayersFor(rule))
            {
                var key = FilterKey(index++, bootTime: false);
                if (WfpApi.FwpmFilterGetByKey0(engine.Handle, ref key, out var f) != 0) return false;
                WfpApi.FwpmFreeMemory0(ref f);
            }
        return true;
    }

    /// <summary>Removes every Guardian Angel filter, the sublayer and the provider. Only for a due uninstall.</summary>
    public void RemoveAll()
    {
        using var engine = WfpEngine.Open();
        engine.InTransaction(() =>
        {
            DeleteOurFilters(engine);
            var sub = SubLayerKey;
            Check(WfpApi.FwpmSubLayerDeleteByKey0(engine.Handle, ref sub), FWP_E_SUBLAYER_NOT_FOUND);
            var prov = ProviderKey;
            Check(WfpApi.FwpmProviderDeleteByKey0(engine.Handle, ref prov), FWP_E_PROVIDER_NOT_FOUND);
        });
        _appliedSignature = null;
        AppliedCount = 0;
    }

    private static IEnumerable<Guid> LayersFor(FirewallRule r)
    {
        if (!r.IsV6Only) yield return FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        if (!r.IsV4Only) yield return FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    }

    internal static Guid FilterKey(int index, bool bootTime)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes($"GuardianAngel/filter/{(bootTime ? "boot" : "persistent")}/{index}"));
        return new Guid(bytes.AsSpan(0, 16));
    }

    private static void DeleteOurFilters(WfpEngine engine)
    {
        for (int i = 0; i < MaxRules * 2; i++)
            foreach (var boot in new[] { false, true })
            {
                var key = FilterKey(i, boot);
                Check(WfpApi.FwpmFilterDeleteByKey0(engine.Handle, ref key), FWP_E_FILTER_NOT_FOUND);
            }
    }

    private static void EnsureProviderAndSublayer(WfpEngine engine, string? sddl)
    {
        using var name = new NativeString("Guardian Angel");
        using var desc = new NativeString("Locks DNS to the filter you chose. Removed only by a due uninstall.");
        using var sd = SecurityDescriptorHandle.FromSddl(sddl);

        var provider = new FWPM_PROVIDER0
        {
            providerKey = ProviderKey,
            displayData = new FWPM_DISPLAY_DATA0 { name = name.Ptr, description = desc.Ptr },
            flags = FWPM_PROVIDER_FLAG_PERSISTENT,
        };
        Check(WfpApi.FwpmProviderAdd0(engine.Handle, ref provider, sd.Ptr), FWP_E_ALREADY_EXISTS);

        var providerKeyPtr = Marshal.AllocHGlobal(16);
        try
        {
            Marshal.StructureToPtr(ProviderKey, providerKeyPtr, false);
            var sub = new FWPM_SUBLAYER0
            {
                subLayerKey = SubLayerKey,
                displayData = new FWPM_DISPLAY_DATA0 { name = name.Ptr, description = desc.Ptr },
                flags = FWPM_SUBLAYER_FLAG_PERSISTENT,
                providerKey = providerKeyPtr,
                weight = 0xFFFF,
            };
            Check(WfpApi.FwpmSubLayerAdd0(engine.Handle, ref sub, sd.Ptr), FWP_E_ALREADY_EXISTS);
        }
        finally { Marshal.FreeHGlobal(providerKeyPtr); }
    }

    private static void AddFilter(WfpEngine engine, FirewallRule rule, Guid layer, int index, bool bootTime, string? sddl)
    {
        using var mem = new NativeArena();
        var conditions = new List<FWPM_FILTER_CONDITION0>();

        if (rule.RemoteAddress is { } ip)
        {
            var cond = new FWPM_FILTER_CONDITION0 { fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS, matchType = FWP_MATCH_EQUAL };
            if (ip.AddressFamily == AddressFamily.InterNetwork)
            {
                var b = ip.GetAddressBytes();
                cond.conditionValue = new FWP_VALUE0 { type = FWP_UINT32, uint64 = (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]) };
            }
            else
            {
                cond.conditionValue = new FWP_VALUE0 { type = FWP_BYTE_ARRAY16_TYPE, pointer = mem.Bytes(ip.GetAddressBytes()) };
            }
            conditions.Add(cond);
        }
        foreach (var port in rule.RemotePorts ?? [])
            conditions.Add(new FWPM_FILTER_CONDITION0
            {
                fieldKey = FWPM_CONDITION_IP_REMOTE_PORT, matchType = FWP_MATCH_EQUAL,
                conditionValue = new FWP_VALUE0 { type = FWP_UINT16, uint64 = port },
            });
        if (rule.Protocol is { } proto)
            conditions.Add(new FWPM_FILTER_CONDITION0
            {
                fieldKey = FWPM_CONDITION_IP_PROTOCOL, matchType = FWP_MATCH_EQUAL,
                conditionValue = new FWP_VALUE0 { type = FWP_UINT8, uint64 = proto },
            });
        if (rule.LoopbackOnly)
            conditions.Add(new FWPM_FILTER_CONDITION0
            {
                fieldKey = FWPM_CONDITION_FLAGS, matchType = FWP_MATCH_FLAGS_ALL_SET,
                conditionValue = new FWP_VALUE0 { type = FWP_UINT32, uint64 = FWP_CONDITION_FLAG_IS_LOOPBACK },
            });

        var condPtr = mem.Array(conditions);
        using var name = new NativeString($"Guardian Angel: {rule.Name}");
        var providerKeyPtr = mem.Struct(ProviderKey);

        var block = rule.Action == FilterAction.Block;
        var filter = new FWPM_FILTER0
        {
            filterKey = FilterKey(index, bootTime),
            displayData = new FWPM_DISPLAY_DATA0 { name = name.Ptr },
            flags = (bootTime ? FWPM_FILTER_FLAG_BOOTTIME : FWPM_FILTER_FLAG_PERSISTENT) | (block ? FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT : 0),
            // Boot-time filters go to the default sublayer (BFE-owned sublayers don't exist yet at boot) and carry no provider.
            providerKey = bootTime ? IntPtr.Zero : providerKeyPtr,
            layerKey = layer,
            subLayerKey = bootTime ? Guid.Empty : SubLayerKey,
            weight = new FWP_VALUE0 { type = FWP_UINT8, uint64 = rule.Weight },
            numFilterConditions = (uint)conditions.Count,
            filterCondition = condPtr,
            action = new FWPM_ACTION0 { type = block ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT },
        };

        using var sd = SecurityDescriptorHandle.FromSddl(sddl);
        var rc = WfpApi.FwpmFilterAdd0(engine.Handle, ref filter, bootTime ? IntPtr.Zero : sd.Ptr, out _);
        if (rc != 0 && bootTime)
        {
            // [verify in VM] If boot-time filters are refused for any reason, the persistent copy still protects
            // from the moment the Base Filtering Engine starts. Don't fail the whole lock over it.
            BootTimeFailures++;
            return;
        }
        Check(rc);
    }

    public static int BootTimeFailures { get; private set; }

    internal static void Check(uint rc, params uint[] okCodes)
    {
        if (rc == 0 || okCodes.Contains(rc)) return;
        throw new WfpException(rc);
    }
}

public sealed class WfpException(uint code) : Exception($"Windows Filtering Platform error 0x{code:X8}.")
{
    public uint Code { get; } = code;
}

internal sealed class WfpEngine : IDisposable
{
    public IntPtr Handle { get; private set; }

    public static WfpEngine Open()
    {
        var session = new FWPM_SESSION0 { txnWaitTimeoutInMSec = 15_000 };
        WfpFirewall.Check(WfpApi.FwpmEngineOpen0(null, RPC_C_AUTHN_WINNT, IntPtr.Zero, ref session, out var h));
        return new WfpEngine { Handle = h };
    }

    public void InTransaction(Action body)
    {
        WfpFirewall.Check(WfpApi.FwpmTransactionBegin0(Handle, 0));
        try
        {
            body();
            WfpFirewall.Check(WfpApi.FwpmTransactionCommit0(Handle));
        }
        catch
        {
            WfpApi.FwpmTransactionAbort0(Handle); // nothing changes: the previous (locked) filters stay
            throw;
        }
    }

    public void Dispose()
    {
        if (Handle != IntPtr.Zero) WfpApi.FwpmEngineClose0(Handle);
        Handle = IntPtr.Zero;
    }
}

internal sealed class NativeString(string s) : IDisposable
{
    public IntPtr Ptr { get; } = Marshal.StringToHGlobalUni(s);
    public void Dispose() => Marshal.FreeHGlobal(Ptr);
}

public sealed class SecurityDescriptorHandle : IDisposable
{
    public IntPtr Ptr { get; private init; }

    public static SecurityDescriptorHandle FromSddl(string? sddl)
    {
        if (sddl is null) return new SecurityDescriptorHandle { Ptr = IntPtr.Zero }; // Windows' default descriptor
        if (!SecurityApi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out var sd, out _))
            throw new System.ComponentModel.Win32Exception();
        return new SecurityDescriptorHandle { Ptr = sd };
    }

    public void Dispose()
    {
        if (Ptr != IntPtr.Zero) SecurityApi.LocalFree(Ptr);
    }
}

/// <summary>Unmanaged allocations that live for one native call.</summary>
internal sealed class NativeArena : IDisposable
{
    private readonly List<IntPtr> _allocs = new();

    public IntPtr Bytes(byte[] data)
    {
        var p = Marshal.AllocHGlobal(data.Length);
        Marshal.Copy(data, 0, p, data.Length);
        _allocs.Add(p);
        return p;
    }

    public IntPtr Struct<T>(T value) where T : struct
    {
        var p = Marshal.AllocHGlobal(Marshal.SizeOf<T>());
        Marshal.StructureToPtr(value, p, false);
        _allocs.Add(p);
        return p;
    }

    public IntPtr Array<T>(IReadOnlyList<T> items) where T : struct
    {
        if (items.Count == 0) return IntPtr.Zero;
        var size = Marshal.SizeOf<T>();
        var p = Marshal.AllocHGlobal(size * items.Count);
        for (int i = 0; i < items.Count; i++) Marshal.StructureToPtr(items[i], p + i * size, false);
        _allocs.Add(p);
        return p;
    }

    public void Dispose()
    {
        foreach (var p in _allocs) Marshal.FreeHGlobal(p);
        _allocs.Clear();
    }
}
