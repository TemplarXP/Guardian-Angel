using System.Runtime.InteropServices;

namespace GuardianAngel.Platform.Windows.Native;

// Windows Filtering Platform (fwpuclnt.dll) interop. Layouts match the x64/ARM64 C headers (fwpmtypes.h, fwptypes.h).
// Field offsets of FWPM_FILTER0 are asserted in GuardianAngel.Windows.Tests.

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_DISPLAY_DATA0 { public IntPtr name; public IntPtr description; }

[StructLayout(LayoutKind.Sequential)]
internal struct FWP_BYTE_BLOB { public uint size; public IntPtr data; }

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_SESSION0
{
    public Guid sessionKey;
    public FWPM_DISPLAY_DATA0 displayData;
    public uint flags;
    public uint txnWaitTimeoutInMSec;
    public uint processId;
    public IntPtr sid;
    public IntPtr username;
    public int kernelMode;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_PROVIDER0
{
    public Guid providerKey;
    public FWPM_DISPLAY_DATA0 displayData;
    public uint flags;
    public FWP_BYTE_BLOB providerData;
    public IntPtr serviceName;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_SUBLAYER0
{
    public Guid subLayerKey;
    public FWPM_DISPLAY_DATA0 displayData;
    public uint flags;
    public IntPtr providerKey;
    public FWP_BYTE_BLOB providerData;
    public ushort weight;
}

/// <summary>FWP_VALUE0 / FWP_CONDITION_VALUE0: a type tag followed by an 8-byte union.</summary>
[StructLayout(LayoutKind.Explicit, Size = 16)]
internal struct FWP_VALUE0
{
    [FieldOffset(0)] public uint type;
    [FieldOffset(8)] public ulong uint64;
    [FieldOffset(8)] public IntPtr pointer;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_FILTER_CONDITION0
{
    public Guid fieldKey;
    public uint matchType;
    public FWP_VALUE0 conditionValue;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_ACTION0
{
    public uint type;
    public Guid filterTypeOrCalloutKey;
}

[StructLayout(LayoutKind.Explicit, Size = 16)]
internal struct FWPM_FILTER0_CONTEXT
{
    [FieldOffset(0)] public ulong rawContext;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_FILTER0
{
    public Guid filterKey;
    public FWPM_DISPLAY_DATA0 displayData;
    public uint flags;
    public IntPtr providerKey;
    public FWP_BYTE_BLOB providerData;
    public Guid layerKey;
    public Guid subLayerKey;
    public FWP_VALUE0 weight;
    public uint numFilterConditions;
    public IntPtr filterCondition;
    public FWPM_ACTION0 action;
    public FWPM_FILTER0_CONTEXT context;
    public IntPtr reserved;
    public ulong filterId;
    public FWP_VALUE0 effectiveWeight;
}

internal static class WfpConst
{
    public const uint RPC_C_AUTHN_WINNT = 10;

    public const uint FWP_EMPTY = 0, FWP_UINT8 = 1, FWP_UINT16 = 2, FWP_UINT32 = 3, FWP_BYTE_ARRAY16_TYPE = 11;
    public const uint FWP_MATCH_EQUAL = 0, FWP_MATCH_FLAGS_ALL_SET = 6;
    public const uint FWP_ACTION_FLAG_TERMINATING = 0x00001000;
    public const uint FWP_ACTION_BLOCK = 0x1 | FWP_ACTION_FLAG_TERMINATING;
    public const uint FWP_ACTION_PERMIT = 0x2 | FWP_ACTION_FLAG_TERMINATING;

    public const uint FWPM_FILTER_FLAG_PERSISTENT = 0x1;
    public const uint FWPM_FILTER_FLAG_BOOTTIME = 0x2;
    public const uint FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT = 0x8;
    public const uint FWPM_PROVIDER_FLAG_PERSISTENT = 0x1;
    public const uint FWPM_SUBLAYER_FLAG_PERSISTENT = 0x1;
    public const uint FWP_CONDITION_FLAG_IS_LOOPBACK = 0x1;

    public const uint FWP_E_FILTER_NOT_FOUND = 0x80320003;
    public const uint FWP_E_PROVIDER_NOT_FOUND = 0x80320005;
    public const uint FWP_E_SUBLAYER_NOT_FOUND = 0x80320007;
    public const uint FWP_E_ALREADY_EXISTS = 0x80320009;
    public const uint FWP_E_IN_USE = 0x8032000A;

    public static readonly Guid FWPM_LAYER_ALE_AUTH_CONNECT_V4 = new("c38d57d1-05a7-4c33-904f-7fbceee60e82");
    public static readonly Guid FWPM_LAYER_ALE_AUTH_CONNECT_V6 = new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
    public static readonly Guid FWPM_CONDITION_IP_REMOTE_ADDRESS = new("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
    public static readonly Guid FWPM_CONDITION_IP_REMOTE_PORT = new("c35a604d-d22b-4e1a-91b4-68f674ee674b");
    public static readonly Guid FWPM_CONDITION_IP_PROTOCOL = new("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7");
    public static readonly Guid FWPM_CONDITION_FLAGS = new("632ce23b-5167-435c-86d7-e903684aa80c");
}

internal static class WfpApi
{
    private const string Dll = "fwpuclnt.dll";

    [DllImport(Dll, CharSet = CharSet.Unicode)]
    public static extern uint FwpmEngineOpen0(string? serverName, uint authnService, IntPtr authIdentity, ref FWPM_SESSION0 session, out IntPtr engineHandle);
    [DllImport(Dll)] public static extern uint FwpmEngineClose0(IntPtr engineHandle);
    [DllImport(Dll)] public static extern uint FwpmTransactionBegin0(IntPtr engineHandle, uint flags);
    [DllImport(Dll)] public static extern uint FwpmTransactionCommit0(IntPtr engineHandle);
    [DllImport(Dll)] public static extern uint FwpmTransactionAbort0(IntPtr engineHandle);
    [DllImport(Dll)] public static extern uint FwpmProviderAdd0(IntPtr engineHandle, ref FWPM_PROVIDER0 provider, IntPtr sd);
    [DllImport(Dll)] public static extern uint FwpmProviderDeleteByKey0(IntPtr engineHandle, ref Guid key);
    [DllImport(Dll)] public static extern uint FwpmSubLayerAdd0(IntPtr engineHandle, ref FWPM_SUBLAYER0 subLayer, IntPtr sd);
    [DllImport(Dll)] public static extern uint FwpmSubLayerDeleteByKey0(IntPtr engineHandle, ref Guid key);
    [DllImport(Dll)] public static extern uint FwpmSubLayerGetByKey0(IntPtr engineHandle, ref Guid key, out IntPtr subLayer);
    [DllImport(Dll)] public static extern uint FwpmFilterAdd0(IntPtr engineHandle, ref FWPM_FILTER0 filter, IntPtr sd, out ulong id);
    [DllImport(Dll)] public static extern uint FwpmFilterDeleteByKey0(IntPtr engineHandle, ref Guid key);
    [DllImport(Dll)] public static extern uint FwpmFilterGetByKey0(IntPtr engineHandle, ref Guid key, out IntPtr filter);
    [DllImport(Dll)] public static extern void FwpmFreeMemory0(ref IntPtr p);
}

internal static class SecurityApi
{
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint revision, out IntPtr sd, out uint size);

    [DllImport("kernel32.dll")]
    public static extern IntPtr LocalFree(IntPtr mem);
}
