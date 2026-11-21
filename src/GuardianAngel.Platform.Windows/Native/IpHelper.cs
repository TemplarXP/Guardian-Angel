using System.Runtime.InteropServices;

namespace GuardianAngel.Platform.Windows.Native;

/// <summary>DNS_INTERFACE_SETTINGS (netioapi.h), Windows 10 2004+.</summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct DNS_INTERFACE_SETTINGS
{
    public uint Version;
    public ulong Flags;
    public IntPtr Domain;
    public IntPtr NameServer;
    public IntPtr SearchList;
    public uint RegistrationEnabled;
    public uint RegisterAdapterName;
    public uint EnableLLMNR;
    public uint QueryAdapterName;
    public IntPtr ProfileNameServer;
}

internal static class IpHelperApi
{
    public const uint DNS_INTERFACE_SETTINGS_VERSION1 = 1;
    public const ulong DNS_SETTING_IPV6 = 0x0001;
    public const ulong DNS_SETTING_NAMESERVER = 0x0002;

    [DllImport("iphlpapi.dll")]
    public static extern uint SetInterfaceDnsSettings(Guid interfaceGuid, ref DNS_INTERFACE_SETTINGS settings);

    [DllImport("dnsapi.dll", EntryPoint = "DnsFlushResolverCache")]
    public static extern bool DnsFlushResolverCache();
}
