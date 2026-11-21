using System.Runtime.InteropServices;
using GuardianAngel.Platform.Windows.Native;

namespace GuardianAngel.Windows.Tests;

/// <summary>Struct layouts must match the 64-bit C headers exactly, or WFP calls would corrupt memory.</summary>
public class InteropLayoutTests
{
    [Fact]
    public void FWPM_FILTER0_matches_the_x64_header()
    {
        Assert.Equal(200, Marshal.SizeOf<FWPM_FILTER0>());
        Assert.Equal(16, (int)Marshal.OffsetOf<FWPM_FILTER0>("displayData"));
        Assert.Equal(32, (int)Marshal.OffsetOf<FWPM_FILTER0>("flags"));
        Assert.Equal(40, (int)Marshal.OffsetOf<FWPM_FILTER0>("providerKey"));
        Assert.Equal(48, (int)Marshal.OffsetOf<FWPM_FILTER0>("providerData"));
        Assert.Equal(64, (int)Marshal.OffsetOf<FWPM_FILTER0>("layerKey"));
        Assert.Equal(80, (int)Marshal.OffsetOf<FWPM_FILTER0>("subLayerKey"));
        Assert.Equal(96, (int)Marshal.OffsetOf<FWPM_FILTER0>("weight"));
        Assert.Equal(112, (int)Marshal.OffsetOf<FWPM_FILTER0>("numFilterConditions"));
        Assert.Equal(120, (int)Marshal.OffsetOf<FWPM_FILTER0>("filterCondition"));
        Assert.Equal(128, (int)Marshal.OffsetOf<FWPM_FILTER0>("action"));
        Assert.Equal(152, (int)Marshal.OffsetOf<FWPM_FILTER0>("context"));
        Assert.Equal(168, (int)Marshal.OffsetOf<FWPM_FILTER0>("reserved"));
        Assert.Equal(176, (int)Marshal.OffsetOf<FWPM_FILTER0>("filterId"));
        Assert.Equal(184, (int)Marshal.OffsetOf<FWPM_FILTER0>("effectiveWeight"));
    }

    [Fact]
    public void Other_wfp_structs_match()
    {
        Assert.Equal(40, Marshal.SizeOf<FWPM_FILTER_CONDITION0>());
        Assert.Equal(24, (int)Marshal.OffsetOf<FWPM_FILTER_CONDITION0>("conditionValue"));
        Assert.Equal(16, Marshal.SizeOf<FWP_VALUE0>());
        Assert.Equal(20, Marshal.SizeOf<FWPM_ACTION0>());
        Assert.Equal(72, Marshal.SizeOf<FWPM_SUBLAYER0>());
        Assert.Equal(64, (int)Marshal.OffsetOf<FWPM_SUBLAYER0>("weight"));
        Assert.Equal(64, Marshal.SizeOf<FWPM_PROVIDER0>());
        Assert.Equal(72, Marshal.SizeOf<FWPM_SESSION0>());
    }

    [Fact]
    public void DNS_INTERFACE_SETTINGS_matches()
    {
        Assert.Equal(64, Marshal.SizeOf<DNS_INTERFACE_SETTINGS>());
        Assert.Equal(8, (int)Marshal.OffsetOf<DNS_INTERFACE_SETTINGS>("Flags"));
        Assert.Equal(16, (int)Marshal.OffsetOf<DNS_INTERFACE_SETTINGS>("Domain"));
        Assert.Equal(40, (int)Marshal.OffsetOf<DNS_INTERFACE_SETTINGS>("RegistrationEnabled"));
        Assert.Equal(56, (int)Marshal.OffsetOf<DNS_INTERFACE_SETTINGS>("ProfileNameServer"));
    }
}
