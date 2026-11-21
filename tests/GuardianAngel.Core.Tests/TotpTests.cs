using GuardianAngel.Core.Model;
using GuardianAngel.Core.Totp;
using T = GuardianAngel.Core.Totp.Totp;

namespace GuardianAngel.Core.Tests;

public class TotpTests
{
    private static readonly byte[] RfcSecret = "12345678901234567890"u8.ToArray();

    [Theory] // RFC 6238 Appendix B (SHA-1), last 6 digits of the 8-digit vectors
    [InlineData(59, "287082")]
    [InlineData(1111111109, "081804")]
    [InlineData(1111111111, "050471")]
    [InlineData(1234567890, "005924")]
    [InlineData(2000000000, "279037")]
    public void Matches_rfc6238_vectors(long unix, string expected) =>
        Assert.Equal(expected, T.Code(RfcSecret, T.StepAt(DateTimeOffset.FromUnixTimeSeconds(unix))));

    [Fact]
    public void Base32_round_trips()
    {
        var data = T.NewSecret();
        Assert.Equal(data, Base32.Decode(Base32.Encode(data)));
        Assert.Equal("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", Base32.Encode(RfcSecret));
    }

    [Fact]
    public void Accepts_plus_minus_one_step_only()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var step = T.StepAt(now);
        foreach (var (delta, ok) in new[] { (-2, false), (-1, true), (0, true), (1, true), (2, false) })
        {
            var p = new PartnerState { Secret = RfcSecret };
            var r = PartnerVerifier.Verify(p, T.Code(RfcSecret, step + delta), now);
            Assert.Equal(ok ? CodeResult.Accepted : CodeResult.Wrong, r);
        }
    }

    [Fact]
    public void A_code_can_be_used_only_once()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var p = new PartnerState { Secret = RfcSecret };
        var code = T.Code(RfcSecret, T.StepAt(now));
        Assert.Equal(CodeResult.Accepted, PartnerVerifier.Verify(p, code, now));
        Assert.Equal(CodeResult.Wrong, PartnerVerifier.Verify(p, code, now));
        // An older step is also refused after a newer one was used.
        Assert.Equal(CodeResult.Wrong, PartnerVerifier.Verify(p, T.Code(RfcSecret, T.StepAt(now) - 1), now));
    }

    [Fact]
    public void Five_wrong_codes_lock_out_for_an_hour()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var p = new PartnerState { Secret = RfcSecret };
        for (int i = 0; i < 4; i++) Assert.Equal(CodeResult.Wrong, PartnerVerifier.Verify(p, "000000", now));
        Assert.Equal(CodeResult.LockedOut, PartnerVerifier.Verify(p, "000000", now));
        // Even the right code is refused during the lockout.
        Assert.Equal(CodeResult.LockedOut, PartnerVerifier.Verify(p, T.Code(RfcSecret, T.StepAt(now)), now));
        PartnerVerifier.CountDownLockout(p, (long)TimeSpan.FromMinutes(59).TotalMilliseconds);
        Assert.Equal(CodeResult.LockedOut, PartnerVerifier.Verify(p, T.Code(RfcSecret, T.StepAt(now)), now));
        PartnerVerifier.CountDownLockout(p, (long)TimeSpan.FromMinutes(1).TotalMilliseconds);
        Assert.Equal(CodeResult.Accepted, PartnerVerifier.Verify(p, T.Code(RfcSecret, T.StepAt(now)), now));
    }

    [Theory]
    [InlineData("12345")]
    [InlineData("abcdef")]
    [InlineData("")]
    [InlineData(null)]
    public void Malformed_codes_count_as_failures(string? code)
    {
        var p = new PartnerState { Secret = RfcSecret };
        Assert.Equal(CodeResult.Malformed, PartnerVerifier.Verify(p, code, DateTimeOffset.UtcNow));
        Assert.Equal(1, p.FailedAttempts);
    }

    [Fact]
    public void OtpAuth_uri_has_the_standard_shape()
    {
        var uri = T.OtpAuthUri(RfcSecret);
        Assert.StartsWith("otpauth://totp/", uri);
        Assert.Contains("secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", uri);
        Assert.Contains("issuer=Guardian%20Angel", uri);
    }
}
