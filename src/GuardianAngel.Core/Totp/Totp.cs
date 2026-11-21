using System.Security.Cryptography;
using GuardianAngel.Core.Model;
using GuardianAngel.Core.Policy;

namespace GuardianAngel.Core.Totp;

/// <summary>RFC 6238 TOTP: HMAC-SHA1, 6 digits, 30-second steps (what every authenticator app uses).</summary>
public static class Totp
{
    public const int Digits = 6;
    public const int StepSeconds = 30;
    public const int SecretBytes = 20; // 160 bits, as recommended by RFC 4226

    public static byte[] NewSecret() => RandomNumberGenerator.GetBytes(SecretBytes);

    public static long StepAt(DateTimeOffset utc) => utc.ToUnixTimeSeconds() / StepSeconds;

    public static string Code(byte[] secret, long step)
    {
        Span<byte> counter = stackalloc byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(counter, step);
        Span<byte> hash = stackalloc byte[20];
        HMACSHA1.HashData(secret, counter, hash);
        int offset = hash[^1] & 0x0F;
        int binary = ((hash[offset] & 0x7F) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
        return (binary % 1_000_000).ToString("D6");
    }

    public static string OtpAuthUri(byte[] secret, string account = "Accountability partner") =>
        $"otpauth://totp/{Uri.EscapeDataString("Guardian Angel:" + account)}?secret={Base32.Encode(secret)}" +
        $"&issuer={Uri.EscapeDataString("Guardian Angel")}&algorithm=SHA1&digits={Digits}&period={StepSeconds}";
}

public enum CodeResult { Accepted, Wrong, LockedOut, NoPartner, Malformed }

/// <summary>
/// Verifies partner codes: ±1 step window, each step accepted at most once, 5 wrong tries = 1 hour lockout
/// (counted on the monotonic clock, so neither reboots nor clock changes shorten it).
/// </summary>
public static class PartnerVerifier
{
    public static CodeResult Verify(PartnerState? partner, string? code, DateTimeOffset nowUtc)
    {
        if (partner is null) return CodeResult.NoPartner;
        if (partner.LockoutRemainingMs > 0) return CodeResult.LockedOut;

        code = code?.Replace(" ", "").Trim();
        if (code is null || code.Length != Totp.Digits || !code.All(char.IsAsciiDigit))
            return RegisterFailure(partner, CodeResult.Malformed);

        var now = Totp.StepAt(nowUtc);
        var expected = System.Text.Encoding.ASCII.GetBytes(code);
        long? matched = null;
        for (long step = now - 1; step <= now + 1; step++)
        {
            var candidate = System.Text.Encoding.ASCII.GetBytes(Totp.Code(partner.Secret, step));
            // Constant-time compare, and check every step (no early exit) to avoid timing leaks.
            if (CryptographicOperations.FixedTimeEquals(candidate, expected) && step > partner.LastUsedStep)
                matched ??= step;
        }

        if (matched is null) return RegisterFailure(partner, CodeResult.Wrong);
        partner.LastUsedStep = matched.Value;
        partner.FailedAttempts = 0;
        return CodeResult.Accepted;
    }

    private static CodeResult RegisterFailure(PartnerState p, CodeResult r)
    {
        p.FailedAttempts++;
        if (p.FailedAttempts >= Limits.MaxFailedCodes)
        {
            p.FailedAttempts = 0;
            p.LockoutRemainingMs = (long)Limits.CodeLockout.TotalMilliseconds;
            return CodeResult.LockedOut;
        }
        return r;
    }

    public static void CountDownLockout(PartnerState? p, long elapsedMs)
    {
        if (p is null || elapsedMs <= 0 || p.LockoutRemainingMs <= 0) return;
        p.LockoutRemainingMs = Math.Max(0, p.LockoutRemainingMs - elapsedMs);
    }
}
