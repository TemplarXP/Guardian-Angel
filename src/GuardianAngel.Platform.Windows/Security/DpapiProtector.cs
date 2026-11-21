using System.Security.Cryptography;
using GuardianAngel.Core.State;

namespace GuardianAngel.Platform.Windows.Security;

/// <summary>
/// DPAPI in USER scope, called by the service running as LocalSystem. Only code running as SYSTEM can decrypt.
/// (Machine scope would let any process of any user on the PC decrypt the data.)
/// </summary>
public sealed class DpapiProtector : IDataProtector
{
    private static readonly byte[] Entropy = "GuardianAngel/state/v1"u8.ToArray();

    public byte[] Protect(byte[] plain) => ProtectedData.Protect(plain, Entropy, DataProtectionScope.CurrentUser);
    public byte[] Unprotect(byte[] cipher) => ProtectedData.Unprotect(cipher, Entropy, DataProtectionScope.CurrentUser);
}
