namespace GuardianAngel.Core.Model;

public enum EncryptionMode
{
    /// <summary>Plain DNS on port 53. Works everywhere, but a network device could intercept it.</summary>
    None = 0,
    /// <summary>DNS over HTTPS using Windows 11's built-in client. Recommended.</summary>
    Doh = 1,
    /// <summary>DNS over TLS (only on Windows builds that support it natively).</summary>
    Dot = 2,
}

public enum UnreachableBehavior
{
    /// <summary>If no filter server answers, block all internet access (fail closed).</summary>
    BlockInternet = 0,
    /// <summary>If the primary server fails, use only the locked fallback servers. Never anything else.</summary>
    FallbackOnly = 1,
}

public enum Direction
{
    /// <summary>Makes protection stronger: applied immediately.</summary>
    Tighten,
    /// <summary>Makes protection weaker: must wait out the delay (or get a partner code).</summary>
    Loosen,
}

public enum ChangeStatus
{
    Pending,
    Applying,
    Applied,
    Cancelled,
    Superseded,
    Failed,
}
