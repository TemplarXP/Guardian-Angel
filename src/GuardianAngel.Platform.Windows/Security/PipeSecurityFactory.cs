using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using GuardianAngel.Core.Ipc;

namespace GuardianAngel.Platform.Windows.Security;

public static class PipeSecurityFactory
{
    /// <summary>
    /// The UI pipe: SYSTEM full control; signed-in (interactive) users may connect and talk; network logons are denied.
    /// Any local user may ASK; the service decides.
    /// </summary>
    public static NamedPipeServerStream CreateUiPipe(string name = Framing.PipeName)
    {
        var sec = new PipeSecurity();
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.InteractiveSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
        return NamedPipeServerStreamAcl.Create(name, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 64 * 1024, 64 * 1024, sec);
    }

    /// <summary>The watchdog pipe: SYSTEM only.</summary>
    public static NamedPipeServerStream CreateSystemOnlyPipe(string name)
    {
        var sec = new PipeSecurity();
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        return NamedPipeServerStreamAcl.Create(name, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 4096, 4096, sec);
    }
}
