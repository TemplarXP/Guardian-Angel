using System.IO.Pipes;
using GuardianAngel.Core.Model;

namespace GuardianAngel.Core.Ipc;

/// <summary>Used by the UI and the uninstall gate. One connection per call keeps things simple and robust.</summary>
public sealed class IpcClient(string pipeName = Framing.PipeName)
{
    public async Task<IpcResponse> CallAsync(string op, object? body = null, CancellationToken ct = default, int timeoutMs = 30_000)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);
        await using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await pipe.ConnectAsync(5_000, cts.Token);
        var req = new IpcRequest(Framing.ProtocolVersion, op, body is null ? null : Json.ToElement(body));
        await Framing.WriteAsync(pipe, req, cts.Token);
        return await Framing.ReadAsync<IpcResponse>(pipe, cts.Token) ?? IpcResponse.Fail("No response from the service.");
    }

    public async Task<T> CallAsync<T>(string op, object? body = null, CancellationToken ct = default, int timeoutMs = 30_000)
    {
        var r = await CallAsync(op, body, ct, timeoutMs);
        if (!r.Ok) throw new IpcException(r.Error ?? "The service refused the request.");
        return Json.FromElement<T>(r.Body)!;
    }
}

public sealed class IpcException(string message) : Exception(message);
