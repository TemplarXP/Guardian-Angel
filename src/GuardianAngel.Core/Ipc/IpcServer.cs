using System.IO.Pipes;

namespace GuardianAngel.Core.Ipc;

/// <summary>
/// Accepts connections and hands each request to a handler. The pipe factory lets the Windows
/// service create the pipe with a strict ACL; tests use a plain pipe.
/// </summary>
public sealed class IpcServer(Func<NamedPipeServerStream> pipeFactory, Func<IpcRequest, NamedPipeServerStream, Task<IpcResponse>> handler,
    Action<Exception>? onError = null)
{
    public async Task RunAsync(CancellationToken ct)
    {
        var clients = new List<Task>();
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream pipe;
            try
            {
                pipe = pipeFactory();
                await pipe.WaitForConnectionAsync(ct);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) { onError?.Invoke(ex); await Task.Delay(500, ct).ContinueWith(_ => { }); continue; }

            clients.Add(HandleAsync(pipe, ct));
            clients.RemoveAll(t => t.IsCompleted);
        }
        await Task.WhenAll(clients);
    }

    private async Task HandleAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        await using (pipe)
        {
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(60));
                var req = await Framing.ReadAsync<IpcRequest>(pipe, cts.Token);
                if (req is null) return;
                IpcResponse resp;
                if (req.V != Framing.ProtocolVersion) resp = IpcResponse.Fail("Please update Guardian Angel: the app and service versions don't match.");
                else
                {
                    try { resp = await handler(req, pipe); }
                    catch (Exception ex) { onError?.Invoke(ex); resp = IpcResponse.Fail("Something went wrong in the service. Nothing was loosened."); }
                }
                await Framing.WriteAsync(pipe, resp, cts.Token);
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or InvalidDataException or System.Text.Json.JsonException)
            {
                onError?.Invoke(ex);
            }
        }
    }
}
