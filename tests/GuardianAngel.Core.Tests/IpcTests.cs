using System.IO.Pipes;
using GuardianAngel.Core.Ipc;

namespace GuardianAngel.Core.Tests;

public class IpcTests
{
    [Fact]
    public async Task Client_and_server_round_trip_over_a_named_pipe()
    {
        var h = await new Harness().StartAsync();
        var name = "ga-test-" + Guid.NewGuid().ToString("N")[..8];
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var server = new IpcServer(
            () => new NamedPipeServerStream(name, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte, PipeOptions.Asynchronous),
            (req, _) => h.Engine.HandleAsync(req, cts.Token));
        var run = server.RunAsync(cts.Token);

        var client = new IpcClient(name);
        var status = await client.CallAsync<StatusDto>(Ops.GetStatus, ct: cts.Token);
        Assert.False(status.IsLocked);

        var bad = await client.CallAsync("no.such.op", ct: cts.Token);
        Assert.False(bad.Ok);

        cts.Cancel();
        await run;
    }
}
