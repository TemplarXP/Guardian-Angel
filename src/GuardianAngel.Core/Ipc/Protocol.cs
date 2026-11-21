using System.Buffers.Binary;
using System.Text.Json;
using GuardianAngel.Core.Model;

namespace GuardianAngel.Core.Ipc;

/// <summary>Wire format: 4-byte little-endian length, then UTF-8 JSON. One request, one response.</summary>
public static class Framing
{
    public const int MaxMessageBytes = 1 << 20;
    public const string PipeName = "GuardianAngel";
    public const int ProtocolVersion = 1;

    public static async Task WriteAsync<T>(Stream s, T message, CancellationToken ct)
    {
        var body = JsonSerializer.SerializeToUtf8Bytes(message, Json.Options);
        if (body.Length > MaxMessageBytes) throw new InvalidDataException("Message too large.");
        var header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, body.Length);
        await s.WriteAsync(header, ct);
        await s.WriteAsync(body, ct);
        await s.FlushAsync(ct);
    }

    public static async Task<T?> ReadAsync<T>(Stream s, CancellationToken ct)
    {
        var header = new byte[4];
        try { await s.ReadExactlyAsync(header, ct); }
        catch (EndOfStreamException) { return default; }
        var len = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (len <= 0 || len > MaxMessageBytes) throw new InvalidDataException("Bad message length.");
        var body = new byte[len];
        await s.ReadExactlyAsync(body, ct);
        return JsonSerializer.Deserialize<T>(body, Json.Options);
    }
}

public sealed record IpcRequest(int V, string Op, JsonElement? Body = null);

public sealed record IpcResponse(bool Ok, string? Error = null, JsonElement? Body = null)
{
    public static IpcResponse Success<T>(T body) => new(true, null, Json.ToElement(body));
    public static IpcResponse Success() => new(true);
    public static IpcResponse Fail(string error) => new(false, error);
}

/// <summary>Operation names. The service validates every one; the UI is never trusted.</summary>
public static class Ops
{
    public const string GetStatus = "status.get";

    // Setup (only before Lock)
    public const string TestFilter = "setup.testFilter";
    public const string PartnerBegin = "setup.partnerBegin";
    public const string PartnerConfirm = "setup.partnerConfirm";
    public const string PartnerClear = "setup.partnerClear";
    public const string Lock = "setup.lock";

    // Locked
    public const string PreviewChange = "change.preview";
    public const string RequestChange = "change.request";
    public const string CancelChange = "change.cancel";
    public const string Expedite = "change.expedite";

    // Uninstall gate
    public const string UninstallStatus = "uninstall.status";
}
