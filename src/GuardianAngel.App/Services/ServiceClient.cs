using System.IO;
using GuardianAngel.Core.Ipc;

namespace GuardianAngel.App.Services;

/// <summary>Talks to the Guardian Angel service. The app never makes decisions itself.</summary>
public static class ServiceClient
{
    private static readonly IpcClient Client = new();

    public static Task<T> Call<T>(string op, object? body = null, int timeoutMs = 30_000) => Client.CallAsync<T>(op, body, timeoutMs: timeoutMs);
    public static Task<IpcResponse> Call(string op, object? body = null, int timeoutMs = 30_000) => Client.CallAsync(op, body, timeoutMs: timeoutMs);

    public static async Task<StatusDto?> TryStatus()
    {
        try { return await Call<StatusDto>(Ops.GetStatus, timeoutMs: 8_000); }
        catch (Exception) { return null; }
    }
}

/// <summary>Per-user conveniences only (never anything that matters for protection).</summary>
public static class UiSettings
{
    private static string FilePath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "GuardianAngel", "guide-seen");

    public static bool GuideSeen
    {
        get { try { return File.Exists(FilePath); } catch { return false; } }
        set
        {
            try { Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!); if (value) File.WriteAllText(FilePath, "1"); }
            catch { /* not important */ }
        }
    }
}
