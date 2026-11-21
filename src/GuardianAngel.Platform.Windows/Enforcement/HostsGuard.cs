using System.Text;
using GuardianAngel.Core.Hosts;
using GuardianAngel.Core.Ipc;
using Microsoft.Win32;

namespace GuardianAngel.Platform.Windows.Enforcement;

/// <summary>
/// Removes hosts-file lines that point a name at a real address (which would get around the filter),
/// and keeps Windows reading the hosts file from its normal place.
/// </summary>
public sealed class HostsGuard : IDisposable
{
    private const string TcpipParams = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";
    private const string DefaultDataBasePath = @"%SystemRoot%\System32\drivers\etc";
    private FileSystemWatcher? _watcher;

    public static string HostsPath => Path.Combine(Environment.SystemDirectory, "drivers", "etc", "hosts");

    public event Action? Changed;

    public void StartWatching()
    {
        if (_watcher is not null) return;
        _watcher = new FileSystemWatcher(Path.GetDirectoryName(HostsPath)!, "hosts")
        {
            NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size | NotifyFilters.Security,
            EnableRaisingEvents = true,
        };
        _watcher.Changed += (_, _) => Changed?.Invoke();
        _watcher.Created += (_, _) => Changed?.Invoke();
        _watcher.Renamed += (_, _) => Changed?.Invoke();
        _watcher.Deleted += (_, _) => Changed?.Invoke();
    }

    public (EnforcementItemDto Item, IReadOnlyList<string> Removed) Apply()
    {
        var removed = new List<string>();

        using (var k = Registry.LocalMachine.OpenSubKey(TcpipParams, writable: true))
        {
            var current = k?.GetValue("DataBasePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
            if (k is not null && !string.Equals(current, DefaultDataBasePath, StringComparison.OrdinalIgnoreCase))
            {
                k.SetValue("DataBasePath", DefaultDataBasePath, RegistryValueKind.ExpandString);
                removed.Add($"hosts location redirected to \"{current}\"");
            }
        }

        try
        {
            var content = File.Exists(HostsPath) ? ReadShared(HostsPath) : HostsAnalyzer.DefaultWindowsHosts;
            var result = HostsAnalyzer.Sanitize(content);
            if (result.Changed)
            {
                WriteWithRetry(HostsPath, result.SanitizedContent);
                removed.AddRange(result.RemovedLines);
            }
        }
        catch (IOException ex)
        {
            return (new EnforcementItemDto("Hosts file guard", false, "Couldn't check the hosts file: " + ex.Message), removed);
        }

        return (new EnforcementItemDto("Hosts file guard", true,
            removed.Count == 0 ? "No redirects in the hosts file." : $"Removed {removed.Count} redirect(s)."), removed);
    }

    private static string ReadShared(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var r = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        return r.ReadToEnd();
    }

    private static void WriteWithRetry(string path, string content)
    {
        for (int i = 0; ; i++)
        {
            try
            {
                var attrs = File.Exists(path) ? File.GetAttributes(path) : FileAttributes.Normal;
                if (attrs.HasFlag(FileAttributes.ReadOnly)) File.SetAttributes(path, attrs & ~FileAttributes.ReadOnly);
                File.WriteAllText(path, content, new UTF8Encoding(false));
                return;
            }
            catch (IOException) when (i < 5) { Thread.Sleep(200); }
        }
    }

    public void Dispose() => _watcher?.Dispose();
}
