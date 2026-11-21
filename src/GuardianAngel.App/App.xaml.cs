using System.Windows;

namespace GuardianAngel.App;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        // "Settings > Apps > Uninstall" runs this app with --uninstall (see the installer).
        Window w = e.Args.Contains("--uninstall", StringComparer.OrdinalIgnoreCase) ? new Views.UninstallGateWindow() : new MainWindow();
        MainWindow = w;
        w.Show();
    }
}
