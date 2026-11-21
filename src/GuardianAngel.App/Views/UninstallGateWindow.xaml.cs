using System.Diagnostics;
using System.Windows;
using GuardianAngel.App.Services;
using GuardianAngel.Core.Ipc;

namespace GuardianAngel.App.Views;

/// <summary>
/// Settings > Apps > Uninstall opens this. Uninstalling is a queued change: when it's due, the SERVICE removes
/// Guardian Angel by itself. This window never uninstalls anything.
/// </summary>
public partial class UninstallGateWindow : Window
{
    public UninstallGateWindow()
    {
        InitializeComponent();
        Loaded += async (_, _) =>
        {
            try
            {
                var s = await ServiceClient.Call<UninstallStatusDto>(Ops.UninstallStatus);
                MessageText.Text = s.Allowed
                    ? "Guardian Angel isn't locked, so you can uninstall it. Use \"Remove\" in the installer, or ask your administrator."
                    : s.Message;
                OpenAppButton.Visibility = s.Allowed ? Visibility.Collapsed : Visibility.Visible;
            }
            catch (Exception)
            {
                MessageText.Text = "The Guardian Angel service didn't answer. Uninstalling isn't possible until it's running and an uninstall is due.";
            }
        };
    }

    private void OpenApp_Click(object sender, RoutedEventArgs e)
    {
        Process.Start(new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = true });
        Close();
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
