using System.Diagnostics;
using System.Windows.Controls;
using System.Windows.Navigation;

namespace GuardianAngel.App.Views;

public partial class AboutView : UserControl
{
    public AboutView()
    {
        InitializeComponent();
        VersionText.Text = $"Version {typeof(AboutView).Assembly.GetName().Version}";
    }

    private void Link_RequestNavigate(object sender, RequestNavigateEventArgs e)
    {
        Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) { UseShellExecute = true });
        e.Handled = true;
    }
}
