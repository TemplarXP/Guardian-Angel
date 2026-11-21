using System.Windows;
using GuardianAngel.App.Services;
using GuardianAngel.App.Views;

namespace GuardianAngel.App;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        Loaded += async (_, _) => await ShowStartAsync();
    }

    public async Task ShowStartAsync()
    {
        var status = await ServiceClient.TryStatus();
        if (status is null)
        {
            Body.Content = new MessageView("Can't reach the Guardian Angel service",
                "The service may still be starting. If this keeps happening, restart the PC. Your protection stays on either way.",
                "Try again", async () => await ShowStartAsync());
            return;
        }
        DebugBanner.Visibility = status.IsDebugBuild ? Visibility.Visible : Visibility.Collapsed;

        if (status.IsLocked) { Body.Content = new HomeView(this); return; }
        if (!UiSettings.GuideSeen)
        {
            Body.Content = new GuideView(firstRun: true, onDone: () => { UiSettings.GuideSeen = true; Body.Content = new WizardView(this); });
            return;
        }
        Body.Content = new WizardView(this);
    }

    private async void NavHome_Click(object sender, RoutedEventArgs e) => await ShowStartAsync();
    private void NavLearn_Click(object sender, RoutedEventArgs e) => Body.Content = new GuideView(firstRun: false, onDone: null);
    private void NavAbout_Click(object sender, RoutedEventArgs e) => Body.Content = new AboutView();
}
