using System.Windows;
using GuardianAngel.App.Services;
using GuardianAngel.Core.Engine;
using GuardianAngel.Core.Ipc;

namespace GuardianAngel.App.Views;

public partial class ExpediteWindow : Window
{
    private readonly Guid _id;

    public ExpediteWindow(Guid id)
    {
        InitializeComponent();
        _id = id;
        Loaded += (_, _) => CodeBox.Focus();
    }

    private async void Apply_Click(object sender, RoutedEventArgs e)
    {
        ApplyButton.IsEnabled = false;
        try
        {
            var r = await ServiceClient.Call<ExpediteResult>(Ops.Expedite, new ExpediteRequest(_id, CodeBox.Text.Trim()));
            ResultText.Text = r.Result switch
            {
                "Accepted" => "Code accepted. The change has been applied.",
                "LockedOut" => $"Too many wrong codes. Try again in {DelayMath.Countdown(r.LockoutRemainingMs)}.",
                "NoPartner" => "You don't have an accountability partner.",
                _ => "That code didn't match. Codes change every 30 seconds; use the newest one.",
            };
            if (r.Result == "Accepted") ApplyButton.Visibility = Visibility.Collapsed;
        }
        catch (Exception ex) { ResultText.Text = ex.Message; }
        finally { ApplyButton.IsEnabled = true; }
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
