using System.Text.Json;
using System.Windows;
using GuardianAngel.App.Services;
using GuardianAngel.Core.Engine;
using GuardianAngel.Core.Ipc;
using GuardianAngel.Core.Model;
using GuardianAngel.Core.Policy;

namespace GuardianAngel.App.Views;

public partial class RequestChangeWindow : Window
{
    private string _kind = "delay.change";
    private JsonElement _params;
    private ChangePreviewDto? _preview;

    public RequestChangeWindow(StatusDto status)
    {
        InitializeComponent();
        NewDelay.Value = status.Delay;
        NewDelayEnabled.IsChecked = status.DelayEnabled;
        NewDelayEnabled.IsEnabled = status.HasPartner;
        DelayHint.Text = $"Now: {DelayMath.Describe(status.DelayEnabled ? status.Delay : null)}. A longer delay applies immediately; a shorter one waits out the current delay.";
        if (status.Filter is not null) NewFilter.Load(status.Filter);
        KindPartner.IsEnabled = status.HasPartner;
    }

    private void Kind_Checked(object sender, RoutedEventArgs e)
    {
        if (DelayParams is null) return;
        DelayParams.Visibility = KindDelay.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        FilterParams.Visibility = KindFilter.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        UninstallParams.Visibility = KindUninstall.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
    }

    private async void Next_Click(object sender, RoutedEventArgs e)
    {
        ErrorText.Text = "";
        try
        {
            if (ChoosePanel.Visibility == Visibility.Visible) await PreviewAsync();
            else if (ReflectPanel.Visibility == Visibility.Visible) await SubmitAsync(_preview!.ConfirmationPhrase.Length > 0 ? PhraseBox.Text : "");
            else Close();
        }
        catch (Exception ex) { ErrorText.Text = ex.Message; }
    }

    private async Task PreviewAsync()
    {
        if (KindDelay.IsChecked == true)
        {
            var enabled = NewDelayEnabled.IsChecked == true;
            if (enabled && NewDelay.Value is null) { ErrorText.Text = "Enter a delay."; return; }
            _kind = "delay.change";
            _params = Json.ToElement(new DelayChangeParams(enabled, NewDelay.Value ?? TimeSpan.Zero));
        }
        else if (KindFilter.IsChecked == true)
        {
            var (f, errors) = NewFilter.Read();
            if (f is null) { ErrorText.Text = string.Join(" ", errors); return; }
            _kind = "filter.change";
            _params = Json.ToElement(f);
        }
        else
        {
            _kind = KindPartner.IsChecked == true ? "partner.remove" : "uninstall";
            _params = Json.ToElement(new { });
        }

        _preview = await ServiceClient.Call<ChangePreviewDto>(Ops.PreviewChange, new ChangeRequestDto(_kind, _params));
        if (_preview.Errors.Count > 0) { ErrorText.Text = string.Join(" ", _preview.Errors); return; }

        if (_preview.Direction == Direction.Tighten) { await SubmitAsync(null); return; }

        ReflectionText.Text = string.IsNullOrWhiteSpace(_preview.ReflectionMessage) ? "(You didn't write a reflection message.)" : _preview.ReflectionMessage;
        ChangeText.Text = _preview.Description;
        DelayText.Text = _preview.Delay is null
            ? "This needs your partner's code."
            : $"This will apply automatically in {DelayMath.Describe(_preview.Delay)}. You can cancel it any time before then.";
        PhraseText.Text = _preview.ConfirmationPhrase;
        PhraseBox.Text = "";
        ChoosePanel.Visibility = Visibility.Collapsed;
        ReflectPanel.Visibility = Visibility.Visible;
        BackButton.Visibility = Visibility.Visible;
        NextButton.Content = "Request this change";
    }

    private async Task SubmitAsync(string? phrase)
    {
        var r = await ServiceClient.Call<ChangeResultDto>(Ops.RequestChange, new ChangeRequestDto(_kind, _params, phrase));
        if (r.Errors.Count > 0) { ErrorText.Text = string.Join(" ", r.Errors); return; }
        ChoosePanel.Visibility = ReflectPanel.Visibility = Visibility.Collapsed;
        DonePanel.Visibility = Visibility.Visible;
        BackButton.Visibility = Visibility.Collapsed;
        NextButton.Content = "Done";
        DoneTitle.Text = r.Applied ? "Done. That was a tightening, so it applied right away." : "Your request is queued.";
        DoneText.Text = r.Applied ? "" : "You'll see the countdown on the main screen. You can cancel it any time.";
    }

    private void Back_Click(object sender, RoutedEventArgs e)
    {
        ReflectPanel.Visibility = Visibility.Collapsed;
        ChoosePanel.Visibility = Visibility.Visible;
        BackButton.Visibility = Visibility.Collapsed;
        NextButton.Content = "Next";
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
