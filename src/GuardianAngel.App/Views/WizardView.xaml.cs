using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Imaging;
using GuardianAngel.App.Services;
using GuardianAngel.Core.Dns;
using GuardianAngel.Core.Engine;
using GuardianAngel.Core.Ipc;
using GuardianAngel.Core.Model;
using QRCoder;

namespace GuardianAngel.App.Views;

public partial class WizardView : UserControl
{
    private readonly MainWindow _shell;
    private readonly (string Title, FrameworkElement Panel)[] _steps;
    private int _step;
    private FilterConfig? _filter;
    private ConnectionTestResult? _test;
    private string? _testedFor;
    private bool _partnerConfirmed;

    public WizardView(MainWindow shell)
    {
        InitializeComponent();
        _shell = shell;
        _steps =
        [
            ("Choose your setup", StepSetup),
            ("Your filter", StepFilter),
            ("Connection test", StepTest),
            ("How unlocking works", StepUnlock),
            ("Your reflection message", StepReflection),
            ("Browsers", StepBrowsers),
            ("Summary", StepSummary),
        ];
        Loaded += async (_, _) =>
        {
            var s = await ServiceClient.TryStatus();
            if (s is not null)
            {
                DelayLimits.Text = $"Between {DelayMath.Describe(s.MinDelay)} and {DelayMath.Describe(s.MaxDelay)}. Many people choose 12 to 24 hours.";
                if (s.HasPartner) { _partnerConfirmed = true; UsePartner.IsChecked = true; PartnerStatus.Text = "Partner is set up."; }
            }
        };
        Show();
    }

    private void Show()
    {
        for (int i = 0; i < _steps.Length; i++) _steps[i].Panel.Visibility = i == _step ? Visibility.Visible : Visibility.Collapsed;
        StepTitle.Text = _steps[_step].Title;
        StepCounter.Text = $"Step {_step + 1} of {_steps.Length}";
        BackButton.IsEnabled = _step > 0;
        NextButton.Visibility = _step == _steps.Length - 1 ? Visibility.Collapsed : Visibility.Visible;
        ErrorText.Text = "";
        if (_steps[_step].Panel == StepSummary) SummaryText.Text = BuildSummary();
    }

    private void Back_Click(object sender, RoutedEventArgs e) { if (_step > 0) { _step--; Show(); } }

    private void Next_Click(object sender, RoutedEventArgs e)
    {
        var error = Validate();
        if (error is not null) { ErrorText.Text = error; return; }
        _step++;
        Show();
    }

    private string? Validate()
    {
        var panel = _steps[_step].Panel;
        if (panel == StepFilter)
        {
            var (f, errors) = Editor.Read();
            if (f is null) return string.Join(" ", errors);
            _filter = f;
        }
        else if (panel == StepTest)
        {
            if (_test is null || _testedFor != Key()) return "Run the test first.";
            if (!_test.Passed(ConfirmBlockPage.IsChecked == true)) return _test.Summary;
        }
        else if (panel == StepUnlock)
        {
            if (UseDelay.IsChecked != true && UsePartner.IsChecked != true) return "Choose a time delay, a partner, or both.";
            if (UseDelay.IsChecked == true && Delay.Value is null) return "Enter a delay.";
            if (UsePartner.IsChecked == true && !_partnerConfirmed) return "Confirm your partner's code first, or untick the partner option.";
        }
        return null;
    }

    private string Key() => $"{System.Text.Json.JsonSerializer.Serialize(_filter)}|{BlockedDomainBox.Text.Trim()}";

    private async void RunTest_Click(object sender, RoutedEventArgs e)
    {
        if (_filter is null) return;
        RunTestButton.IsEnabled = false;
        TestSummary.Text = "Testing...";
        try
        {
            var domain = string.IsNullOrWhiteSpace(BlockedDomainBox.Text) ? null : BlockedDomainBox.Text.Trim();
            _test = await ServiceClient.Call<ConnectionTestResult>(Ops.TestFilter, new TestFilterRequest(_filter, domain), timeoutMs: 90_000);
            _testedFor = Key();
            TestSummary.Text = _test.Summary;
            TestServers.ItemsSource = _test.Servers;
            BlockAnswers.Text = _test.BlockedDomainAnswers.Count > 0 ? $"The test site answered: {string.Join(", ", _test.BlockedDomainAnswers)}" : "";
            ConfirmBlockPage.Visibility = _test.BlockedDomainResult == BlockCheck.ResolvedNormally ? Visibility.Visible : Visibility.Collapsed;
        }
        catch (Exception ex) { TestSummary.Text = "The test couldn't run: " + ex.Message; }
        finally { RunTestButton.IsEnabled = true; }
    }

    private async void UsePartner_Checked(object sender, RoutedEventArgs e)
    {
        PartnerCard.Visibility = Visibility.Visible;
        if (_partnerConfirmed) { QrImage.Visibility = Visibility.Collapsed; ManualSecret.Text = ""; return; }
        try
        {
            var begin = await ServiceClient.Call<PartnerBeginResponse>(Ops.PartnerBegin);
            QrImage.Source = Qr(begin.OtpAuthUri);
            QrImage.Visibility = Visibility.Visible;
            ManualSecret.Text = $"Can't scan? Enter this key manually (time-based, 6 digits): {begin.SecretForManualEntry}";
        }
        catch (Exception ex) { PartnerStatus.Text = ex.Message; }
    }

    private async void UsePartner_Unchecked(object sender, RoutedEventArgs e)
    {
        PartnerCard.Visibility = Visibility.Collapsed;
        try { await ServiceClient.Call(Ops.PartnerClear); } catch { /* nothing to clear */ }
        _partnerConfirmed = false;
        QrImage.Source = null;
        PartnerStatus.Text = "";
    }

    private async void ConfirmPartner_Click(object sender, RoutedEventArgs e)
    {
        var r = await ServiceClient.Call(Ops.PartnerConfirm, new CodeRequest(PartnerCodeBox.Text.Trim()));
        if (!r.Ok) { PartnerStatus.Text = r.Error; PartnerStatus.Foreground = (System.Windows.Media.Brush)FindResource("Bad"); return; }
        _partnerConfirmed = true;
        QrImage.Source = null;
        QrImage.Visibility = Visibility.Collapsed;
        ManualSecret.Text = "";
        PartnerStatus.Text = "Partner confirmed. The QR code has been hidden for good.";
        PartnerStatus.Foreground = (System.Windows.Media.Brush)FindResource("Good");
    }

    private static BitmapImage Qr(string text)
    {
        using var gen = new QRCodeGenerator();
        using var data = gen.CreateQrCode(text, QRCodeGenerator.ECCLevel.M);
        var png = new PngByteQRCode(data).GetGraphic(8);
        var img = new BitmapImage();
        using var ms = new MemoryStream(png);
        img.BeginInit();
        img.CacheOption = BitmapCacheOption.OnLoad;
        img.StreamSource = ms;
        img.EndInit();
        img.Freeze();
        return img;
    }

    private string BuildSummary()
    {
        var delay = UseDelay.IsChecked == true ? DelayMath.Describe(Delay.Value) : "none (partner code only)";
        return $"Filter: {_filter?.Name}\n" +
               $"Servers: {string.Join(", ", _filter?.Servers ?? [])}\n" +
               $"Encryption: {_filter?.Encryption switch { EncryptionMode.Doh => "DNS over HTTPS", EncryptionMode.Dot => "DNS over TLS", _ => "none (plain DNS)" }}\n" +
               $"If no filter answers: {(_filter?.WhenUnreachable == UnreachableBehavior.BlockInternet ? "block the internet" : "fallback servers only")}\n" +
               $"Delay: {delay}\n" +
               $"Partner: {(UsePartner.IsChecked == true ? "yes" : "no")}\n" +
               $"Private windows: {(DisablePrivate.IsChecked == true ? "off" : "allowed")}\n" +
               $"Proxy/VPN extensions: {(BlockProxy.IsChecked == true ? "blocked" : "allowed")}\n" +
               $"Reflection message: {(string.IsNullOrWhiteSpace(ReflectionBox.Text) ? "(none)" : "set")}";
    }

    private async void Lock_Click(object sender, RoutedEventArgs e)
    {
        if (_filter is null) return;
        LockButton.IsEnabled = false;
        ErrorText.Text = "Locking...";
        try
        {
            var req = new LockRequest(_filter, UseDelay.IsChecked == true, Delay.Value ?? TimeSpan.FromHours(24), ReflectionBox.Text,
                new BrowserOptions { DisablePrivateMode = DisablePrivate.IsChecked == true, BlockProxyExtensions = BlockProxy.IsChecked == true },
                string.IsNullOrWhiteSpace(BlockedDomainBox.Text) ? null : BlockedDomainBox.Text.Trim(), ConfirmBlockPage.IsChecked == true);
            var r = await ServiceClient.Call<LockResponse>(Ops.Lock, req, timeoutMs: 120_000);
            if (!r.Locked) { ErrorText.Text = string.Join(" ", r.Errors); return; }
            await _shell.ShowStartAsync();
        }
        catch (Exception ex) { ErrorText.Text = ex.Message; }
        finally { LockButton.IsEnabled = true; }
    }
}
