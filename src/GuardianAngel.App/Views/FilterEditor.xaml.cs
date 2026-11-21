using System.Windows;
using System.Windows.Controls;
using GuardianAngel.Core.Model;

namespace GuardianAngel.App.Views;

public partial class FilterEditor : UserControl
{
    private sealed record Choice(string Name, FilterPresets.Preset? Preset);

    public FilterEditor()
    {
        InitializeComponent();
        var choices = FilterPresets.All.Select(p => new Choice(p.Name, p)).Append(new Choice("My own filter", null)).ToList();
        PresetBox.ItemsSource = choices;
        PresetBox.SelectedIndex = 0;
    }

    public void Load(FilterConfig f)
    {
        var idx = FilterPresets.All.ToList().FindIndex(p => p.Id == f.PresetId);
        PresetBox.SelectedIndex = idx >= 0 ? idx : FilterPresets.All.Count;
        Fill(f);
    }

    private void PresetBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (PresetBox.SelectedItem is not Choice c) return;
        PresetDescription.Text = c.Preset?.Description ?? "Enter your filter's addresses. Your filter's dashboard or setup page lists them.";
        ProfilePanel.Visibility = c.Preset?.NeedsProfileId == true ? Visibility.Visible : Visibility.Collapsed;
        if (c.Preset is not null) Fill(c.Preset.Config);
        else Fill(new FilterConfig { Name = "My filter", Encryption = EncryptionMode.Doh });
    }

    private void ProfileBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (PresetBox.SelectedItem is Choice { Preset: { NeedsProfileId: true } p })
            Fill(FilterPresets.WithProfile(p.Config, string.IsNullOrWhiteSpace(ProfileBox.Text) ? "PROFILE" : ProfileBox.Text.Trim()), keepProfile: true);
    }

    private void Fill(FilterConfig f, bool keepProfile = false)
    {
        NameBox.Text = f.Name;
        ServersBox.Text = string.Join(Environment.NewLine, f.Servers);
        DohBox.Text = f.DohTemplate ?? "";
        DotBox.Text = f.DotHost ?? "";
        EncDoh.IsChecked = f.Encryption == EncryptionMode.Doh;
        EncDot.IsChecked = f.Encryption == EncryptionMode.Dot;
        EncNone.IsChecked = f.Encryption == EncryptionMode.None;
        UnreachBlock.IsChecked = f.WhenUnreachable == UnreachableBehavior.BlockInternet;
        UnreachFallback.IsChecked = f.WhenUnreachable == UnreachableBehavior.FallbackOnly;
        if (!keepProfile) ProfileBox.Text = "";
    }

    private void Enc_Checked(object sender, RoutedEventArgs e)
    {
        if (DohPanel is null || DotPanel is null) return;
        DohPanel.Visibility = EncDoh.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        DotPanel.Visibility = EncDot.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
    }

    /// <summary>The filter as entered, or a list of problems.</summary>
    public (FilterConfig? Filter, List<string> Errors) Read()
    {
        var preset = (PresetBox.SelectedItem as Choice)?.Preset;
        var f = new FilterConfig
        {
            Name = NameBox.Text.Trim(),
            PresetId = preset?.Id,
            Servers = ServersBox.Text.Split(['\r', '\n', ',', ' '], StringSplitOptions.RemoveEmptyEntries).Select(s => s.Trim()).ToList(),
            Encryption = EncDot.IsChecked == true ? EncryptionMode.Dot : EncNone.IsChecked == true ? EncryptionMode.None : EncryptionMode.Doh,
            DohTemplate = string.IsNullOrWhiteSpace(DohBox.Text) ? null : DohBox.Text.Trim(),
            DotHost = string.IsNullOrWhiteSpace(DotBox.Text) ? null : DotBox.Text.Trim(),
            WhenUnreachable = UnreachFallback.IsChecked == true ? UnreachableBehavior.FallbackOnly : UnreachableBehavior.BlockInternet,
        };
        var errors = f.Validate();
        if ((f.DohTemplate ?? "").Contains("PROFILE") || (f.DotHost ?? "").Contains("PROFILE")) errors.Add("Enter your profile ID.");
        return (errors.Count == 0 ? f : null, errors);
    }
}
