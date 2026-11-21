using System.Windows;
using System.Windows.Controls;
using GuardianAngel.App.Content;

namespace GuardianAngel.App.Views;

public partial class GuideView : UserControl
{
    private readonly Action? _onDone;
    private readonly bool _firstRun;
    private int _page;

    public GuideView(bool firstRun, Action? onDone)
    {
        InitializeComponent();
        _firstRun = firstRun;
        _onDone = onDone;
        SkipButton.Visibility = firstRun ? Visibility.Visible : Visibility.Collapsed;
        Intro.Visibility = firstRun ? Visibility.Visible : Visibility.Collapsed;
        Show();
    }

    private void Show()
    {
        var t = LearnContent.Topics[_page];
        TopicTitle.Text = t.Title;
        TopicBody.Text = t.Body;
        PageText.Text = $"{_page + 1} of {LearnContent.Topics.Count}";
        BackButton.IsEnabled = _page > 0;
        var last = _page == LearnContent.Topics.Count - 1;
        NextButton.Content = last ? (_firstRun ? "Start setup" : "Back to start") : "Next";
    }

    private void Back_Click(object sender, RoutedEventArgs e) { if (_page > 0) { _page--; Show(); } }

    private void Next_Click(object sender, RoutedEventArgs e)
    {
        if (_page < LearnContent.Topics.Count - 1) { _page++; Show(); return; }
        if (_onDone is not null) _onDone();
        else { _page = 0; Show(); }
    }

    private void Skip_Click(object sender, RoutedEventArgs e) => _onDone?.Invoke();
}
