using System.Windows;
using System.Windows.Controls;

namespace GuardianAngel.App.Views;

public partial class MessageView : UserControl
{
    private readonly Func<Task>? _action;

    public MessageView(string title, string body, string? actionText = null, Func<Task>? action = null)
    {
        InitializeComponent();
        TitleText.Text = title;
        BodyText.Text = body;
        _action = action;
        ActionButton.Content = actionText;
        ActionButton.Visibility = actionText is null ? Visibility.Collapsed : Visibility.Visible;
    }

    private async void ActionButton_Click(object sender, RoutedEventArgs e)
    {
        if (_action is not null) await _action();
    }
}
