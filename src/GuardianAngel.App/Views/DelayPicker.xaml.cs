using System.Windows.Controls;

namespace GuardianAngel.App.Views;

public partial class DelayPicker : UserControl
{
    public DelayPicker() => InitializeComponent();

    public TimeSpan? Value
    {
        get
        {
            if (!double.TryParse(AmountBox.Text.Trim(), out var n) || n <= 0) return null;
            return UnitBox.SelectedIndex switch { 0 => TimeSpan.FromMinutes(n), 2 => TimeSpan.FromDays(n), _ => TimeSpan.FromHours(n) };
        }
        set
        {
            var t = value ?? TimeSpan.FromHours(24);
            if (t.TotalDays >= 1 && t.TotalHours % 24 == 0) { AmountBox.Text = t.TotalDays.ToString(); UnitBox.SelectedIndex = 2; }
            else if (t.TotalHours >= 1 && t.TotalMinutes % 60 == 0) { AmountBox.Text = t.TotalHours.ToString(); UnitBox.SelectedIndex = 1; }
            else { AmountBox.Text = Math.Ceiling(t.TotalMinutes).ToString(); UnitBox.SelectedIndex = 0; }
        }
    }
}
