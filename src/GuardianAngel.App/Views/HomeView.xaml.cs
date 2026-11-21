using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using GuardianAngel.App.Services;
using GuardianAngel.Core.Engine;
using GuardianAngel.Core.Ipc;
using GuardianAngel.Core.Model;

namespace GuardianAngel.App.Views;

public partial class HomeView : UserControl
{
    public sealed record PendingRow(Guid Id, string Description, string Countdown, Visibility ExpediteVisibility);
    public sealed record CheckRow(string Icon, Brush Color, string Name, string Detail);
    public sealed record HistoryRow(string Text);

    private readonly MainWindow _shell;
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(1) };
    private StatusDto? _status;
    private DateTime _statusAt;
    private int _ticks;

    public HomeView(MainWindow shell)
    {
        InitializeComponent();
        _shell = shell;
        _timer.Tick += async (_, _) =>
        {
            if (++_ticks % 5 == 0) await Refresh(); else Render();
        };
        Loaded += async (_, _) => { await Refresh(); _timer.Start(); };
        Unloaded += (_, _) => _timer.Stop();
    }

    private async Task Refresh()
    {
        var s = await ServiceClient.TryStatus();
        if (s is null) { LockSubtitle.Text = "Can't reach the service right now. Your protection stays on."; return; }
        if (!s.IsLocked) { _timer.Stop(); await _shell.ShowStartAsync(); return; }
        _status = s;
        _statusAt = DateTime.UtcNow;
        Render();
    }

    private void Render()
    {
        if (_status is not { } s) return;
        var since = (long)(DateTime.UtcNow - _statusAt).TotalMilliseconds;

        LockTitle.Text = "Locked";
        LockSubtitle.Text = $"Filter: {s.Filter?.Name}  ·  Delay: {DelayMath.Describe(s.DelayEnabled ? s.Delay : null)}  ·  Partner: {(s.HasPartner ? "yes" : "no")}";
        SafeLockedCard.Visibility = s.SafeLocked ? Visibility.Visible : Visibility.Collapsed;
        SafeLockedText.Text = s.SafeLockedReason ?? "";

        PendingList.ItemsSource = s.Pending.Select(p => new PendingRow(p.Id, p.Description,
            p.Status == ChangeStatus.Applying ? "Applying now..."
                : p.RemainingMs is null ? "Waiting for your partner's code"
                : $"Applies in {DelayMath.Countdown(Math.Max(0, p.RemainingMs.Value - since))} (about {DateTime.Now.AddMilliseconds(Math.Max(0, p.RemainingMs.Value - since)):ddd h:mm tt})",
            s.HasPartner ? Visibility.Visible : Visibility.Collapsed)).ToList();
        NoPending.Visibility = s.Pending.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

        var good = (Brush)FindResource("Good");
        var bad = (Brush)FindResource("Bad");
        var warn = (Brush)FindResource("Warn");
        var rows = s.Enforcement.Select(e => new CheckRow(e.Healthy ? "✓" : "!", e.Healthy ? good : bad, e.Name, e.Detail)).ToList();
        if (s.Filter?.Encryption == EncryptionMode.None)
            rows.Add(new CheckRow("!", warn, "Plain DNS", "A device on your network could intercept plain DNS. Encrypted DNS is safer."));
        rows.Add(new CheckRow("!", warn, "Admin rights", "Your account is still an administrator. The next version helps you protect admin rights."));
        Checklist.ItemsSource = rows;

        HistoryList.ItemsSource = s.RecentHistory.Select(h => new HistoryRow(
            $"{h.Status}: {h.Description}{(h.FailureReason is null ? "" : $" ({h.FailureReason})")}")).ToList();
    }

    private void RequestChange_Click(object sender, RoutedEventArgs e)
    {
        if (_status is null) return;
        new RequestChangeWindow(_status) { Owner = Window.GetWindow(this) }.ShowDialog();
        _ = Refresh();
    }

    private async void Cancel_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: Guid id }) return;
        var r = await ServiceClient.Call(Ops.CancelChange, new IdRequest(id));
        if (!r.Ok) MessageBox.Show(r.Error, "Guardian Angel");
        await Refresh();
    }

    private void Expedite_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: Guid id }) return;
        new ExpediteWindow(id) { Owner = Window.GetWindow(this) }.ShowDialog();
        _ = Refresh();
    }
}
