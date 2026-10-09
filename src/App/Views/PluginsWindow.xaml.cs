using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Net;
using System.Text;
using ANetworkScanner.App.Services;
using ANetworkScanner.App.ViewModels;
using ANetworkScanner.Engine.Probes;
using Microsoft.UI;
using Microsoft.UI.Composition.SystemBackdrops;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Windows.Storage.Pickers;

namespace ANetworkScanner.App.Views;

/// <summary>
/// Manages the service probes: switch them on and off, see how each one works, test one against a host, and
/// add, create, customize or delete the user's own probe files.
/// </summary>
public sealed partial class PluginsWindow : Window
{
    private readonly MainViewModel _main;
    private readonly List<PluginItem> _all = [];
    private CancellationTokenSource? _testCts;
    private string _signature = "";
    private bool _refreshing;

    public PluginsWindow(MainViewModel main)
    {
        _main = main;
        InitializeComponent();

        WindowIcon.Apply(this);
        SystemBackdrop = new MicaBackdrop { Kind = MicaKind.BaseAlt };
        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);
        ThemeService.Register(this, Root, _main.Settings.Theme);
        FitToScreen(1240, 820);

        Activated += OnActivated;
        Closed += (_, _) => _testCts?.Cancel();

        Reload(selectId: null);
        if (Items.Count > 0) PluginList.SelectedIndex = 0;
    }

    public ObservableCollection<PluginItem> Items { get; } = [];

    private void FitToScreen(int preferredWidth, int preferredHeight)
    {
        var work = DisplayArea.GetFromWindowId(AppWindow.Id, DisplayAreaFallback.Primary).WorkArea;
        int width = Math.Min(preferredWidth, (int)(work.Width * 0.92));
        int height = Math.Min(preferredHeight, (int)(work.Height * 0.92));
        AppWindow.MoveAndResize(new Windows.Graphics.RectInt32(
            work.X + (work.Width - width) / 2, work.Y + (work.Height - height) / 2, width, height));
    }

    // ── List ─────────────────────────────────────────────────────────────────

    private PluginItem? Selection => PluginList.SelectedItem as PluginItem;

    /// <summary>Reads the probe files again and rebuilds the list, keeping the selection when possible.</summary>
    private void Reload(string? selectId)
    {
        selectId ??= Selection?.Id;
        _main.LoadProbes();
        _signature = FolderSignature();

        _all.Clear();
        foreach (var probe in _main.AllProbes.OrderBy(p => p.Title, StringComparer.OrdinalIgnoreCase))
        {
            bool enabled = !_main.Settings.DisabledProbes.Contains(probe.Id, StringComparer.OrdinalIgnoreCase);
            _all.Add(new PluginItem(probe, enabled, OnEnabledChanged));
        }

        ApplyFilter(selectId);
        ShowProblems();
    }

    private void ApplyFilter(string? selectId = null)
    {
        selectId ??= Selection?.Id;
        var filter = FilterBox.Text.Trim();

        _refreshing = true;
        Items.Clear();
        foreach (var item in _all.Where(i => filter.Length == 0
                     || i.Title.Contains(filter, StringComparison.OrdinalIgnoreCase)
                     || i.Id.Contains(filter, StringComparison.OrdinalIgnoreCase)
                     || i.Definition.Description.Contains(filter, StringComparison.OrdinalIgnoreCase)))
            Items.Add(item);
        _refreshing = false;

        PluginList.SelectedItem = Items.FirstOrDefault(i => string.Equals(i.Id, selectId, StringComparison.OrdinalIgnoreCase))
                                  ?? Items.FirstOrDefault();
        ShowDetails(Selection);
    }

    private void FilterBox_TextChanged(object sender, TextChangedEventArgs e) => ApplyFilter();

    private void OnEnabledChanged(PluginItem item)
    {
        var disabled = _main.Settings.DisabledProbes;
        disabled.RemoveAll(id => string.Equals(id, item.Id, StringComparison.OrdinalIgnoreCase));
        if (!item.IsEnabled) disabled.Add(item.Id);
        _main.SaveSettings();
    }

    private void PluginList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_refreshing) return;
        ShowDetails(Selection);
    }

    private void ShowProblems()
    {
        var problems = _main.ProbeProblems;
        SkippedExpander.Visibility = problems.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
        SkippedTitle.Text = problems.Count == 1 ? "1 file was skipped" : $"{problems.Count} files were skipped";
        ProblemList.ItemsSource = problems;
        if (problems.Count > 0) SkippedExpander.IsExpanded = true;
    }

    // ── Details ──────────────────────────────────────────────────────────────

    private void ShowDetails(PluginItem? item)
    {
        _testCts?.Cancel();
        TestProgress.Visibility = Visibility.Collapsed;
        TestButton.IsEnabled = true;
        TestResult.Text = "";

        NothingSelected.Visibility = item is null ? Visibility.Visible : Visibility.Collapsed;
        DetailScroll.Visibility = item is null ? Visibility.Collapsed : Visibility.Visible;
        if (item is null) return;

        var probe = item.Definition;
        DetailTitle.Text = probe.Title;
        DetailOrigin.Text = item.OriginText;
        DetailDescription.Text = probe.Description.Length > 0 ? probe.Description : "No description.";
        FactId.Text = probe.Id;
        FactPorts.Text = item.PortsText;
        FactFile.Text = probe.SourcePath.Length > 0 ? probe.SourcePath : probe.SourceFile;
        StepsText.Text = string.Join("\n", ProbeDescriber.DescribeSteps(probe));
        MatchText.Text = string.Join("\n", ProbeDescriber.DescribeMatches(probe));

        DuplicateButton.Visibility = probe.IsUser ? Visibility.Collapsed : Visibility.Visible;
        DeleteButton.Visibility = probe.IsUser ? Visibility.Visible : Visibility.Collapsed;
        ToolTipService.SetToolTip(DeleteButton, probe.OverridesBuiltIn
            ? "Delete your copy and go back to the built-in probe"
            : "Delete this probe file");

        if (TestAddress.Text.Length == 0)
            TestAddress.Text = _main.Selected?.Address ?? "127.0.0.1";
    }

    // ── Toolbar actions ──────────────────────────────────────────────────────

    private async void Add_Click(object sender, RoutedEventArgs e)
    {
        var picker = new FileOpenPicker { SuggestedStartLocation = PickerLocationId.DocumentsLibrary };
        picker.FileTypeFilter.Add(".json");
        WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
        var file = await picker.PickSingleFileAsync();
        if (file is null) return;

        string json;
        try { json = await File.ReadAllTextAsync(file.Path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            ShowNotice(InfoBarSeverity.Error, "Could not read the file", ex.Message);
            return;
        }

        var check = ProbeLoader.LoadFromJson(json, file.Name);
        if (check.Problems.Count > 0 || check.Probes.Count == 0)
        {
            await ShowDialogAsync($"{file.Name} is not a valid probe",
                string.Join("\n", check.Problems.Select(p => "• " + p.Message)));
            return;
        }

        var probe = check.Probes[0];
        var existing = _all.FirstOrDefault(i => string.Equals(i.Id, probe.Id, StringComparison.OrdinalIgnoreCase));
        var target = Path.Combine(ProbeInstaller.UserDirectory, ProbeInstaller.FileNameFor(probe.Id));

        if (File.Exists(target) && !await ConfirmAsync("Replace your probe?",
                $"You already have a custom probe \"{probe.Id}\". Replace it with this file?", "Replace"))
            return;
        if (existing is { IsCustom: false } && !await ConfirmAsync("Replace a built-in probe?",
                $"\"{probe.Id}\" is a built-in probe. Your file will be used instead of it. You can delete it later to go back.", "Use mine"))
            return;

        try
        {
            ProbeInstaller.Save(json, probe.Id, ProbeInstaller.UserDirectory, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            ShowNotice(InfoBarSeverity.Error, "Could not save the probe", ex.Message);
            return;
        }

        Reload(probe.Id);
        ShowNotice(InfoBarSeverity.Success, $"Added \"{probe.Title}\"", "It will be used by the next scan.");
    }

    private void New_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var path = ProbeInstaller.CreateFromTemplate(ProbeInstaller.UserDirectory, _all.Select(i => i.Id));
            var id = Path.GetFileNameWithoutExtension(path);
            Reload(id);
            Launch(new ProcessStartInfo(path) { UseShellExecute = true });
            ShowNotice(InfoBarSeverity.Informational, "New probe created",
                $"Edit {Path.GetFileName(path)}, save it, then come back here: changes are picked up automatically.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            ShowNotice(InfoBarSeverity.Error, "Could not create the probe", ex.Message);
        }
    }

    private void Folder_Click(object sender, RoutedEventArgs e)
    {
        Directory.CreateDirectory(ProbeInstaller.UserDirectory);
        Launch(new ProcessStartInfo(ProbeInstaller.UserDirectory) { UseShellExecute = true });
    }

    private void Reload_Click(object sender, RoutedEventArgs e)
    {
        Reload(null);
        ShowNotice(InfoBarSeverity.Informational, "Probes reloaded",
            $"{_all.Count} probes loaded" + (_main.ProbeProblems.Count > 0 ? $", {_main.ProbeProblems.Count} file(s) skipped." : "."));
    }

    // ── Detail actions ───────────────────────────────────────────────────────

    private void Edit_Click(object sender, RoutedEventArgs e)
    {
        if (Selection is { Definition.SourcePath: { Length: > 0 } path })
            Launch(new ProcessStartInfo(path) { UseShellExecute = true });
    }

    private void ShowInFolder_Click(object sender, RoutedEventArgs e)
    {
        if (Selection is { Definition.SourcePath: { Length: > 0 } path })
            Launch(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = true });
    }

    private void OpenProblem_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is string { Length: > 0 } path)
            Launch(new ProcessStartInfo(path) { UseShellExecute = true });
    }

    private async void Duplicate_Click(object sender, RoutedEventArgs e)
    {
        if (Selection is not { IsCustom: false } item) return;
        var target = Path.Combine(ProbeInstaller.UserDirectory, ProbeInstaller.FileNameFor(item.Id));
        if (File.Exists(target) && !await ConfirmAsync("Replace your copy?", "You already have a custom copy of this probe. Overwrite it?", "Overwrite"))
            return;

        try
        {
            var json = await File.ReadAllTextAsync(item.Definition.SourcePath);
            ProbeInstaller.Save(json, item.Id, ProbeInstaller.UserDirectory, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            ShowNotice(InfoBarSeverity.Error, "Could not copy the probe", ex.Message);
            return;
        }

        Reload(item.Id);
        ShowNotice(InfoBarSeverity.Success, "Copy created",
            "Your copy replaces the built-in probe. Use \"Open file\" to edit it, or delete it to go back.");
    }

    private async void Delete_Click(object sender, RoutedEventArgs e)
    {
        if (Selection is not { IsCustom: true } item) return;
        var message = item.Definition.OverridesBuiltIn
            ? $"Delete your copy of \"{item.Title}\"? The built-in probe will be used again."
            : $"Delete the probe \"{item.Title}\"? The file is removed from disk.";
        if (!await ConfirmAsync("Delete probe", message, "Delete")) return;

        try
        {
            if (!ProbeInstaller.Delete(item.Definition.SourcePath, ProbeInstaller.UserDirectory))
            {
                ShowNotice(InfoBarSeverity.Error, "Not deleted", "Only files in your own probes folder can be deleted.");
                return;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            ShowNotice(InfoBarSeverity.Error, "Could not delete the probe", ex.Message);
            return;
        }

        Reload(item.Definition.OverridesBuiltIn ? item.Id : null);
        ShowNotice(InfoBarSeverity.Success, "Deleted", $"\"{item.Title}\" was removed.");
    }

    // ── Test run ─────────────────────────────────────────────────────────────

    private void TestAddress_KeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key != Windows.System.VirtualKey.Enter) return;
        e.Handled = true;
        Test_Click(sender, e);
    }

    private async void Test_Click(object sender, RoutedEventArgs e)
    {
        if (Selection is not { } item) return;
        if (!IPAddress.TryParse(TestAddress.Text.Trim(), out var address) ||
            address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            TestResult.Text = "Enter a valid IPv4 address.";
            return;
        }

        _testCts?.Cancel();
        var cts = _testCts = new CancellationTokenSource();
        TestButton.IsEnabled = false;
        TestProgress.Visibility = Visibility.Visible;
        TestResult.Text = $"Running {item.Title} against {address}…";

        var runner = new ProbeRunner(connectRetries: _main.Settings.Discovery.ConnectRetries);
        var started = Stopwatch.StartNew();
        try
        {
            var result = await runner.RunAsync(item.Definition, address, cts.Token);
            if (cts.IsCancellationRequested) return;
            TestResult.Text = FormatTest(result, started.Elapsed);
        }
        catch (OperationCanceledException)
        {
            return;
        }
        finally
        {
            if (ReferenceEquals(_testCts, cts))
            {
                TestButton.IsEnabled = true;
                TestProgress.Visibility = Visibility.Collapsed;
            }
        }
    }

    private static string FormatTest(ProbeResult result, TimeSpan elapsed)
    {
        var sb = new StringBuilder();
        sb.AppendLine(result.State == PortState.Open
            ? $"Result: {(result.Short.Length > 0 ? result.Short : "open")}"
            : $"Result: no open port ({result.State.ToString().ToLowerInvariant()})");
        sb.AppendLine($"Took {elapsed.TotalSeconds:0.0} s");
        sb.AppendLine();
        foreach (var port in result.Ports.OrderBy(p => p.Port))
            sb.AppendLine($"  {port.Port,-6} {port.State.ToString().ToLowerInvariant(),-9} {(port.State == PortState.Open ? port.Short : port.Long)}");

        if (result.State == PortState.Open)
        {
            sb.AppendLine();
            sb.Append(result.Long);
        }
        return sb.ToString().TrimEnd();
    }

    // ── Live reload ──────────────────────────────────────────────────────────

    /// <summary>Coming back from an editor: pick up any file that changed while the window was in the background.</summary>
    private void OnActivated(object sender, WindowActivatedEventArgs args)
    {
        if (args.WindowActivationState == WindowActivationState.Deactivated) return;
        var now = FolderSignature();
        if (now == _signature) return;
        Reload(null);
        ShowNotice(InfoBarSeverity.Informational, "Probe files changed", "The list was reloaded.");
    }

    private static string FolderSignature()
    {
        var sb = new StringBuilder();
        foreach (var dir in new[] { Path.Combine(AppContext.BaseDirectory, "probes"), ProbeInstaller.UserDirectory })
        {
            if (!Directory.Exists(dir)) continue;
            foreach (var file in Directory.EnumerateFiles(dir, "*.json").Order(StringComparer.OrdinalIgnoreCase))
                sb.Append(file).Append('|').Append(File.GetLastWriteTimeUtc(file).Ticks).Append('|').Append(new FileInfo(file).Length).Append(';');
        }
        return sb.ToString();
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private void ShowNotice(InfoBarSeverity severity, string title, string message)
    {
        Notice.Severity = severity;
        Notice.Title = title;
        Notice.Message = message;
        Notice.IsOpen = true;
    }

    private async Task<bool> ConfirmAsync(string title, string message, string primary) =>
        await new ContentDialog
        {
            Title = title,
            Content = message,
            PrimaryButtonText = primary,
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
            RequestedTheme = Root.ActualTheme,
            XamlRoot = Root.XamlRoot,
        }.ShowAsync() == ContentDialogResult.Primary;

    private async Task ShowDialogAsync(string title, string message) =>
        await new ContentDialog
        {
            Title = title,
            Content = new ScrollViewer
            {
                MaxHeight = 360,
                Content = new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true },
            },
            CloseButtonText = "OK",
            RequestedTheme = Root.ActualTheme,
            XamlRoot = Root.XamlRoot,
        }.ShowAsync();

    private static void Launch(ProcessStartInfo info)
    {
        try { Process.Start(info); }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException) { }
    }
}
