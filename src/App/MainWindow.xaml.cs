using System.Reflection;
using System.ComponentModel;
using System.Diagnostics;
using ANetworkScanner.App.Controls;
using ANetworkScanner.App.Services;
using ANetworkScanner.App.ViewModels;
using ANetworkScanner.App.Views;
using ANetworkScanner.Engine.Probes;
using ANetworkScanner.Engine.Vendors;
using ANetworkScanner.Engine.Targets;
using Microsoft.UI;
using Microsoft.UI.Composition.SystemBackdrops;
using Microsoft.UI.Input;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using Windows.ApplicationModel.DataTransfer;
using Windows.Storage.Pickers;

namespace ANetworkScanner.App;

public sealed partial class MainWindow : Window
{
    private Storyboard? _pulse;
    private PluginsWindow? _plugins;
    private bool _probeRefreshPending;

    public MainWindow(string? initialTarget = null)
    {
        ViewModel = new MainViewModel(DispatcherQueue);
        InitializeComponent();
        Root.KeyDown += Root_KeyDown;

        var version = typeof(MainWindow).Assembly.GetCustomAttribute<System.Reflection.AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion.Split('+')[0] ?? "";
        Title = TitleText.Text = version.Length > 0 ? $"A Network Scanner {version}" : "A Network Scanner";

        WindowIcon.Apply(this);
        SystemBackdrop = new MicaBackdrop { Kind = MicaKind.BaseAlt };
        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);
        ThemeService.Register(this, Root, ViewModel.Settings.Theme);
        FitToScreen(1500, 960);

        ViewModel.ScanStarted += OnScanStarted;
        ViewModel.TargetScanned += (address, alive) => Map.Mark(address, alive);
        ViewModel.ScanFinished += OnScanFinished;
        ViewModel.SelectedChanged += RefreshDetails;
        Closed += (_, _) => _plugins?.Close();
        ViewModel.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(MainViewModel.Selected)) RefreshDetails(ViewModel.Selected);
        };
        Map.HoverTextChanged += text => MapHover.Text = text;

        BuildHeader();
        SetUpDetailsSplitter();
        UpdateProblemsBar();
        ViewModel.Layout.WidthsChanged += UpdateScrollWidth;
        ViewModel.Layout.VisibilityChanged += BuildHeader;
        ThemeService.Changed += OnThemeChanged;
        Closed += (_, _) => ThemeService.Changed -= OnThemeChanged;
        ViewModel.VendorsLoaded += OnVendorsLoaded;
        Root.Loaded += async (_, _) =>
        {
            if (!string.IsNullOrWhiteSpace(initialTarget))
            {
                ViewModel.Target = initialTarget;
                ViewModel.StartScan();
            }
            else TargetBox.Focus(FocusState.Programmatic);

            await ViewModel.LoadVendorsAsync();
        };
    }

    public MainViewModel ViewModel { get; }

    /// <summary>Opens centred at the preferred size, but never larger than 92% of the usable screen area.</summary>
    private void FitToScreen(int preferredWidth, int preferredHeight)
    {
        var work = DisplayArea.GetFromWindowId(AppWindow.Id, DisplayAreaFallback.Primary).WorkArea;
        int width = Math.Min(preferredWidth, (int)(work.Width * 0.92));
        int height = Math.Min(preferredHeight, (int)(work.Height * 0.92));
        AppWindow.MoveAndResize(new Windows.Graphics.RectInt32(
            work.X + (work.Width - width) / 2, work.Y + (work.Height - height) / 2, width, height));
    }

    // ── x:Bind helpers ───────────────────────────────────────────────────────

    public bool NotScanning(bool scanning) => !scanning;
    public Visibility NotScanningVisibility(bool scanning) => scanning ? Visibility.Collapsed : Visibility.Visible;
    public Visibility NoResultsVisibility(bool hasResults, bool scanning) =>
        hasResults || scanning ? Visibility.Collapsed : Visibility.Visible;

    // ── Scan lifecycle ───────────────────────────────────────────────────────

    private void ScanButton_Click(object sender, RoutedEventArgs e) => StartScan();

    private void StopButton_Click(object sender, RoutedEventArgs e) => ViewModel.StopScan();

    private void TargetBox_TextSubmitted(ComboBox sender, ComboBoxTextSubmittedEventArgs args)
    {
        ViewModel.Target = args.Text;
        StartScan();
    }

    /// <summary>F5 scans, Esc stops. Plain key handling: XAML accelerators would add an "F5" hint to every tooltip.</summary>
    private void Root_KeyDown(object sender, Microsoft.UI.Xaml.Input.KeyRoutedEventArgs e)
    {
        if (e.Key == Windows.System.VirtualKey.F5)
        {
            e.Handled = true;
            StartScan();
        }
        else if (e.Key == Windows.System.VirtualKey.Escape && ViewModel.IsScanning)
        {
            e.Handled = true;
            ViewModel.StopScan();
        }
    }

    private void StartScan()
    {
        // The editable combo box only commits its text on focus loss or Enter.
        if (!string.IsNullOrWhiteSpace(TargetBox.Text)) ViewModel.Target = TargetBox.Text;
        ViewModel.StartScan();
    }

    private void OnScanStarted(TargetSet targets, IReadOnlyList<ProbeDefinition> probes)
    {
        Map.Begin(targets);
        MapEmpty.Visibility = Visibility.Collapsed;
        DetailsTitle.Text = "Details";
        DetailsText.Text = "Select a host to see everything the scan learned about it.";
        DetailsActions.Visibility = Visibility.Collapsed;
        StartPulse();
    }

    private void OnScanFinished()
    {
        _pulse?.Stop();
        ScanDot.Opacity = 0.25;
        if (_probeRefreshPending) RefreshProbeColumns();
    }

    /// <summary>The probe set changed in the Probes window: rebuild the columns (never in the middle of a scan).</summary>
    private void RefreshProbeColumns()
    {
        _probeRefreshPending = false;
        UpdateProblemsBar();
    }

    /// <summary>A slow breathing dot in the map card: the scan is alive.</summary>
    private void StartPulse()
    {
        _pulse?.Stop();
        var animation = new DoubleAnimation
        {
            From = 0.25,
            To = 1.0,
            Duration = TimeSpan.FromMilliseconds(700),
            AutoReverse = true,
            RepeatBehavior = RepeatBehavior.Forever,
            EasingFunction = new SineEase { EasingMode = EasingMode.EaseInOut },
        };
        Storyboard.SetTarget(animation, ScanDot);
        Storyboard.SetTargetProperty(animation, "Opacity");
        _pulse = new Storyboard();
        _pulse.Children.Add(animation);
        _pulse.Begin();
    }

    // ── Columns, resizing and sorting ────────────────────────────────────────

    private sealed record HeaderCell(Button Button, string Title, SortColumn Sort, ColumnInfo Column);

    private readonly List<HeaderCell> _headerCells = [];
    private readonly List<(ColumnInfo Column, PropertyChangedEventHandler Handler)> _headerSubscriptions = [];

    /// <summary>Builds the header: one sortable, resizable cell per column. Rows share the same column objects.</summary>
    private void BuildHeader()
    {
        foreach (var (column, handler) in _headerSubscriptions) column.PropertyChanged -= handler;
        _headerSubscriptions.Clear();
        _headerCells.Clear();
        HeaderPanel.Children.Clear();

        HeaderPanel.Children.Add(new Border { Width = TableLayout.StatusWidth });
        foreach (var column in ViewModel.Layout.VisibleFixedColumns)
        {
            var sort = column.Key switch
            {
                "name" => SortColumn.Name,
                "rtt" => SortColumn.Rtt,
                "mac" => SortColumn.Mac,
                "vendor" => SortColumn.Vendor,
                "method" => SortColumn.Method,
                "services" => SortColumn.Services,
                _ => SortColumn.Address,
            };
            AddHeaderCell(column, sort);
        }

        UpdateScrollWidth();
        UpdateHeaderArrows();
    }

    private void AddHeaderCell(ColumnInfo column, SortColumn sort)
    {
        var cell = new Grid { Width = column.Width };
        var button = new Button
        {
            Style = (Style)Root.Resources["HeaderButtonStyle"],
            Content = column.Title,
            Margin = new Thickness(0, 0, 12, 0),
        };
        button.Click += (_, _) =>
        {
            ViewModel.SortOn(sort);
            UpdateHeaderArrows();
        };

        var grip = new ResizeGrip { HorizontalAlignment = HorizontalAlignment.Right };
        double startWidth = column.Width;
        grip.DragStarted += () => startWidth = column.Width;
        grip.DragDelta += delta => column.SetWidth(startWidth + delta);
        grip.DragCompleted += SaveColumnWidths;
        grip.AutoFitRequested += () =>
        {
            column.SetWidth(FitWidth(column, sort));
            SaveColumnWidths();
        };

        cell.Children.Add(button);
        cell.Children.Add(grip);
        HeaderPanel.Children.Add(cell);
        _headerCells.Add(new HeaderCell(button, column.Title, sort, column));

        PropertyChangedEventHandler handler = (_, e) =>
        {
            if (e.PropertyName == nameof(ColumnInfo.Width)) cell.Width = column.Width;
        };
        column.PropertyChanged += handler;
        _headerSubscriptions.Add((column, handler));
    }

    /// <summary>The scrollable area is as wide as all columns together, so a wide table scrolls instead of clipping.</summary>
    private void UpdateScrollWidth() =>
        ResultsGrid.MinWidth = ViewModel.Layout.TotalWidth();

    /// <summary>A grip between the table and the details panel; dragging left widens the panel.</summary>
    private void SetUpDetailsSplitter()
    {
        if (ViewModel.Settings.DetailsWidth >= 240) DetailsColumn.Width = new GridLength(ViewModel.Settings.DetailsWidth);

        var grip = new ResizeGrip { HorizontalAlignment = HorizontalAlignment.Center, Width = 12 };
        Grid.SetColumn(grip, 1);
        double start = DetailsColumn.Width.Value;
        grip.DragStarted += () => start = DetailsColumn.ActualWidth;
        grip.DragDelta += delta =>
        {
            double max = Math.Max(240, BodyGrid.ActualWidth - 300 - 12);
            DetailsColumn.Width = new GridLength(Math.Clamp(start - delta, 240, max));
        };
        grip.DragCompleted += () =>
        {
            ViewModel.Settings.DetailsWidth = DetailsColumn.ActualWidth;
            ViewModel.SaveSettings();
        };
        grip.AutoFitRequested += () =>
        {
            DetailsColumn.Width = new GridLength(380);
            ViewModel.Settings.DetailsWidth = 0;
            ViewModel.SaveSettings();
        };
        BodyGrid.Children.Add(grip);
    }

    private void SaveColumnWidths()
    {
        ViewModel.Layout.Save(ViewModel.Settings);
        ViewModel.SaveSettings();
    }

    private void UpdateHeaderArrows()
    {
        foreach (var cell in _headerCells)
        {
            bool sorted = ViewModel.SortBy == cell.Sort;
            cell.Button.Content = cell.Title + (sorted ? (ViewModel.SortDescending ? "  ▼" : "  ▲") : "");
        }
    }

    /// <summary>Width that fits the widest value of a column (header included), measured with the row's fonts.</summary>
    private double FitWidth(ColumnInfo column, SortColumn sort)
    {
        double widest = Measure(column.Title, 12, FontWeights.SemiBold, mono: false) + 36;

        foreach (var row in ViewModel.Rows.Take(3000))
        {
            double width = sort switch
            {
                SortColumn.Address => Measure(row.Address, 14.4, FontWeights.SemiBold, mono: true) + 28 + 10 + 16,
                SortColumn.Name => Measure(row.Name, 14, FontWeights.Normal, mono: false) + 16,
                SortColumn.Rtt => Measure(row.RttText, 14, FontWeights.Normal, mono: false) + 16,
                SortColumn.Mac => Measure(row.Mac, 12, FontWeights.Normal, mono: true) + 16,
                SortColumn.Vendor => Measure(row.VendorText, 14, FontWeights.Normal, mono: false) + 16,
                SortColumn.Method => Measure(row.MethodText, 14, FontWeights.Normal, mono: false) + 16,
                _ => row.ServiceCells.Sum(c => Measure(c.Title, 11, FontWeights.Normal, mono: false)
                                               + Measure(c.Text, 12, FontWeights.SemiBold, mono: false) + 20 + 6 + 6),
            };
            if (width > widest) widest = width;
        }

        return Math.Clamp(Math.Ceiling(widest), column.MinWidth, 700);
    }

    private static double Measure(string text, double size, Windows.UI.Text.FontWeight weight, bool mono)
    {
        if (string.IsNullOrEmpty(text)) return 0;
        var block = new TextBlock
        {
            Text = text,
            FontSize = size,
            FontWeight = weight,
            FontFamily = new FontFamily(mono ? "Cascadia Mono, Consolas" : "Segoe UI Variable"),
        };
        block.Measure(new Windows.Foundation.Size(double.PositiveInfinity, double.PositiveInfinity));
        return block.DesiredSize.Width;
    }

    // ── Selection and details ────────────────────────────────────────────────

    private void ResultsList_SelectionChanged(object sender, SelectionChangedEventArgs e) =>
        ViewModel.Selected = ResultsList.SelectedItem as HostRow;

    private void RefreshDetails(HostRow? row)
    {
        if (row is null)
        {
            DetailsTitle.Text = "Details";
            DetailsText.Text = "Select a host to see everything the scan learned about it.";
            DetailsActions.Visibility = Visibility.Collapsed;
            return;
        }

        DetailsTitle.Text = row.Address;
        DetailsText.Text = row.BuildDetails();
        DetailsActions.Visibility = Visibility.Visible;
        BrowserButton.IsEnabled = WebPort(row) is not null;
        RdpButton.IsEnabled = row.CellFor("rdp") is { IsOpen: true };
    }

    private static (string Scheme, int Port)? WebPort(HostRow row)
    {
        if (row.CellFor("http") is not { IsOpen: true } cell) return null;
        // Prefer plain HTTP on 80, then HTTPS on 443, then whatever answered first.
        int port = cell.OpenPorts.Contains(443) ? 443 : cell.OpenPorts.Contains(80) ? 80 : cell.OpenPorts[0];
        return (port is 443 or 8443 ? "https" : "http", port);
    }

    private void CopyIp_Click(object sender, RoutedEventArgs e) => Copy(ViewModel.Selected?.Address);
    private void CopyMac_Click(object sender, RoutedEventArgs e) => Copy(ViewModel.Selected?.Mac);

    private static void Copy(string? text)
    {
        if (string.IsNullOrEmpty(text)) return;
        var package = new DataPackage();
        package.SetText(text);
        Clipboard.SetContent(package);
    }

    private void OpenBrowser_Click(object sender, RoutedEventArgs e) => OpenBrowser(ViewModel.Selected);
    private void OpenRdp_Click(object sender, RoutedEventArgs e) => OpenRdp(ViewModel.Selected);

    private static void OpenBrowser(HostRow? row)
    {
        if (row is null || WebPort(row) is not var (scheme, port)) return;
        var url = port is 80 or 443 ? $"{scheme}://{row.Address}/" : $"{scheme}://{row.Address}:{port}/";
        Launch(new ProcessStartInfo(url) { UseShellExecute = true });
    }

    private static void OpenRdp(HostRow? row)
    {
        if (row is null) return;
        Launch(new ProcessStartInfo("mstsc.exe", $"/v:{row.Address}") { UseShellExecute = true });
    }

    private static void Launch(ProcessStartInfo info)
    {
        try { Process.Start(info); }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException) { }
    }

    private void ResultsList_DoubleTapped(object sender, DoubleTappedRoutedEventArgs e)
    {
        var row = RowFrom(e.OriginalSource);
        if (row is null) return;
        if (WebPort(row) is not null) OpenBrowser(row);
        else if (row.CellFor("rdp") is { IsOpen: true }) OpenRdp(row);
    }

    private void ResultsList_RightTapped(object sender, RightTappedRoutedEventArgs e)
    {
        var row = RowFrom(e.OriginalSource);
        if (row is null) return;
        ResultsList.SelectedItem = row;

        var menu = new MenuFlyout();
        menu.Items.Add(Item("Copy IP address", () => Copy(row.Address)));
        if (row.Mac.Length > 0) menu.Items.Add(Item("Copy MAC address", () => Copy(row.Mac)));
        menu.Items.Add(Item("Copy all details", () => Copy(row.BuildDetails())));
        if (WebPort(row) is not null || row.CellFor("rdp") is { IsOpen: true }) menu.Items.Add(new MenuFlyoutSeparator());
        if (WebPort(row) is not null) menu.Items.Add(Item("Open in browser", () => OpenBrowser(row)));
        if (row.CellFor("rdp") is { IsOpen: true }) menu.Items.Add(Item("Remote Desktop", () => OpenRdp(row)));
        menu.ShowAt(ResultsList, e.GetPosition(ResultsList));

        static MenuFlyoutItem Item(string text, Action action)
        {
            var item = new MenuFlyoutItem { Text = text };
            item.Click += (_, _) => action();
            return item;
        }
    }

    private static HostRow? RowFrom(object source) => (source as FrameworkElement)?.DataContext as HostRow;

    /// <summary>The effective theme changed: repaint the rows and rebuild the header (its dividers are themed).</summary>
    private void OnThemeChanged()
    {
        ViewModel.RefreshTheme();
        BuildHeader();
    }

    // ── Probes window ────────────────────────────────────────────────────────

    private async void PluginsButton_Click(object sender, RoutedEventArgs e)
    {
        if (_plugins is not null)
        {
            _plugins.Activate();
            return;
        }

        if (ViewModel.IsScanning)
        {
            await ShowMessageAsync("Service probes", "Stop the running scan before managing probes.");
            return;
        }

        _plugins = new PluginsWindow(ViewModel);
        _plugins.Closed += (_, _) =>
        {
            _plugins = null;
            // Probes (and their on/off state) may have changed; a scan started meanwhile keeps its own set.
            if (ViewModel.IsScanning) _probeRefreshPending = true;
            else RefreshProbeColumns();
        };
        _plugins.Activate();
    }

    // ── MAC vendor list ──────────────────────────────────────────────────────

    private void OnVendorsLoaded(bool offerUpdate)
    {
        if (!offerUpdate) return;
        bool missing = ViewModel.VendorInfo is null;
        VendorBar.Severity = InfoBarSeverity.Informational;
        VendorBar.Title = missing ? "No MAC vendor list was found" : "The MAC vendor list is out of date";
        VendorBar.Message = (missing ? "" : ViewModel.VendorStatusText + ". ")
            + "Updating downloads the current list from ieee.org (about 6 MB).";
        VendorUpdateButton.Visibility = Visibility.Visible;
        VendorBar.IsOpen = true;
    }

    private bool _vendorBusy;

    private async void VendorUpdate_Click(object sender, RoutedEventArgs e)
    {
        _vendorBusy = true;
        VendorUpdateButton.IsEnabled = false;
        VendorBar.Title = "Updating the MAC vendor list…";
        VendorBar.Message = "Downloading from ieee.org";
        try
        {
            var result = await ViewModel.UpdateVendorsAsync();
            bool ok = result.Status != OuiUpdateStatus.Failed;
            VendorBar.Severity = ok ? InfoBarSeverity.Success : InfoBarSeverity.Error;
            VendorBar.Title = result.Status switch
            {
                OuiUpdateStatus.Updated => "MAC vendor list updated",
                OuiUpdateStatus.AlreadyCurrent => "MAC vendor list is up to date",
                _ => "Could not update the MAC vendor list",
            };
            VendorBar.Message = ok ? $"{result.Message} {ViewModel.VendorStatusText}." : result.Message;
            VendorUpdateButton.Visibility = ok ? Visibility.Collapsed : Visibility.Visible;
        }
        finally
        {
            VendorUpdateButton.IsEnabled = true;
            _vendorBusy = false;
        }
    }

    /// <summary>Closing the reminder with its X means "not now": ask again in a week. Not while an update runs.</summary>
    private void VendorBar_Closed(InfoBar sender, InfoBarClosedEventArgs args)
    {
        if (!_vendorBusy && args.Reason == InfoBarCloseReason.CloseButton && VendorUpdateButton.Visibility == Visibility.Visible)
            ViewModel.SnoozeVendorReminder();
    }

    // ── Options ──────────────────────────────────────────────────────────────

    private async void OptionsButton_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel.IsScanning)
        {
            await ShowMessageAsync("Options", "Stop the running scan before changing options.");
            return;
        }

        var dialog = new OptionsDialog(ViewModel.Settings, ViewModel) { XamlRoot = Root.XamlRoot, RequestedTheme = Root.ActualTheme };
        if (await dialog.ShowAsync() != ContentDialogResult.Primary) return;

        ViewModel.SaveSettings();
        ViewModel.Layout.Load(ViewModel.Settings); // density and which columns are shown
        ThemeService.SetChoice(ViewModel.Settings.Theme);
    }

    private void UpdateProblemsBar()
    {
        var problems = ViewModel.ProbeProblems;
        ProblemsBar.IsOpen = problems.Count > 0;
        ProblemsBar.Message = string.Join("\n", problems.Take(6).Select(p => p.ToString()))
            + (problems.Count > 6 ? $"\n…and {problems.Count - 6} more" : "");
    }

    // ── Export ───────────────────────────────────────────────────────────────

    private async void ExportCsv_Click(object sender, RoutedEventArgs e) =>
        await ExportAsync("CSV file", ".csv", Exporter.ToCsv);

    private async void ExportJson_Click(object sender, RoutedEventArgs e) =>
        await ExportAsync("JSON file", ".json", Exporter.ToJson);

    private async Task ExportAsync(string typeName, string extension, Func<IReadOnlyList<HostRow>, string> render)
    {
        var picker = new FileSavePicker
        {
            SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
            SuggestedFileName = $"scan-{DateTime.Now:yyyy-MM-dd-HHmm}",
        };
        picker.FileTypeChoices.Add(typeName, [extension]);
        WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));

        var file = await picker.PickSaveFileAsync();
        if (file is null) return;

        try
        {
            await File.WriteAllTextAsync(file.Path, render([.. ViewModel.Rows]), new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
            ViewModel.StatusText = $"Exported {ViewModel.Rows.Count} hosts to {file.Name}";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            await ShowMessageAsync("Export failed", ex.Message);
        }
    }

    private async Task ShowMessageAsync(string title, string message) =>
        await new ContentDialog
        {
            Title = title,
            Content = message,
            CloseButtonText = "OK",
            RequestedTheme = Root.ActualTheme,
            XamlRoot = Root.XamlRoot,
        }.ShowAsync();
}
