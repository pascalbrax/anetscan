using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using ANetworkScanner.Engine;
using ANetworkScanner.Engine.Discovery;
using ANetworkScanner.Engine.Probes;
using ANetworkScanner.Engine.Settings;
using ANetworkScanner.Engine.Targets;
using ANetworkScanner.Engine.Vendors;
using CommunityToolkit.Mvvm.ComponentModel;
using Microsoft.UI.Dispatching;

namespace ANetworkScanner.App.ViewModels;

public enum SortColumn
{
    Address,
    Name,
    Rtt,
    Mac,
    Vendor,
    Method,
    Probe,
}

/// <summary>
/// Owns the scan: starts the engine on a background task, queues its events, and applies them to the UI in
/// batches every 50 ms. Thousands of events per second therefore never flood the dispatcher.
/// </summary>
public sealed partial class MainViewModel : ObservableObject
{
    private readonly DispatcherQueue _dispatcher;
    private readonly SettingsStore _store = new();
    private readonly ConcurrentQueue<ScanEvent> _queue = new();
    private readonly Dictionary<uint, HostRow> _byAddress = [];
    private readonly List<HostRow> _all = [];
    private readonly Stopwatch _clock = new();
    private readonly SystemArpResolver _arp = new();
    private readonly OuiStore _ouiStore = OuiStore.CreateDefault();
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(90) };
    private DispatcherQueueTimer? _timer;
    private CancellationTokenSource? _cts;
    private Task? _reader;
    private Exception? _readerError;
    private TargetSet _targets = TargetSet.Empty;
    private long _expectedProbes;
    private long _probesDone;
    private bool _stopped;
    private IReadOnlyList<ProbeDefinition> _scanProbes = [];
    private bool _scanResolvesNames;

    public MainViewModel(DispatcherQueue dispatcher)
    {
        _dispatcher = dispatcher;
        Settings = _store.Load();
        Layout.Load(Settings);
        LoadProbes();
        Target = Settings.RecentTargets.FirstOrDefault() ?? "";
        RefreshSuggestions();
        StatusText = "Ready";
    }

    public AppSettings Settings { get; private set; }

    /// <summary>Column widths and row height shared by the header and every row.</summary>
    public TableLayout Layout { get; } = new();

    public ObservableCollection<HostRow> Rows { get; } = [];
    public ObservableCollection<string> TargetSuggestions { get; } = [];

    /// <summary>The MAC vendor list; empty until the background load finishes.</summary>
    public MacVendors Vendors { get; private set; } = MacVendors.Empty;

    /// <summary>Where the list came from and how old it is; null when no list could be loaded.</summary>
    public OuiInfo? VendorInfo { get; private set; }

    public IReadOnlyList<ProbeDefinition> AllProbes { get; private set; } = [];
    public IReadOnlyList<ProbeProblem> ProbeProblems { get; private set; } = [];
    public IReadOnlyList<ProbeDefinition> EnabledProbes =>
        [.. AllProbes.Where(p => !Settings.DisabledProbes.Contains(p.Id, StringComparer.OrdinalIgnoreCase))];

    public SortColumn SortBy { get; private set; } = SortColumn.Address;
    public string? SortProbeId { get; private set; }
    public bool SortDescending { get; private set; }

    [ObservableProperty] public partial string Target { get; set; } = "";
    [ObservableProperty] public partial string ErrorText { get; set; } = "";
    [ObservableProperty] public partial string StatusText { get; set; } = "";
    [ObservableProperty] public partial string CountsText { get; set; } = "";
    [ObservableProperty] public partial string ElapsedText { get; set; } = "";
    [ObservableProperty] public partial double Progress { get; set; }
    [ObservableProperty] public partial bool IsScanning { get; set; }
    [ObservableProperty] public partial bool HasResults { get; set; }
    [ObservableProperty] public partial HostRow? Selected { get; set; }

    /// <summary>Raised on the UI thread when a scan starts, so the window can rebuild columns and the map.</summary>
    public event Action<TargetSet, IReadOnlyList<ProbeDefinition>>? ScanStarted;
    /// <summary>Raised for every target once discovery has settled it.</summary>
    public event Action<uint, bool>? TargetScanned;
    public event Action? ScanFinished;
    /// <summary>The vendor list was (re)loaded. The argument says whether an update should be offered.</summary>
    public event Action<bool>? VendorsLoaded;
    /// <summary>The list changed in a way that needs the selected host's details redrawn.</summary>
    public event Action<HostRow>? SelectedChanged;

    // ── MAC vendors ──────────────────────────────────────────────────────────

    /// <summary>Loads the vendor list on a background thread and fills in the vendors of rows already shown.</summary>
    public async Task LoadVendorsAsync()
    {
        var (vendors, info) = await Task.Run(_ouiStore.Load);
        Vendors = vendors;
        VendorInfo = info;
        foreach (var row in _all) row.ApplyVendor(vendors);
        if (Selected is { } selected) SelectedChanged?.Invoke(selected);

        VendorsLoaded?.Invoke(ShouldOfferVendorUpdate());
    }

    /// <summary>True when the list is older than two months (or missing) and the user has not muted or snoozed the reminder.</summary>
    public bool ShouldOfferVendorUpdate()
    {
        if (!Settings.RemindAboutVendorUpdates) return false;
        if (Settings.VendorReminderSnoozedUntilUtc is { } until && until > DateTime.UtcNow) return false;
        return OuiStore.IsStale(VendorInfo, DateTime.UtcNow);
    }

    /// <summary>"Not now": stay quiet for a week.</summary>
    public void SnoozeVendorReminder()
    {
        Settings.VendorReminderSnoozedUntilUtc = DateTime.UtcNow.AddDays(7);
        SaveSettings();
    }

    /// <summary>Downloads the current IEEE list (only ever called because the user asked) and reloads it.</summary>
    public async Task<OuiUpdateResult> UpdateVendorsAsync(CancellationToken cancellationToken = default)
    {
        var result = await _ouiStore.UpdateAsync(Http, cancellationToken);
        if (result.Status != OuiUpdateStatus.Failed)
        {
            Settings.VendorReminderSnoozedUntilUtc = null;
            SaveSettings();
            await LoadVendorsAsync();
        }
        return result;
    }

    /// <summary>"Vendor list: 40,319 entries, from 8 Oct 2026 (today)".</summary>
    public string VendorStatusText
    {
        get
        {
            if (VendorInfo is not { } info) return "No vendor list found.";
            int days = (int)info.Age(DateTime.UtcNow).TotalDays;
            string age = days <= 0 ? "today" : days == 1 ? "yesterday" : $"{days} days ago";
            return $"{info.Entries:N0} vendors, downloaded {info.DownloadedUtc.ToLocalTime():d MMM yyyy} ({age})";
        }
    }

    // ── Probes and settings ──────────────────────────────────────────────────

    public void LoadProbes()
    {
        var loaded = ProbeLoader.LoadDirectories(
            Path.Combine(AppContext.BaseDirectory, "probes"),
            Path.Combine(SettingsStore.DefaultDirectory, "probes"));
        AllProbes = loaded.Probes;
        ProbeProblems = loaded.Problems;
    }

    public void SaveSettings()
    {
        try { _store.Save(Settings); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            ErrorText = $"Could not save settings: {ex.Message}";
        }
    }

    public void RefreshSuggestions()
    {
        TargetSuggestions.Clear();
        foreach (var t in Settings.RecentTargets) TargetSuggestions.Add(t);
        try
        {
            foreach (var cidr in LocalSubnets.Detect().Cidrs)
                if (!TargetSuggestions.Contains(cidr, StringComparer.OrdinalIgnoreCase)) TargetSuggestions.Add(cidr);
        }
        catch (Exception ex) when (ex is System.Net.NetworkInformation.NetworkInformationException)
        {
            // No adapter information: recents only.
        }

        if (Target.Length == 0 && TargetSuggestions.Count > 0) Target = TargetSuggestions[0];
    }

    // ── Scan ─────────────────────────────────────────────────────────────────

    /// <summary>The theme changed: rows repaint their status dots and result pills.</summary>
    public void RefreshTheme()
    {
        foreach (var row in _all) row.RefreshBrushes();
    }

    public bool StartScan()
    {
        if (IsScanning) return false;

        if (!TargetSet.TryParse(Target, out var targets, out var error))
        {
            ErrorText = error;
            return false;
        }
        ErrorText = "";

        Settings.AddRecentTarget(Target);
        SaveSettings();
        RefreshSuggestions();

        _targets = targets;
        Rows.Clear();
        _all.Clear();
        _byAddress.Clear();
        Selected = null;
        HasResults = false;
        _expectedProbes = _probesDone = 0;
        _scanned = _alive = 0;
        _stopped = false;
        _readerError = null;
        while (_queue.TryDequeue(out _)) { }

        var probes = _scanProbes = EnabledProbes;
        _scanResolvesNames = Settings.Discovery.ResolveNames;
        CountsText = "";
        Progress = 0;
        IsScanning = true;
        StatusText = $"Scanning {targets.Count:N0} addresses…";
        ScanStarted?.Invoke(targets, probes);

        var subnets = LocalSubnets.Detect();
        var engine = new ScanEngine(new SystemPinger(), Settings.Discovery, subnets, _arp);
        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        _clock.Restart();
        _reader = Task.Run(async () =>
        {
            try
            {
                await foreach (var e in engine.RunAsync(targets, probes, token).ConfigureAwait(false))
                    _queue.Enqueue(e);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) { _readerError = ex; }
        });

        _timer = _dispatcher.CreateTimer();
        _timer.Interval = TimeSpan.FromMilliseconds(50);
        _timer.Tick += OnTick;
        _timer.Start();
        return true;
    }

    public void StopScan()
    {
        if (!IsScanning) return;
        _stopped = true;
        StatusText = "Stopping…";
        _cts?.Cancel();
    }

    private void OnTick(DispatcherQueueTimer sender, object args)
    {
        int budget = 3000;
        while (budget-- > 0 && _queue.TryDequeue(out var e)) Apply(e);

        UpdateProgress();

        if (_reader is { IsCompleted: true } && _queue.IsEmpty)
        {
            sender.Stop();
            sender.Tick -= OnTick;
            Finish();
        }
    }

    private int _scanned, _alive;

    private void Apply(ScanEvent e)
    {
        switch (e)
        {
            case HostScanned h:
                _scanned++;
                TargetScanned?.Invoke(TargetSet.ToValue(h.Host.Address), h.Host.IsAlive);
                if (h.Host.IsAlive)
                {
                    _alive++;
                    var row = new HostRow(h.Host, _scanProbes, Layout);
                    row.ApplyVendor(Vendors);
                    if (_scanResolvesNames) row.BeginName();
                    _expectedProbes += _scanProbes.Count;
                    _byAddress[row.Value] = row;
                    InsertSorted(row);
                    HasResults = true;
                }
                break;

            case NameResolved n:
                if (_byAddress.TryGetValue(TargetSet.ToValue(n.Address), out var named))
                {
                    named.ApplyName(n.Name);
                    if (ReferenceEquals(named, Selected)) SelectedChanged?.Invoke(named);
                }
                break;

            case ProbeCompleted p:
                _probesDone++;
                if (_byAddress.TryGetValue(TargetSet.ToValue(p.Address), out var owner))
                {
                    owner.CellFor(p.Result.ProbeId)?.Apply(p.Result);
                    owner.UpdateDevice();
                    if (ReferenceEquals(owner, Selected)) SelectedChanged?.Invoke(owner);
                }
                break;
        }
    }

    private void UpdateProgress()
    {
        long total = _targets.Count + _expectedProbes;
        long done = _scanned + _probesDone;
        Progress = total == 0 ? 0 : Math.Min(100.0, done * 100.0 / total);

        bool discovering = _scanned < _targets.Count;
        StatusText = _stopped ? "Stopping…"
            : discovering ? $"Discovering hosts… {_scanned:N0} of {_targets.Count:N0}"
            : $"Probing services… {_probesDone:N0} of {_expectedProbes:N0}";
        CountsText = $"{_alive:N0} alive";
        ElapsedText = FormatElapsed(_clock.Elapsed);
    }

    private void Finish()
    {
        _clock.Stop();
        _cts?.Dispose();
        _cts = null;
        IsScanning = false;
        Progress = 100;
        var elapsed = FormatElapsed(_clock.Elapsed);
        ElapsedText = elapsed;
        CountsText = $"{_alive:N0} alive of {_scanned:N0}";

        StatusText = _readerError is not null ? $"Scan failed: {_readerError.Message}"
            : _stopped ? $"Stopped after {elapsed}"
            : $"Done in {elapsed}";
        _scanned = _alive = 0;
        ScanFinished?.Invoke();
    }

    private static string FormatElapsed(TimeSpan t) =>
        t.TotalMinutes >= 1 ? t.ToString(@"m\:ss", CultureInfo.InvariantCulture) : $"{t.TotalSeconds:0.0} s";

    // ── Sorting ──────────────────────────────────────────────────────────────

    public void SortOn(SortColumn column, string? probeId = null)
    {
        if (SortBy == column && SortProbeId == probeId) SortDescending = !SortDescending;
        else
        {
            SortBy = column;
            SortProbeId = probeId;
            SortDescending = false;
        }

        _all.Sort(Compare);
        var selected = Selected;
        Rows.Clear();
        foreach (var row in _all) Rows.Add(row);
        Selected = selected;
        OnPropertyChanged(nameof(SortBy));
    }

    private void InsertSorted(HostRow row)
    {
        int lo = 0, hi = _all.Count;
        while (lo < hi)
        {
            int mid = (lo + hi) / 2;
            if (Compare(_all[mid], row) <= 0) lo = mid + 1; else hi = mid;
        }
        _all.Insert(lo, row);
        Rows.Insert(lo, row);
    }

    private int Compare(HostRow a, HostRow b)
    {
        int result = SortBy switch
        {
            SortColumn.Name => string.Compare(a.Name.Length == 0 ? "\uFFFF" : a.Name, b.Name.Length == 0 ? "\uFFFF" : b.Name,
                                              StringComparison.OrdinalIgnoreCase),
            SortColumn.Rtt => (a.RttMs < 0 ? double.MaxValue : a.RttMs).CompareTo(b.RttMs < 0 ? double.MaxValue : b.RttMs),
            SortColumn.Mac => string.Compare(a.Mac, b.Mac, StringComparison.OrdinalIgnoreCase),
            SortColumn.Vendor => string.Compare(a.VendorText.Length == 0 ? "￿" : a.VendorText,
                                                b.VendorText.Length == 0 ? "￿" : b.VendorText, StringComparison.OrdinalIgnoreCase),
            SortColumn.Method => string.Compare(a.MethodText, b.MethodText, StringComparison.Ordinal),
            SortColumn.Probe => string.Compare(CellText(a), CellText(b), StringComparison.OrdinalIgnoreCase),
            _ => a.Value.CompareTo(b.Value),
        };
        if (result == 0) result = a.Value.CompareTo(b.Value);
        return SortDescending ? -result : result;

        string CellText(HostRow r) => r.CellFor(SortProbeId ?? "") is { IsOpen: true } c ? c.Text : "￿";
    }
}
