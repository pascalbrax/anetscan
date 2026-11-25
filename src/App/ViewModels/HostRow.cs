using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using ANetworkScanner.Engine;
using ANetworkScanner.Engine.Discovery;
using ANetworkScanner.Engine.Names;
using ANetworkScanner.Engine.Probes;
using ANetworkScanner.Engine.Vendors;
using CommunityToolkit.Mvvm.ComponentModel;
using Microsoft.UI.Xaml.Media;

namespace ANetworkScanner.App.ViewModels;

/// <summary>One probe's cell in a host row: "…" while running, then a coloured pill with the result.</summary>
public sealed partial class ProbeCell : ObservableObject
{
    public ProbeCell(string probeId, string title, ColumnInfo column)
    {
        ProbeId = probeId;
        Title = title;
        Column = column;
        column.PropertyChanged += OnColumnChanged;
        Text = "…";
        RefreshBrushes();
    }

    private enum Look { Pending, Dash, Result, Error }

    private Look _look = Look.Pending;
    private ProbeLevel _level;

    /// <summary>Recomputes the colours from the current theme (the cell remembers whether it is a result, a dash, ...).</summary>
    public void RefreshBrushes()
    {
        switch (_look)
        {
            case Look.Result:
                (Foreground, Background) = _level switch
                {
                    ProbeLevel.Good => (Palette.Success, Palette.SuccessBackground),
                    ProbeLevel.Warning => (Palette.Caution, Palette.CautionBackground),
                    ProbeLevel.Bad => (Palette.Critical, Palette.CriticalBackground),
                    _ => (Palette.Primary, Palette.NeutralBackground),
                };
                SetPill(true);
                break;

            case Look.Error:
                (Foreground, Background) = (Palette.Critical, Palette.CriticalBackground);
                SetPill(true);
                break;

            default:
                (Foreground, Background) = (Palette.Tertiary, Palette.NeutralBackground);
                SetPill(false);
                break;
        }
    }

    public string ProbeId { get; }
    public string Title { get; }
    public ColumnInfo Column { get; }

    /// <summary>The pill never grows past its column; the text is trimmed with an ellipsis instead.</summary>
    public double PillMaxWidth => Math.Max(24, Column.Width - 12);

    [ObservableProperty] public partial string Text { get; set; }
    [ObservableProperty] public partial Brush Foreground { get; set; }
    [ObservableProperty] public partial Brush Background { get; set; }
    [ObservableProperty] public partial bool IsPill { get; set; }
    [ObservableProperty] public partial bool IsPlain { get; set; }

    /// <summary>False until the probe finished (with any outcome).</summary>
    public bool IsDone { get; private set; }

    /// <summary>The probe's detail text for the side panel; empty until the probe finished with an open port.</summary>
    public string Detail { get; private set; } = "";

    public bool IsOpen { get; private set; }

    /// <summary>Ports that answered, lowest first.</summary>
    public IReadOnlyList<int> OpenPorts { get; private set; } = [];

    public void Apply(ProbeResult result)
    {
        IsDone = true;
        OpenPorts = [.. result.Ports.Where(p => p.State == PortState.Open).Select(p => p.Port).Order()];
        Detail = result.Long;

        switch (result.State)
        {
            case PortState.Open:
                IsOpen = true;
                Text = result.Short;
                _look = Look.Result;
                _level = result.Level;
                break;

            case PortState.Error:
                Text = "error";
                _look = Look.Error;
                break;

            default:
                Text = "—";
                _look = Look.Dash;
                break;
        }
        RefreshBrushes();
    }

    private void SetPill(bool pill)
    {
        IsPill = pill;
        IsPlain = !pill;
    }

    private void OnColumnChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(ColumnInfo.Width)) OnPropertyChanged(nameof(PillMaxWidth));
    }
}

/// <summary>A live host in the results grid.</summary>
public sealed partial class HostRow : ObservableObject
{
    public HostRow(HostObservation host, IEnumerable<ProbeDefinition> probes, TableLayout layout)
    {
        Layout = layout;
        Address = host.Address.ToString();
        Value = Engine.Targets.TargetSet.ToValue(host.Address);
        Method = host.Method;
        Mac = host.Mac ?? "";
        Ttl = host.Ttl;
        RttMs = host.Method.HasFlag(DiscoveryMethod.Icmp) ? host.RttMs : -1;
        RttText = RttMs < 0 ? "—" : RttMs < 1 ? "<1 ms" : string.Create(CultureInfo.InvariantCulture, $"{RttMs:0.#} ms");
        MethodText = host.Method switch
        {
            DiscoveryMethod.Icmp => "ICMP",
            DiscoveryMethod.Arp => "ARP only",
            DiscoveryMethod.Tcp => "TCP only",
            _ => "ICMP + ARP",
        };
        DiscoveryDetail = host.Detail;
        DotBrush = IsWeakEvidence ? Palette.Caution : Palette.Success;
        foreach (var p in probes) Cells.Add(new ProbeCell(p.Id, p.Title, layout.Services));

        DeviceGlyph = "";
        UpdateDevice();
    }

    public TableLayout Layout { get; }
    public string Address { get; }
    public uint Value { get; }
    public DiscoveryMethod Method { get; }
    public string MethodText { get; }
    public string Mac { get; }
    public int Ttl { get; }
    public double RttMs { get; }
    public string RttText { get; }
    [ObservableProperty] public partial Brush DotBrush { get; set; }

    /// <summary>The resolved hostname; empty until (or unless) a source knows one.</summary>
    public string Name { get; private set; } = "";

    /// <summary>Which source supplied the name: DNS, mDNS or NetBIOS.</summary>
    public string NameSourceText { get; private set; } = "";

    /// <summary>What the Hostname column shows: "…" while looking, the name, or "—" when nobody knows it.</summary>
    [ObservableProperty] public partial string NameText { get; set; } = "";
    [ObservableProperty] public partial double NameOpacity { get; set; } = 1;
    [ObservableProperty] public partial string NameTip { get; set; } = "";

    /// <summary>The lookup has been started: show a placeholder until it answers.</summary>
    public void BeginName()
    {
        NameText = "…";
        NameOpacity = 0.5;
        NameTip = "Looking up the hostname…";
    }

    public void ApplyName(HostName? name)
    {
        Name = name?.Name ?? "";
        NameSourceText = name?.SourceText ?? "";
        NameText = name is null ? "—" : name.Name;
        NameOpacity = name is null ? 0.5 : 1;
        NameTip = name is null ? "No DNS, mDNS or NetBIOS name found" : $"{name.Name}\nvia {name.SourceText}";
        UpdateDevice();
    }

    /// <summary>The registered company name from the IEEE list; empty when unknown.</summary>
    public string Vendor { get; private set; } = "";

    /// <summary>What the Vendor column shows: the short company name, or "Private address" for a randomized MAC.</summary>
    [ObservableProperty] public partial string VendorText { get; set; } = "";
    [ObservableProperty] public partial double VendorOpacity { get; set; } = 1;

    [ObservableProperty] public partial string DeviceGlyph { get; set; }
    [ObservableProperty] public partial string DeviceTip { get; set; } = "";
    [ObservableProperty] public partial double DeviceOpacity { get; set; } = 0.45;

    public DeviceGuess Device { get; private set; } = DeviceGuess.Unknown;

    public ObservableCollection<ProbeCell> Cells { get; } = [];

    /// <summary>The probes that found something: these are the pills of the Services column.</summary>
    public ObservableCollection<ProbeCell> ServiceCells { get; } = [];

    /// <summary>Shown instead of pills: "…" while probes run, "—" when none found anything.</summary>
    [ObservableProperty] public partial string ServicesPlaceholder { get; set; } = "…";

    /// <summary>1 normally; lower for rows the Services filter does not select (they stay in place, just faded).</summary>
    [ObservableProperty] public partial double RowOpacity { get; set; } = 1;

    /// <summary>Fades the row unless it has one of the selected services (an empty selection selects everything).</summary>
    public void ApplyServiceFilter(ISet<string> selected)
    {
        MatchesServiceFilter = selected.Count == 0 || ServiceCells.Any(c => selected.Contains(c.Title));
        RowOpacity = MatchesServiceFilter ? 1 : 0.3;
    }

    public bool MatchesServiceFilter { get; private set; } = true;

    /// <summary>One line per service, for the tooltip of the whole column (long lists do not fit the cell).</summary>
    [ObservableProperty] public partial string ServicesTip { get; set; } = "";

    /// <summary>Sort key of the Services column: the services as text, rows without any last.</summary>
    public string ServicesSortKey => ServiceCells.Count == 0 ? "\uFFFF" : string.Join(" ", ServiceCells.Select(c => c.Title + " " + c.Text));

    /// <summary>Also the accessible name of the list item.</summary>
    public override string ToString() => $"{Address}, {MethodText}";

    /// <summary>What the discovery stage noted (for a TCP-only host: which port gave it away).</summary>
    public string DiscoveryDetail { get; } = "";

    /// <summary>Found without an ICMP echo reply: flagged amber, since something is filtering ping.</summary>
    private bool IsWeakEvidence => Method is DiscoveryMethod.Arp or DiscoveryMethod.Tcp;

    public string DotTooltip => Method switch
    {
        DiscoveryMethod.Arp => "Answers ARP but not ping (a firewall is probably blocking ICMP)",
        DiscoveryMethod.Tcp => "Answers neither ping nor ARP; found because a TCP port answered (" + DiscoveryDetail + ")",
        _ => "Alive",
    };

    /// <summary>TTL gives only a weak hint: routers and embedded devices often differ from the OS default.</summary>
    public string TtlHint => Ttl switch
    {
        <= 0 => "",
        <= 64 => $"{Ttl} (Linux, macOS or embedded?)",
        <= 128 => $"{Ttl} (Windows?)",
        _ => $"{Ttl} (network device?)",
    };

    /// <summary>Looks the MAC up in the vendor list (also called again when a newer list is loaded).</summary>
    public void ApplyVendor(MacVendors vendors)
    {
        Vendor = vendors.Lookup(Mac) ?? "";
        VendorText = vendors.Describe(Mac);
        VendorOpacity = VendorText == "Private address" ? 0.55 : 1;
        UpdateDevice();
    }

    private void SyncServices()
    {
        var open = Cells.Where(c => c.IsOpen && c.Text.Length > 0).ToList();
        if (!open.SequenceEqual(ServiceCells))
        {
            ServiceCells.Clear();
            foreach (var cell in open) ServiceCells.Add(cell);
        }

        ServicesPlaceholder = open.Count > 0 ? "" : Cells.Any(c => !c.IsDone) ? "…" : Cells.Count == 0 ? "" : "—";
        ServicesTip = open.Count > 0 ? string.Join("\n", open.Select(c => $"{c.Title}: {c.Text}")) : "";
    }

    /// <summary>The theme changed: repaint everything that was coloured from code.</summary>
    public void RefreshBrushes()
    {
        DotBrush = IsWeakEvidence ? Palette.Caution : Palette.Success;
        foreach (var cell in Cells) cell.RefreshBrushes();
    }

    public ProbeCell? CellFor(string probeId) => Cells.FirstOrDefault(c => c.ProbeId == probeId);

    /// <summary>Re-guesses the device type from everything known so far. Call after each probe result.</summary>
    public void UpdateDevice()
    {
        SyncServices();
        var services = Cells.Where(c => c.IsOpen)
            .Select(c => new ServiceEvidence(c.ProbeId, c.OpenPorts, c.Text, c.Detail))
            .ToList();
        bool complete = Cells.All(c => c.IsDone);

        Device = DeviceClassifier.Classify(new DeviceEvidence(Ttl, Mac.Length > 0 ? Mac : null, services, complete,
            Vendor.Length > 0 ? Vendor : null, Name.Length > 0 ? Name : null));
        DeviceGlyph = Device.Kind switch
        {
            DeviceKind.Computer => "",
            DeviceKind.Server => "",
            DeviceKind.Printer => "",
            DeviceKind.NetworkDevice => "",
            DeviceKind.Camera => "",
            DeviceKind.IpPhone => "",
            DeviceKind.Mobile => "",
            _ => "",
        };
        DeviceOpacity = Device.Kind == DeviceKind.Unknown ? 0.4 : 1.0;
        DeviceTip = Device.Kind == DeviceKind.Unknown
            ? "Device type unknown"
            : $"{KindName(Device.Kind)} (guess): {Device.Reason}";
    }

    public static string KindName(DeviceKind kind) => kind switch
    {
        DeviceKind.Computer => "Computer",
        DeviceKind.Server => "Server",
        DeviceKind.Printer => "Printer",
        DeviceKind.NetworkDevice => "Network device",
        DeviceKind.Camera => "Camera",
        DeviceKind.IpPhone => "IP phone",
        DeviceKind.Mobile => "Phone or laptop",
        _ => "Unknown",
    };

    /// <summary>Everything known about the host, for the details panel and "copy details".</summary>
    public string BuildDetails()
    {
        var lines = new List<string>
        {
            $"Address  : {Address}",
            $"Found by : {MethodText}",
        };
        if (Method == DiscoveryMethod.Tcp && DiscoveryDetail.Length > 0) lines.Add($"Reason   : {DiscoveryDetail}");
        if (Name.Length > 0) lines.Add($"Hostname : {Name}  (via {NameSourceText})");
        if (Device.Kind != DeviceKind.Unknown) lines.Add($"Device   : {KindName(Device.Kind)} (guess)");
        if (Mac.Length > 0) lines.Add($"MAC      : {Mac}");
        if (Vendor.Length > 0) lines.Add($"Vendor   : {Vendor}");
        else if (VendorText == "Private address") lines.Add("Vendor   : none (randomized private address)");
        if (RttMs >= 0) lines.Add($"RTT      : {RttText}");
        if (Ttl > 0) lines.Add($"TTL      : {TtlHint}");
        if (Device.Kind != DeviceKind.Unknown) lines.Add($"Because  : {Device.Reason}");

        foreach (var cell in Cells.Where(c => c.Detail.Length > 0 && c.IsOpen))
        {
            lines.Add("");
            lines.Add(cell.Detail);
        }

        if (Cells.Any(c => !c.IsDone)) { lines.Add(""); lines.Add("Probes still running…"); }
        else if (!Cells.Any(c => c.IsOpen) && Cells.Count > 0) { lines.Add(""); lines.Add("No probe found an open service."); }
        return string.Join("\n", lines);
    }
}


