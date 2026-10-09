using ANetworkScanner.Engine.Settings;
using CommunityToolkit.Mvvm.ComponentModel;

namespace ANetworkScanner.App.ViewModels;

/// <summary>One resizable column. Rows and the header bind to the same instance, so a drag moves them together.</summary>
public sealed partial class ColumnInfo : ObservableObject
{
    public ColumnInfo(string key, string title, double defaultWidth, double minWidth, bool canHide = true)
    {
        Key = key;
        Title = title;
        DefaultWidth = defaultWidth;
        MinWidth = minWidth;
        CanHide = canHide;
        Width = defaultWidth;
        IsVisible = true;
    }

    public string Key { get; }
    public string Title { get; }
    public double DefaultWidth { get; }
    public double MinWidth { get; }

    /// <summary>The IP address column is the row's identity and cannot be hidden.</summary>
    public bool CanHide { get; }

    [ObservableProperty] public partial double Width { get; set; }
    [ObservableProperty] public partial bool IsVisible { get; set; }

    public void SetWidth(double width) => Width = Math.Round(Math.Clamp(width, MinWidth, 800));
}

/// <summary>The shared geometry of the results table: which columns show, their widths, and the row height.</summary>
public sealed partial class TableLayout : ObservableObject
{
    public const double StatusWidth = 36;
    private const double ComfortableRow = 46, CompactRow = 34;

    private readonly Dictionary<string, ColumnInfo> _probeColumns = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, double> _saved = new(StringComparer.OrdinalIgnoreCase);

    public TableLayout()
    {
        Address = Track(new ColumnInfo("address", "IP address", 210, 140, canHide: false));
        Name = Track(new ColumnInfo("name", "Hostname", 220, 100));
        Rtt = Track(new ColumnInfo("rtt", "RTT", 84, 56));
        Mac = Track(new ColumnInfo("mac", "MAC address", 150, 110));
        Vendor = Track(new ColumnInfo("vendor", "Vendor", 170, 90));
        Method = Track(new ColumnInfo("method", "Found by", 104, 70));
        RowHeight = ComfortableRow;
    }

    public ColumnInfo Address { get; }
    public ColumnInfo Name { get; }
    public ColumnInfo Rtt { get; }
    public ColumnInfo Mac { get; }
    public ColumnInfo Vendor { get; }
    public ColumnInfo Method { get; }

    [ObservableProperty] public partial double RowHeight { get; set; }

    /// <summary>Raised when any column width changes (the window resizes its scrollable area).</summary>
    public event Action? WidthsChanged;

    /// <summary>Raised when a column is shown or hidden (the window rebuilds the header).</summary>
    public event Action? VisibilityChanged;

    /// <summary>All built-in columns in display order.</summary>
    public IReadOnlyList<ColumnInfo> FixedColumns => [Address, Name, Rtt, Mac, Vendor, Method];

    /// <summary>The columns shown to the left of the probe columns, in display order.</summary>
    public IEnumerable<ColumnInfo> VisibleFixedColumns => FixedColumns.Where(c => c.IsVisible);

    /// <summary>The column of a probe, created on first use with its saved width if there is one.</summary>
    public ColumnInfo ProbeColumn(string probeId, string title)
    {
        if (_probeColumns.TryGetValue(probeId, out var existing)) return existing;
        var column = Track(new ColumnInfo("probe:" + probeId, title, 160, 80, canHide: false));
        if (_saved.TryGetValue(column.Key, out var width)) column.SetWidth(width);
        _probeColumns[probeId] = column;
        return column;
    }

    public double TotalWidth(IEnumerable<ColumnInfo> probeColumns) =>
        StatusWidth + VisibleFixedColumns.Sum(c => c.Width) + probeColumns.Sum(c => c.Width) + 28;

    public void ApplyDensity(bool compact) => RowHeight = compact ? CompactRow : ComfortableRow;

    /// <summary>Applies saved widths, hidden columns and density.</summary>
    public void Load(AppSettings settings)
    {
        _saved.Clear();
        foreach (var (key, width) in settings.ColumnWidths) _saved[key] = width;
        foreach (var column in FixedColumns.Concat(_probeColumns.Values))
            if (_saved.TryGetValue(column.Key, out var width)) column.SetWidth(width);

        bool changed = false;
        foreach (var column in FixedColumns)
        {
            bool visible = !column.CanHide || !settings.HiddenColumns.Contains(column.Key, StringComparer.OrdinalIgnoreCase);
            // The hostname column is pointless while name resolution is off, so it only shows when both allow it.
            if (column == Name) visible &= settings.Discovery.ResolveNames;
            if (column.IsVisible == visible) continue;
            column.IsVisible = visible;
            changed = true;
        }
        if (changed) VisibilityChanged?.Invoke();

        ApplyDensity(settings.CompactRows);
    }

    /// <summary>Stores the widths that differ from the defaults; columns left alone stay at their default.</summary>
    public void Save(AppSettings settings)
    {
        foreach (var column in FixedColumns.Concat(_probeColumns.Values))
        {
            if (Math.Abs(column.Width - column.DefaultWidth) < 0.5) settings.ColumnWidths.Remove(column.Key);
            else settings.ColumnWidths[column.Key] = column.Width;
        }
        Load(settings);
    }

    private ColumnInfo Track(ColumnInfo column)
    {
        column.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(ColumnInfo.Width)) WidthsChanged?.Invoke();
        };
        return column;
    }
}
