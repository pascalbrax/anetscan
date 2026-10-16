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

    private readonly Dictionary<string, double> _saved = new(StringComparer.OrdinalIgnoreCase);

    public TableLayout()
    {
        Address = Track(new ColumnInfo("address", "IP address", 210, 140, canHide: false));
        Name = Track(new ColumnInfo("name", "Hostname", 220, 100));
        Rtt = Track(new ColumnInfo("rtt", "RTT", 84, 56));
        Mac = Track(new ColumnInfo("mac", "MAC address", 150, 110));
        Vendor = Track(new ColumnInfo("vendor", "Vendor", 170, 90));
        Method = Track(new ColumnInfo("method", "Found by", 104, 70));
        Services = Track(new ColumnInfo("services", "Services", 440, 120, canHide: false));
        RowHeight = ComfortableRow;
    }

    public ColumnInfo Address { get; }
    public ColumnInfo Name { get; }
    public ColumnInfo Rtt { get; }
    public ColumnInfo Mac { get; }
    public ColumnInfo Vendor { get; }
    public ColumnInfo Method { get; }

    /// <summary>All probe results of a host, merged into one column of pills.</summary>
    public ColumnInfo Services { get; }

    [ObservableProperty] public partial double RowHeight { get; set; }

    /// <summary>Raised when any column width changes (the window resizes its scrollable area).</summary>
    public event Action? WidthsChanged;

    /// <summary>Raised when a column is shown or hidden (the window rebuilds the header).</summary>
    public event Action? VisibilityChanged;

    /// <summary>All built-in columns in display order.</summary>
    public IReadOnlyList<ColumnInfo> FixedColumns => [Address, Name, Rtt, Mac, Vendor, Method, Services];

    /// <summary>The columns that are currently shown, in display order.</summary>
    public IEnumerable<ColumnInfo> VisibleFixedColumns => FixedColumns.Where(c => c.IsVisible);

    public double TotalWidth() => StatusWidth + VisibleFixedColumns.Sum(c => c.Width) + 28;

    public void ApplyDensity(bool compact) => RowHeight = compact ? CompactRow : ComfortableRow;

    /// <summary>Applies saved widths, hidden columns and density.</summary>
    public void Load(AppSettings settings)
    {
        _saved.Clear();
        // "probe:<id>" widths belong to the old one-column-per-probe table.
        foreach (var key in settings.ColumnWidths.Keys.Where(k => k.StartsWith("probe:", StringComparison.Ordinal)).ToList())
            settings.ColumnWidths.Remove(key);
        foreach (var (key, width) in settings.ColumnWidths) _saved[key] = width;
        foreach (var column in FixedColumns)
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
        foreach (var column in FixedColumns)
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
