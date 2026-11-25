using System.Text.Json;
using System.Text.Json.Serialization;

namespace ANetworkScanner.Engine.Settings;

/// <summary>Which colour theme the app uses.</summary>
public enum AppTheme
{
    /// <summary>Follow the Windows light/dark setting.</summary>
    System,
    Light,
    Dark,
}

/// <summary>Everything persisted between runs.</summary>
public sealed class AppSettings
{
    public AppTheme Theme { get; set; } = AppTheme.System;

    public const int MaxRecentTargets = 10;

    public List<string> RecentTargets { get; set; } = [];

    public DiscoverySettings Discovery { get; set; } = new();

    /// <summary>Tighter result rows.</summary>
    public bool CompactRows { get; set; }

    /// <summary>With a Services filter on, remove the hosts that do not match from the table instead of fading them.</summary>
    public bool HideFilteredRows { get; set; }

    /// <summary>Columns the user switched off (keys such as "rtt", "mac", "vendor", "method"). The address column cannot be hidden.</summary>
    public List<string> HiddenColumns { get; set; } = [];

    /// <summary>Ask when the MAC vendor list is older than two months.</summary>
    public bool RemindAboutVendorUpdates { get; set; } = true;

    /// <summary>"Not now" on the update reminder: stay quiet until this moment.</summary>
    public DateTime? VendorReminderSnoozedUntilUtc { get; set; }

    /// <summary>User-chosen column widths, by column key ("address", "mac", "probe:ssh", ...).</summary>
    public Dictionary<string, double> ColumnWidths { get; set; } = [];

    /// <summary>Width of the details panel in pixels (0 = default).</summary>
    public double DetailsWidth { get; set; }

    /// <summary>Probe ids the user switched off in Options. Stored as the exceptions so new probes start enabled.</summary>
    public List<string> DisabledProbes { get; set; } = [];

    /// <summary>Most recent first, no duplicates (case-insensitive), capped at <see cref="MaxRecentTargets"/>.</summary>
    public void AddRecentTarget(string target)
    {
        target = target.Trim();
        if (target.Length == 0) return;

        RecentTargets.RemoveAll(t => string.Equals(t, target, StringComparison.OrdinalIgnoreCase));
        RecentTargets.Insert(0, target);
        if (RecentTargets.Count > MaxRecentTargets)
            RecentTargets.RemoveRange(MaxRecentTargets, RecentTargets.Count - MaxRecentTargets);
    }
}

/// <summary>Loads and saves <see cref="AppSettings"/> as JSON under %LocalAppData%\A Network Scanner.</summary>
public sealed class SettingsStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        Converters = { new JsonStringEnumConverter() },
    };

    public SettingsStore(string? path = null) => Path = path ?? DefaultPath;

    public string Path { get; }

    public static string DefaultDirectory => System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "A Network Scanner");

    public static string DefaultPath => System.IO.Path.Combine(DefaultDirectory, "settings.json");

    /// <summary>Returns defaults when the file is missing or unreadable; a corrupt file never blocks startup.</summary>
    public AppSettings Load()
    {
        try
        {
            if (!File.Exists(Path)) return new AppSettings();
            using var stream = File.OpenRead(Path);
            var settings = JsonSerializer.Deserialize<AppSettings>(stream, JsonOptions) ?? new AppSettings();
            settings.Discovery = (settings.Discovery ?? new DiscoverySettings()).Normalized();
            settings.RecentTargets ??= [];
            settings.DisabledProbes ??= [];
            settings.ColumnWidths ??= [];
            settings.HiddenColumns ??= [];
            return settings;
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            return new AppSettings();
        }
    }

    /// <summary>Writes via a temp file and rename so a crash mid-write cannot leave a truncated file.</summary>
    public void Save(AppSettings settings)
    {
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path)!);
        var temp = Path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(settings, JsonOptions));
        File.Move(temp, Path, overwrite: true);
    }
}
