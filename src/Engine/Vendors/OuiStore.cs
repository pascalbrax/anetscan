using System.Globalization;
using System.Net;
using System.Text.Json;
using ANetworkScanner.Engine.Settings;

namespace ANetworkScanner.Engine.Vendors;

/// <summary>Where the vendor list came from and how old it is.</summary>
public sealed record OuiInfo(string Path, int Entries, DateTime DownloadedUtc, bool IsUserCopy)
{
    public TimeSpan Age(DateTime nowUtc) => nowUtc - DownloadedUtc;
}

public enum OuiUpdateStatus
{
    Updated,
    /// <summary>The server confirmed our copy is current.</summary>
    AlreadyCurrent,
    Failed,
}

public sealed record OuiUpdateResult(OuiUpdateStatus Status, string Message, int Entries = 0);

/// <summary>
/// Finds, loads and refreshes the OUI list. The app ships a copy next to the executable; a downloaded update is
/// kept in the user's data folder and wins whenever it is newer. Updates only ever happen when the user asks.
/// </summary>
public sealed class OuiStore
{
    public const string SourceUrl = "https://standards-oui.ieee.org/oui/oui.txt";

    /// <summary>The list is considered stale after about two months.</summary>
    public static readonly TimeSpan MaxAge = TimeSpan.FromDays(60);

    private readonly int _minEntries;

    public OuiStore(string bundledPath, string userPath, int minEntries = 10_000)
    {
        BundledPath = bundledPath;
        UserPath = userPath;
        _minEntries = minEntries;
    }

    public static OuiStore CreateDefault() => new(
        Path.Combine(AppContext.BaseDirectory, "data", "oui.txt"),
        Path.Combine(SettingsStore.DefaultDirectory, "oui.txt"));

    public string BundledPath { get; }
    public string UserPath { get; }

    // ── Loading ──────────────────────────────────────────────────────────────

    /// <summary>Loads the newest available list. An unreadable or empty user copy falls back to the bundled one.</summary>
    public (MacVendors Vendors, OuiInfo? Info) Load()
    {
        var candidates = new[] { (Path: UserPath, IsUser: true), (Path: BundledPath, IsUser: false) }
            .Where(c => File.Exists(c.Path))
            .Select(c => (c.Path, c.IsUser, Downloaded: ReadMeta(c.Path).DownloadedUtc ?? File.GetLastWriteTimeUtc(c.Path)))
            .OrderByDescending(c => c.Downloaded);

        foreach (var (path, isUser, downloaded) in candidates)
        {
            try
            {
                var vendors = MacVendors.LoadFile(path);
                if (vendors.Count == 0) continue;
                return (vendors, new OuiInfo(path, vendors.Count, downloaded, isUser));
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
        return (MacVendors.Empty, null);
    }

    /// <summary>True when there is no list, or it is older than <see cref="MaxAge"/>.</summary>
    public static bool IsStale(OuiInfo? info, DateTime nowUtc) => info is null || info.Age(nowUtc) > MaxAge;

    // ── Updating ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Downloads the current registry. The old list is kept until the new one has been fully received and parsed
    /// with a plausible number of entries, so a broken download can never leave the app without vendors.
    /// </summary>
    public async Task<OuiUpdateResult> UpdateAsync(HttpClient http, CancellationToken cancellationToken)
    {
        var tempPath = UserPath + ".download";
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(UserPath)!);

            using var request = new HttpRequestMessage(HttpMethod.Get, SourceUrl);
            request.Headers.UserAgent.ParseAdd("A-Network-Scanner/0.1 (OUI update)");
            // Ask only "has it changed?" when we already hold a copy and know its ETag.
            var existing = File.Exists(UserPath) ? UserPath : File.Exists(BundledPath) ? BundledPath : null;
            var known = existing is null ? new Meta(null, null) : ReadMeta(existing);
            if (known.ETag is { Length: > 0 } etag)
                request.Headers.TryAddWithoutValidation("If-None-Match", etag);

            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                .ConfigureAwait(false);

            if (response.StatusCode == HttpStatusCode.NotModified)
            {
                // Same data, but it is now confirmed current: restart the two-month clock.
                if (existing is not null) WriteMeta(existing, DateTime.UtcNow, known.ETag);
                return new OuiUpdateResult(OuiUpdateStatus.AlreadyCurrent, "The vendor list is already up to date.");
            }

            if (!response.IsSuccessStatusCode)
                return new OuiUpdateResult(OuiUpdateStatus.Failed, $"The server answered {(int)response.StatusCode} {response.ReasonPhrase}.");

            await using (var source = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false))
            await using (var target = File.Create(tempPath))
                await source.CopyToAsync(target, cancellationToken).ConfigureAwait(false);

            var vendors = MacVendors.LoadFile(tempPath);
            if (vendors.Count < _minEntries)
                return new OuiUpdateResult(OuiUpdateStatus.Failed,
                    $"The download looks incomplete ({vendors.Count:N0} entries); the current list was kept.");

            File.Move(tempPath, UserPath, overwrite: true);
            WriteMeta(UserPath, DateTime.UtcNow, response.Headers.ETag?.ToString());
            return new OuiUpdateResult(OuiUpdateStatus.Updated, $"Vendor list updated: {vendors.Count:N0} entries.", vendors.Count);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or UnauthorizedAccessException or TaskCanceledException)
        {
            return new OuiUpdateResult(OuiUpdateStatus.Failed, ex.InnerException?.Message ?? ex.Message);
        }
        finally
        {
            try { File.Delete(tempPath); } catch (IOException) { }
        }
    }

    // ── Metadata next to each list: when it was fetched, and the server's ETag ──

    private sealed record Meta(DateTime? DownloadedUtc, string? ETag);

    private static string MetaPath(string listPath) => Path.ChangeExtension(listPath, ".meta.json");

    private static Meta ReadMeta(string listPath)
    {
        try
        {
            var path = MetaPath(listPath);
            if (!File.Exists(path)) return new Meta(null, null);
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            DateTime? when = doc.RootElement.TryGetProperty("downloadedUtc", out var d) && d.ValueKind == JsonValueKind.String &&
                             DateTime.TryParse(d.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var parsed)
                ? parsed : null;
            string? etag = doc.RootElement.TryGetProperty("etag", out var e) && e.ValueKind == JsonValueKind.String ? e.GetString() : null;
            return new Meta(when, etag);
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            return new Meta(null, null);
        }
    }

    private static void WriteMeta(string listPath, DateTime downloadedUtc, string? etag)
    {
        try
        {
            var json = JsonSerializer.Serialize(new
            {
                source = SourceUrl,
                downloadedUtc = downloadedUtc.ToString("O", CultureInfo.InvariantCulture),
                etag,
            }, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(MetaPath(listPath), json);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // The list itself is what matters; without metadata the file's own timestamp is used.
        }
    }
}
