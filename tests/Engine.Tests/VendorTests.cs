using System.Net;
using System.Text;
using ANetworkScanner.Engine;
using ANetworkScanner.Engine.Vendors;
using Xunit;

namespace ANetworkScanner.Engine.Tests;

public class VendorTests : IDisposable
{
    private const string Sample = """
        OUI/MA-L                                                    Organization
        company_id                                                  Organization
                                                                    Address

        28-6F-B9   (hex)		Nokia Shanghai Bell Co., Ltd.
        286FB9     (base 16)		Nokia Shanghai Bell Co., Ltd.
        				No.388 Ning Qiao Road,Jin Qiao Pudong Shanghai
        				Shanghai     201206
        				CN

        E8-0A-B9   (hex)		Cisco Systems, Inc
        E80AB9     (base 16)		Cisco Systems, Inc
        				80 West Tasman Drive
        				San Jose  CA  94568
        				US

        00-1B-00   (hex)		Neopost Technologies
        001B00     (base 16)		Neopost Technologies

        AA-BB-CC   (hex)		Private
        AABBCC     (base 16)		Private
        """;

    private readonly string _root = Path.Combine(Path.GetTempPath(), "ans-oui-" + Guid.NewGuid().ToString("N"));

    public VendorTests() => Directory.CreateDirectory(_root);

    public void Dispose() => Directory.Delete(_root, recursive: true);

    private static MacVendors Parse(string text) => MacVendors.Load(new StringReader(text));

    // ── Parsing and lookup ───────────────────────────────────────────────────

    [Fact]
    public void Parse_ReadsOnlyTheHexRecords()
    {
        var v = Parse(Sample);
        Assert.Equal(3, v.Count); // the "Private" block is not a vendor
    }

    [Theory]
    [InlineData("E8:0A:B9:12:34:56")]
    [InlineData("e8-0a-b9-12-34-56")]
    [InlineData("e80a.b912.3456")]
    [InlineData("E80AB9123456")]
    [InlineData("E8:0A:B9")]
    public void Lookup_AcceptsCommonMacSpellings(string mac) => Assert.Equal("Cisco Systems, Inc", Parse(Sample).Lookup(mac));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("E8:0A")]
    [InlineData("not a mac")]
    [InlineData("12:34:56:78:9A:BC")]
    [InlineData("AA:BB:CC:00:00:00")]
    public void Lookup_ReturnsNullWhenUnknownOrPrivate(string? mac) => Assert.Null(Parse(Sample).Lookup(mac));

    [Fact]
    public void Describe_ShortensTheNameAndFlagsRandomizedAddresses()
    {
        var v = Parse(Sample);
        Assert.Equal("Cisco Systems", v.Describe("E8:0A:B9:00:00:01"));
        Assert.Equal("Cisco Systems, Inc", v.Describe("E8:0A:B9:00:00:01", shorten: false));
        Assert.Equal("Private address", v.Describe("2E:DE:3E:98:46:35"));
        Assert.Equal("", v.Describe("F8:ED:FC:21:6E:26"));
        Assert.Equal("", v.Describe(null));
    }

    [Theory]
    [InlineData("Nokia Shanghai Bell Co., Ltd.", "Nokia Shanghai Bell")]
    [InlineData("Cisco Systems, Inc", "Cisco Systems")]
    [InlineData("Apple, Inc.", "Apple")]
    [InlineData("Hewlett Packard Enterprise", "Hewlett Packard Enterprise")]
    [InlineData("Fiberhome Telecommunication Technologies Co.,LTD", "Fiberhome Telecommunication Technologies")]
    [InlineData("Siemens AG", "Siemens")]
    [InlineData("Robert Bosch GmbH", "Robert Bosch")]
    [InlineData("Samsung Electronics Co.,Ltd", "Samsung Electronics")]
    [InlineData("SALTO SYSTEMS S.L.", "SALTO SYSTEMS S.L.")]
    [InlineData("Acme Widgets CO.,LTD", "Acme Widgets")]
    [InlineData("Inc", "Inc")]
    public void Shorten_DropsLegalSuffixes(string full, string expected) => Assert.Equal(expected, MacVendors.Shorten(full));

    // ── Real data shipped with the app ───────────────────────────────────────

    [Fact]
    public void BundledList_ResolvesRealDevicesFromTheLan()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "data", "oui.txt");
        Assert.True(File.Exists(path), "data/oui.txt must ship with the app");

        var v = MacVendors.LoadFile(path);
        Assert.InRange(v.Count, 30_000, 200_000);
        Assert.Equal("Neopost Technologies", v.Lookup("00:1B:00:33:10:69"));
        Assert.Contains("Apple", v.Lookup("90:84:0D:D3:B2:09")!);
        Assert.Contains("Cisco", v.Lookup("F4:DB:E6:C1:A1:CE")!);
        Assert.Contains("Salto", v.Lookup("00:0A:83:0D:01:16")!, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Samsung", v.Lookup("00:16:6C:DE:98:3F")!);
        Assert.Contains("Netgear", v.Lookup("20:4E:7F:13:77:54")!, StringComparison.OrdinalIgnoreCase);
    }

    // ── Store: choosing the freshest list ────────────────────────────────────

    private string Write(string name, string text, DateTime? downloaded = null)
    {
        var path = Path.Combine(_root, name);
        File.WriteAllText(path, text);
        if (downloaded is { } when)
            File.WriteAllText(Path.ChangeExtension(path, ".meta.json"), $$"""{ "downloadedUtc": "{{when:O}}" }""");
        return path;
    }

    private const string OneEntry = "00-1B-00   (hex)\t\tFromUserFile\n";
    private const string OtherEntry = "00-1B-00   (hex)\t\tFromBundled\n";

    [Fact]
    public void Load_PrefersTheNewerCopy()
    {
        var bundled = Write("bundled.txt", OtherEntry, new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        var user = Write("user.txt", OneEntry, new DateTime(2026, 6, 1, 0, 0, 0, DateTimeKind.Utc));

        var (vendors, info) = new OuiStore(bundled, user).Load();

        Assert.Equal("FromUserFile", vendors.Lookup("00:1B:00:00:00:00"));
        Assert.True(info!.IsUserCopy);
        Assert.Equal(new DateTime(2026, 6, 1, 0, 0, 0, DateTimeKind.Utc), info.DownloadedUtc);
    }

    [Fact]
    public void Load_UsesTheBundledCopyWhenItIsNewer()
    {
        var bundled = Write("bundled.txt", OtherEntry, new DateTime(2026, 9, 1, 0, 0, 0, DateTimeKind.Utc));
        var user = Write("user.txt", OneEntry, new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc));

        var (vendors, info) = new OuiStore(bundled, user).Load();

        Assert.Equal("FromBundled", vendors.Lookup("00:1B:00:00:00:00"));
        Assert.False(info!.IsUserCopy);
    }

    [Fact]
    public void Load_FallsBackWhenTheUserCopyIsEmptyOrMissing()
    {
        var bundled = Write("bundled.txt", OtherEntry, new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        var empty = Write("user.txt", "garbage, no records", new DateTime(2026, 8, 1, 0, 0, 0, DateTimeKind.Utc));

        Assert.Equal("FromBundled", new OuiStore(bundled, empty).Load().Vendors.Lookup("00:1B:00:00:00:00"));
        Assert.Equal("FromBundled", new OuiStore(bundled, Path.Combine(_root, "missing.txt")).Load().Vendors.Lookup("00:1B:00:00:00:00"));
        Assert.Null(new OuiStore(Path.Combine(_root, "a"), Path.Combine(_root, "b")).Load().Info);
    }

    [Fact]
    public void Load_WithoutMetadata_UsesTheFileTimestamp()
    {
        var path = Write("bundled.txt", OtherEntry);
        File.SetLastWriteTimeUtc(path, new DateTime(2026, 3, 3, 0, 0, 0, DateTimeKind.Utc));
        var info = new OuiStore(path, Path.Combine(_root, "none.txt")).Load().Info!;
        Assert.Equal(new DateTime(2026, 3, 3, 0, 0, 0, DateTimeKind.Utc), info.DownloadedUtc);
    }

    [Fact]
    public void IsStale_AfterAboutTwoMonths()
    {
        var now = new DateTime(2026, 10, 8, 0, 0, 0, DateTimeKind.Utc);
        OuiInfo At(int daysAgo) => new("x", 1, now.AddDays(-daysAgo), false);

        Assert.False(OuiStore.IsStale(At(0), now));
        Assert.False(OuiStore.IsStale(At(59), now));
        Assert.True(OuiStore.IsStale(At(61), now));
        Assert.True(OuiStore.IsStale(null, now));
    }

    // ── Updater (fake HTTP, no network) ──────────────────────────────────────

    private sealed class FakeHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public List<HttpRequestMessage> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Requests.Add(request);
            return Task.FromResult(respond(request));
        }
    }

    private static HttpResponseMessage Ok(string body, string? etag = null)
    {
        var r = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "text/plain") };
        if (etag is not null) r.Headers.ETag = new System.Net.Http.Headers.EntityTagHeaderValue(etag);
        return r;
    }

    [Fact]
    public async Task Update_ReplacesTheListWhenTheDownloadIsValid()
    {
        var bundled = Write("bundled.txt", OtherEntry, new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        var user = Path.Combine(_root, "user.txt");
        var store = new OuiStore(bundled, user, minEntries: 2);
        var handler = new FakeHandler(_ => Ok(Sample, "\"abc\""));

        var result = await store.UpdateAsync(new HttpClient(handler), CancellationToken.None);

        Assert.Equal(OuiUpdateStatus.Updated, result.Status);
        Assert.Equal(3, result.Entries);
        var (vendors, info) = store.Load();
        Assert.Equal("Cisco Systems, Inc", vendors.Lookup("E8:0A:B9:00:00:00"));
        Assert.True(info!.IsUserCopy);
        Assert.True((DateTime.UtcNow - info.DownloadedUtc).TotalMinutes < 1);
        Assert.False(File.Exists(user + ".download"), "temporary file must be cleaned up");
        Assert.Equal(OuiStore.SourceUrl, handler.Requests.Single().RequestUri!.ToString());
    }

    [Fact]
    public async Task Update_RejectsAnIncompleteDownload_AndKeepsTheCurrentList()
    {
        var bundled = Write("bundled.txt", OtherEntry, new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        var user = Write("user.txt", OneEntry, new DateTime(2026, 5, 1, 0, 0, 0, DateTimeKind.Utc));
        var store = new OuiStore(bundled, user, minEntries: 10_000);

        var result = await store.UpdateAsync(new HttpClient(new FakeHandler(_ => Ok(Sample))), CancellationToken.None);

        Assert.Equal(OuiUpdateStatus.Failed, result.Status);
        Assert.Contains("incomplete", result.Message);
        Assert.Equal("FromUserFile", store.Load().Vendors.Lookup("00:1B:00:00:00:00"));
        Assert.False(File.Exists(user + ".download"));
    }

    [Fact]
    public async Task Update_ReportsServerErrors_AndNetworkFailures()
    {
        var store = new OuiStore(Path.Combine(_root, "b.txt"), Path.Combine(_root, "u.txt"), minEntries: 1);

        var http500 = await store.UpdateAsync(
            new HttpClient(new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.InternalServerError))), CancellationToken.None);
        Assert.Equal(OuiUpdateStatus.Failed, http500.Status);
        Assert.Contains("500", http500.Message);

        var offline = await store.UpdateAsync(
            new HttpClient(new FakeHandler(_ => throw new HttpRequestException("No such host is known"))), CancellationToken.None);
        Assert.Equal(OuiUpdateStatus.Failed, offline.Status);
        Assert.Contains("No such host", offline.Message);
        Assert.False(File.Exists(Path.Combine(_root, "u.txt")));
    }

    [Fact]
    public async Task Update_SendsTheEtag_AndTreats304AsCurrentWhileRestartingTheClock()
    {
        var old = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var bundled = Write("bundled.txt", OtherEntry);
        File.WriteAllText(Path.ChangeExtension(bundled, ".meta.json"), $$"""{ "downloadedUtc": "{{old:O}}", "etag": "\"v1\"" }""");
        var store = new OuiStore(bundled, Path.Combine(_root, "user.txt"), minEntries: 1);
        var handler = new FakeHandler(r =>
            r.Headers.TryGetValues("If-None-Match", out var v) && v.Contains("\"v1\"")
                ? new HttpResponseMessage(HttpStatusCode.NotModified)
                : Ok(Sample));

        var result = await store.UpdateAsync(new HttpClient(handler), CancellationToken.None);

        Assert.Equal(OuiUpdateStatus.AlreadyCurrent, result.Status);
        var info = store.Load().Info!;
        Assert.True((DateTime.UtcNow - info.DownloadedUtc).TotalMinutes < 1, "a confirmed-current list is no longer stale");
        Assert.False(File.Exists(Path.Combine(_root, "user.txt")), "nothing new was downloaded");
    }

    [Fact]
    public async Task Update_CanBeCancelled()
    {
        var store = new OuiStore(Path.Combine(_root, "b.txt"), Path.Combine(_root, "u.txt"), minEntries: 1);
        using var cts = new CancellationTokenSource();
        var handler = new FakeHandler(_ => { cts.Cancel(); throw new OperationCanceledException(cts.Token); });

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => store.UpdateAsync(new HttpClient(handler), cts.Token));
    }

    // ── Vendor evidence in the device guess ──────────────────────────────────

    [Theory]
    [InlineData("Brother Industries", DeviceKind.Printer)]
    [InlineData("Hangzhou Hikvision Digital Technology", DeviceKind.Camera)]
    [InlineData("Ubiquiti Inc", DeviceKind.NetworkDevice)]
    [InlineData("Cisco Systems, Inc", DeviceKind.NetworkDevice)]
    [InlineData("Synology Incorporated", DeviceKind.Server)]
    [InlineData("Hewlett Packard", DeviceKind.Unknown)]
    [InlineData("Apple, Inc.", DeviceKind.Unknown)]
    public void Vendor_FeedsTheDeviceGuess(string vendor, DeviceKind expected) =>
        Assert.Equal(expected, DeviceClassifier.Classify(new DeviceEvidence(0, "F8:ED:FC:21:6E:26", [], Vendor: vendor)).Kind);

    [Fact]
    public void WhatTheDeviceSays_BeatsWhatItsMacSays() =>
        Assert.Equal(DeviceKind.Printer, DeviceClassifier.Classify(new DeviceEvidence(255, null,
            [new ServiceEvidence("snmp", [161], "HP LaserJet MFP", "")], Vendor: "Cisco Systems, Inc")).Kind);
}
