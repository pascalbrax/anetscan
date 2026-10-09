using System.Net;
using System.Net.Sockets;
using System.Text;
using ANetworkScanner.Engine;
using ANetworkScanner.Engine.Discovery;
using ANetworkScanner.Engine.Names;
using ANetworkScanner.Engine.Settings;
using ANetworkScanner.Engine.Targets;
using Xunit;

namespace ANetworkScanner.Engine.Tests;

public class NameResolutionTests
{
    // ── Test helpers: build DNS answers the way a server would ───────────────

    /// <summary>An answer to <paramref name="query"/> whose owner name is a compression pointer back to the question.</summary>
    private static byte[] DnsAnswer(byte[] query, string? ptrName, int rcode = 0, bool compressTarget = false)
    {
        using var ms = new MemoryStream();
        ms.Write(query, 0, 2);                                          // id
        ms.Write([(byte)0x81, (byte)(0x80 | rcode)]);                   // response, recursion available, rcode
        ms.Write([0, 1, 0, (byte)(ptrName is null ? 0 : 1), 0, 0, 0, 0]);
        ms.Write(query, 12, query.Length - 12);                         // the question, echoed

        if (ptrName is not null)
        {
            ms.Write([0xC0, 0x0C]);                                      // owner name: pointer to the question name
            ms.Write([0, 12, 0, 1, 0, 0, 0, 60]);                        // PTR, IN, ttl 60
            var rdata = new MemoryStream();
            if (compressTarget)
            {
                // "host" + pointer to the label "in-addr" inside the question (offset 12 + 1+1 + ... ) is brittle; use a plain name
                // preceded by a pointer-free encoding instead and test pointers separately.
            }
            foreach (var label in ptrName.TrimEnd('.').Split('.'))
            {
                rdata.WriteByte((byte)label.Length);
                rdata.Write(Encoding.UTF8.GetBytes(label));
            }
            rdata.WriteByte(0);
            ms.Write([(byte)(rdata.Length >> 8), (byte)rdata.Length]);
            ms.Write(rdata.ToArray());
        }
        return ms.ToArray();
    }

    private static ushort IdOf(byte[] message) => (ushort)((message[0] << 8) | message[1]);

    // ── DNS wire format ──────────────────────────────────────────────────────

    [Fact]
    public void PtrQuery_UsesTheReversedAddressUnderInAddrArpa()
    {
        var q = DnsWire.BuildPtrQuery(IPAddress.Parse("10.0.1.25"), 0x1234, recursionDesired: true);

        Assert.Equal(0x12, q[0]); Assert.Equal(0x34, q[1]);
        Assert.Equal(0x01, q[2]); Assert.Equal(0x00, q[3]);               // recursion desired
        Assert.Equal(1, q[5]);                                              // one question
        var name = new List<string>();
        int pos = 12;
        while (q[pos] != 0) { name.Add(Encoding.ASCII.GetString(q, pos + 1, q[pos])); pos += 1 + q[pos]; }
        Assert.Equal("25.1.0.10.in-addr.arpa", string.Join('.', name));
        Assert.Equal([0, 12, 0, 1], q[(pos + 1)..]);                        // PTR, IN
    }

    [Fact]
    public void MdnsQuery_AsksForAUnicastAnswer_WithoutRecursion()
    {
        var q = DnsWire.BuildPtrQuery(IPAddress.Parse("10.0.1.25"), 0, recursionDesired: false, unicastResponse: true);
        Assert.Equal(0, q[2]);
        Assert.Equal(0, q[3]);
        Assert.Equal([0x80, 0x01], q[^2..]); // class IN with the unicast-response bit
    }

    [Fact]
    public void ParsePtrResponse_ReadsTheNameFromACompressedAnswer()
    {
        var query = DnsWire.BuildPtrQuery(IPAddress.Parse("10.0.0.212"), 0xBEEF, true);
        var answer = DnsAnswer(query, "SVR-GECOTI-12C.PARADISO.local.");

        var kind = DnsWire.ParsePtrResponse(answer, 0xBEEF, out var name);

        Assert.Equal(DnsWire.ResponseKind.Name, kind);
        Assert.Equal("SVR-GECOTI-12C.PARADISO.local", name);
    }

    [Fact]
    public void ParsePtrResponse_FollowsPointersInsideTheAnswerName()
    {
        // Answer name = "host" + pointer to the question's "in-addr.arpa" labels.
        var query = DnsWire.BuildPtrQuery(IPAddress.Parse("1.2.3.4"), 7, true);
        int inAddrOffset = 12 + 2 + 2 + 2 + 2; // after labels "4","3","2","1" (each 2 bytes)
        using var ms = new MemoryStream();
        ms.Write(query, 0, 2);
        ms.Write([0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        ms.Write(query, 12, query.Length - 12);
        ms.Write([0xC0, 0x0C, 0, 12, 0, 1, 0, 0, 0, 60]);
        var rdata = new byte[] { 4, (byte)'h', (byte)'o', (byte)'s', (byte)'t', 0xC0, (byte)inAddrOffset };
        ms.Write([0, (byte)rdata.Length]);
        ms.Write(rdata);

        Assert.Equal(DnsWire.ResponseKind.Name, DnsWire.ParsePtrResponse(ms.ToArray(), 7, out var name));
        Assert.Equal("host.in-addr.arpa", name);
    }

    [Fact]
    public void ParsePtrResponse_NxDomain_IsAnAnswerWithoutAName()
    {
        var query = DnsWire.BuildPtrQuery(IPAddress.Parse("10.0.0.9"), 5, true);
        var kind = DnsWire.ParsePtrResponse(DnsAnswer(query, null, rcode: 3), 5, out var name);
        Assert.Equal(DnsWire.ResponseKind.NoName, kind);
        Assert.Null(name);
    }

    [Fact]
    public void ParsePtrResponse_RejectsWrongIdQueriesAndGarbage()
    {
        var query = DnsWire.BuildPtrQuery(IPAddress.Parse("10.0.0.9"), 5, true);
        var answer = DnsAnswer(query, "x.local");

        Assert.Equal(DnsWire.ResponseKind.Invalid, DnsWire.ParsePtrResponse(answer, 6, out _));       // someone else's answer
        Assert.Equal(DnsWire.ResponseKind.Invalid, DnsWire.ParsePtrResponse(query, 5, out _));        // a query, not a response
        Assert.Equal(DnsWire.ResponseKind.Invalid, DnsWire.ParsePtrResponse(answer[..20], 5, out _)); // truncated
        Assert.Equal(DnsWire.ResponseKind.Invalid, DnsWire.ParsePtrResponse([], 5, out _));
        Assert.Equal(DnsWire.ResponseKind.Invalid, DnsWire.ParsePtrResponse(new byte[40], 5, out _));
    }

    [Fact]
    public void ParsePtrResponse_SurvivesAPointerLoop()
    {
        var query = DnsWire.BuildPtrQuery(IPAddress.Parse("1.2.3.4"), 9, true);
        using var ms = new MemoryStream();
        ms.Write(query, 0, 2);
        ms.Write([0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        ms.Write(query, 12, query.Length - 12);
        ms.Write([0xC0, 0x0C, 0, 12, 0, 1, 0, 0, 0, 60]);
        int rdataStart = (int)ms.Length + 2;
        ms.Write([0, 2]);
        ms.Write([0xC0, (byte)rdataStart]); // points at itself

        var kind = DnsWire.ParsePtrResponse(ms.ToArray(), 9, out var name);
        Assert.NotEqual(DnsWire.ResponseKind.Name, kind);
        Assert.Null(name);
    }

    // ── Reverse DNS over a real (loopback) UDP server ────────────────────────

    private sealed class FakeUdpServer : IDisposable
    {
        private readonly UdpClient _udp = new(new IPEndPoint(IPAddress.Loopback, 0));
        private readonly CancellationTokenSource _stop = new();

        public FakeUdpServer(Func<byte[], byte[]?> respond)
        {
            Port = ((IPEndPoint)_udp.Client.LocalEndPoint!).Port;
            _ = Task.Run(async () =>
            {
                while (!_stop.IsCancellationRequested)
                {
                    try
                    {
                        var request = await _udp.ReceiveAsync(_stop.Token);
                        Received.Add(request.Buffer);
                        if (respond(request.Buffer) is { } reply)
                            await _udp.SendAsync(reply, request.RemoteEndPoint, _stop.Token);
                    }
                    catch { return; }
                }
            });
        }

        public int Port { get; }
        public List<byte[]> Received { get; } = [];

        public void Dispose()
        {
            _stop.Cancel();
            _udp.Dispose();
        }
    }

    private static readonly IPAddress Host = IPAddress.Parse("10.0.0.212");

    [Fact]
    public async Task DnsSource_ResolvesThroughAServer()
    {
        using var server = new FakeUdpServer(q => DnsAnswer(q, "svr-gecoti-12c.paradiso.local."));
        var source = new DnsPtrSource([new IPEndPoint(IPAddress.Loopback, server.Port)]);

        Assert.Equal("svr-gecoti-12c.paradiso.local", await source.QueryAsync(Host, 1000, CancellationToken.None));
        Assert.Single(server.Received);
    }

    [Fact]
    public async Task DnsSource_NoRecord_ReturnsNull_WithoutAskingTheOtherServers()
    {
        using var nx = new FakeUdpServer(q => DnsAnswer(q, null, rcode: 3));
        using var second = new FakeUdpServer(q => DnsAnswer(q, "should-not-be-asked.local"));
        var source = new DnsPtrSource([new IPEndPoint(IPAddress.Loopback, nx.Port), new IPEndPoint(IPAddress.Loopback, second.Port)]);

        Assert.Null(await source.QueryAsync(Host, 1000, CancellationToken.None));
        Assert.Empty(second.Received);
    }

    [Fact]
    public async Task DnsSource_FallsBackToTheNextServerWhenOneIsSilent()
    {
        using var silent = new FakeUdpServer(_ => null);
        using var working = new FakeUdpServer(q => DnsAnswer(q, "backup-answer.local"));
        var source = new DnsPtrSource([new IPEndPoint(IPAddress.Loopback, silent.Port), new IPEndPoint(IPAddress.Loopback, working.Port)]);

        Assert.Equal("backup-answer.local", await source.QueryAsync(Host, 1000, CancellationToken.None));
    }

    [Fact]
    public async Task DnsSource_IgnoresAnAnswerWithTheWrongId()
    {
        using var server = new FakeUdpServer(q =>
        {
            var forged = DnsAnswer(q, "forged.local");
            forged[0] ^= 0xFF;
            return forged;
        });
        var source = new DnsPtrSource([new IPEndPoint(IPAddress.Loopback, server.Port)]);

        Assert.Null(await source.QueryAsync(Host, 400, CancellationToken.None));
    }

    [Fact]
    public async Task DnsSource_WithNoServers_ReturnsNull() =>
        Assert.Null(await new DnsPtrSource([]).QueryAsync(Host, 200, CancellationToken.None));

    [Fact]
    public async Task DnsSource_TimesOutQuickly()
    {
        using var silent = new FakeUdpServer(_ => null);
        var source = new DnsPtrSource([new IPEndPoint(IPAddress.Loopback, silent.Port)]);

        var sw = System.Diagnostics.Stopwatch.StartNew();
        Assert.Null(await source.QueryAsync(Host, 300, CancellationToken.None));
        Assert.InRange(sw.ElapsedMilliseconds, 200, 1500);
    }

    [Theory]
    [InlineData("10.0.0.1", true)]
    [InlineData("172.16.128.91", true)]
    [InlineData("172.31.255.255", true)]
    [InlineData("172.32.0.1", false)]
    [InlineData("192.168.1.1", true)]
    [InlineData("169.254.3.4", true)]
    [InlineData("100.64.0.1", true)]
    [InlineData("8.8.8.8", false)]
    [InlineData("1.1.1.1", false)]
    [InlineData("93.184.216.34", false)]
    public void IsPrivate_RecognisesLocalAddresses(string ip, bool expected) =>
        Assert.Equal(expected, DnsPtrSource.IsPrivate(IPAddress.Parse(ip)));

    [Fact]
    public async Task DnsSource_NeverSendsAPrivateAddressToAPublicResolver()
    {
        // 127.0.0.1 counts as private here, so use it as the "inside" server and make the "public" one unreachable by
        // pretending: a public server address cannot be bound in a test, so verify the filter on the server list directly.
        var publicOnly = new DnsPtrSource([new IPEndPoint(IPAddress.Parse("8.8.8.8"), 53)]);

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var name = await publicOnly.QueryAsync(IPAddress.Parse("10.0.0.212"), 1500, CancellationToken.None);

        Assert.Null(name);
        Assert.True(sw.ElapsedMilliseconds < 200, "no packet should even be attempted, so it returns at once");
    }

    // ── mDNS ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task MdnsSource_AsksTheHostDirectly_AndReadsItsName()
    {
        using var server = new FakeUdpServer(q =>
        {
            // mDNS answers carry id 0 and may omit the question; mimic that.
            var answer = DnsAnswer(q, "Pascals-iPhone.local");
            answer[0] = 0; answer[1] = 0;
            return answer;
        });

        var name = await new MdnsSource(server.Port).QueryAsync(IPAddress.Loopback, 1000, CancellationToken.None);

        Assert.Equal("Pascals-iPhone.local", name);
        Assert.Equal([0x80, 0x01], server.Received.Single()[^2..]); // the unicast-response bit was set
    }

    // ── NetBIOS ──────────────────────────────────────────────────────────────

    private static byte[] NodeStatus(params (string Name, byte Suffix, ushort Flags)[] names)
    {
        using var ms = new MemoryStream();
        ms.Write([0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0]);                     // header: response, one answer
        ms.WriteByte(0x20);
        ms.Write("CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"u8);
        ms.WriteByte(0);
        ms.Write([0, 0x21, 0, 1, 0, 0, 0, 0]);                                  // NBSTAT, IN, ttl
        int rdLength = 1 + names.Length * 18 + 6;
        ms.Write([(byte)(rdLength >> 8), (byte)rdLength]);
        ms.WriteByte((byte)names.Length);
        foreach (var (name, suffix, flags) in names)
        {
            ms.Write(Encoding.ASCII.GetBytes(name.PadRight(15)));
            ms.WriteByte(suffix);
            ms.Write([(byte)(flags >> 8), (byte)flags]);
        }
        ms.Write(new byte[6]);                                                  // statistics (MAC address etc.)
        return ms.ToArray();
    }

    [Fact]
    public void NodeStatus_PicksTheWorkstationName_NotTheDomain()
    {
        var response = NodeStatus(
            ("PARADISO", 0x00, 0x8400),   // domain: group name
            ("SVR-DC", 0x00, 0x0400),     // workstation: unique name
            ("SVR-DC", 0x20, 0x0400),     // file server service
            ("PARADISO", 0x1C, 0x8400));

        Assert.Equal("SVR-DC", NetBiosSource.ParseNodeStatus(response));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(20)]
    [InlineData(62)]
    public void NodeStatus_TruncatedOrEmptyAnswers_GiveNull(int length) =>
        Assert.Null(NetBiosSource.ParseNodeStatus(NodeStatus(("X", 0, 0))[..Math.Min(length, 60)]));

    [Fact]
    public void NodeStatus_OnlyGroupNames_GiveNull() =>
        Assert.Null(NetBiosSource.ParseNodeStatus(NodeStatus(("WORKGROUP", 0x00, 0x8400))));

    [Fact]
    public async Task NetBiosSource_AsksWithTheWildcardNodeStatusQuery()
    {
        using var server = new FakeUdpServer(_ => NodeStatus(("DESKTOP-ABC123", 0x00, 0x0400)));

        var name = await new NetBiosSource(server.Port).QueryAsync(IPAddress.Loopback, 1000, CancellationToken.None);

        Assert.Equal("DESKTOP-ABC123", name);
        var request = server.Received.Single();
        Assert.Equal(50, request.Length);
        Assert.Equal([0x00, 0x21, 0x00, 0x01], request[^4..]); // NBSTAT, IN
    }

    // ── Choosing between sources ─────────────────────────────────────────────

    private sealed class FakeSource(NameSource kind, string? name, int delayMs = 0, bool throws = false) : INameSource
    {
        public NameSource Kind { get; } = kind;
        public bool Asked { get; private set; }

        public async Task<string?> QueryAsync(IPAddress address, int timeoutMs, CancellationToken ct)
        {
            Asked = true;
            if (delayMs > 0) await Task.Delay(delayMs, ct);
            if (throws) throw new InvalidOperationException("boom");
            return name;
        }
    }

    [Fact]
    public async Task Resolver_PrefersDns_EvenWhenAFasterSourceAnswersFirst()
    {
        var resolver = new HostNameResolver(
            [new FakeSource(NameSource.Dns, "svr-dc.paradiso.local", delayMs: 250), new FakeSource(NameSource.NetBios, "SVR-DC")], 2000);

        var result = await resolver.ResolveAsync(Host, CancellationToken.None);

        Assert.Equal(new HostName("svr-dc.paradiso.local", NameSource.Dns), result);
    }

    [Fact]
    public async Task Resolver_DoesNotWaitForSlowerSources_OnceAPreferredOneAnswered()
    {
        var resolver = new HostNameResolver(
            [new FakeSource(NameSource.Dns, "fast.local"), new FakeSource(NameSource.NetBios, "SLOW", delayMs: 3000)], 5000);

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var result = await resolver.ResolveAsync(Host, CancellationToken.None);

        Assert.Equal("fast.local", result!.Name);
        Assert.True(sw.ElapsedMilliseconds < 1000, $"took {sw.ElapsedMilliseconds} ms");
    }

    [Fact]
    public async Task Resolver_FallsBackToTheNextSource_WhenDnsHasNoName()
    {
        var resolver = new HostNameResolver(
            [new FakeSource(NameSource.Dns, null), new FakeSource(NameSource.MDns, null), new FakeSource(NameSource.NetBios, "WINBOX")], 2000);

        Assert.Equal(new HostName("WINBOX", NameSource.NetBios), await resolver.ResolveAsync(Host, CancellationToken.None));
    }

    [Fact]
    public async Task Resolver_AFailingSourceNeverHidesTheOthers()
    {
        var resolver = new HostNameResolver(
            [new FakeSource(NameSource.Dns, "x", throws: true), new FakeSource(NameSource.MDns, "iphone.local")], 2000);

        Assert.Equal("iphone.local", (await resolver.ResolveAsync(Host, CancellationToken.None))!.Name);
    }

    [Fact]
    public async Task Resolver_NoAnswers_GivesNull() =>
        Assert.Null(await new HostNameResolver([new FakeSource(NameSource.Dns, null), new FakeSource(NameSource.NetBios, null)], 500)
            .ResolveAsync(Host, CancellationToken.None));

    [Theory]
    [InlineData("host.example.com.", "host.example.com")]
    [InlineData("  spaced  ", "spaced")]
    [InlineData("tab\there", "tabhere")]
    [InlineData("localhost", null)]
    [InlineData("LOCALHOST", null)]
    [InlineData("10.0.0.212", null)]
    [InlineData("212.0.0.10.in-addr.arpa", null)]
    [InlineData("", null)]
    [InlineData(null, null)]
    public void Clean_MakesNamesSafeToShow(string? raw, string? expected) =>
        Assert.Equal(expected, HostNameResolver.Clean(raw, Host));

    // ── In the scan ──────────────────────────────────────────────────────────

    private sealed class AlivePinger(params string[] alive) : IPinger
    {
        public Task<PingOutcome> PingAsync(IPAddress address, int timeoutMs, CancellationToken ct) =>
            Task.FromResult(alive.Contains(address.ToString()) ? new PingOutcome(PingStatus.Success, 1, 64) : new PingOutcome(PingStatus.TimedOut));
    }

    private sealed class FakeResolver : IHostNameResolver
    {
        public List<string> Asked { get; } = [];

        public Task<HostName?> ResolveAsync(IPAddress address, CancellationToken ct)
        {
            lock (Asked) Asked.Add(address.ToString());
            return Task.FromResult<HostName?>(address.ToString() == "10.0.0.2" ? null : new HostName($"host-{address.GetAddressBytes()[3]}.local", NameSource.Dns));
        }
    }

    private static readonly DiscoverySettings Fast = new() { ProbesPerSecond = 0, TimeoutMs = 100, Retries = 0 };

    [Fact]
    public async Task Scan_ResolvesNamesOfLiveHostsOnly_WhenEnabled()
    {
        var resolver = new FakeResolver();
        var engine = new ScanEngine(new AlivePinger("10.0.0.1", "10.0.0.2", "10.0.0.3"), Fast with { ResolveNames = true }, names: resolver);

        var names = new Dictionary<string, HostName?>();
        await foreach (var e in engine.RunAsync(TargetSet.Parse("10.0.0.1-5"), []))
            if (e is NameResolved n) names[n.Address.ToString()] = n.Name;

        Assert.Equal(["10.0.0.1", "10.0.0.2", "10.0.0.3"], names.Keys.Order());
        Assert.Equal("host-1.local", names["10.0.0.1"]!.Name);
        Assert.Null(names["10.0.0.2"]); // asked, nobody knew: reported as "no name" so the grid can stop waiting
        Assert.Equal(3, resolver.Asked.Count);
    }

    [Fact]
    public async Task Scan_DoesNotLookUpNames_WhenDisabled()
    {
        var resolver = new FakeResolver();
        var engine = new ScanEngine(new AlivePinger("10.0.0.1"), Fast, names: resolver);

        var events = new List<ScanEvent>();
        await foreach (var e in engine.RunAsync(TargetSet.Parse("10.0.0.1-3"), [])) events.Add(e);

        Assert.DoesNotContain(events, e => e is NameResolved);
        Assert.Empty(resolver.Asked);
    }

    // ── The hostname as evidence for the device guess ────────────────────────

    [Theory]
    [InlineData("SVR-GECOTI-12C.PARADISO.local", DeviceKind.Server)]
    [InlineData("svr-dc.paradiso.local", DeviceKind.Server)]
    [InlineData("NPIE77041.PARADISO.local", DeviceKind.Printer)]
    [InlineData("BRN30055C", DeviceKind.Printer)]
    [InlineData("DESKTOP-ABC123", DeviceKind.Computer)]
    [InlineData("Pascals-MacBook-Pro.local", DeviceKind.Computer)]
    [InlineData("Pascals-iPhone.local", DeviceKind.Mobile)]
    [InlineData("android-5f3c1a", DeviceKind.Mobile)]
    [InlineData("ap-office-2", DeviceKind.NetworkDevice)]
    [InlineData("cam-entrance", DeviceKind.Camera)]
    [InlineData("diskstation.paradiso.local", DeviceKind.Unknown)]
    [InlineData("reception", DeviceKind.Unknown)]
    [InlineData("capital", DeviceKind.Unknown)]   // contains "ap" but not as a word
    public void Hostname_FeedsTheDeviceGuess(string name, DeviceKind expected) =>
        Assert.Equal(expected, DeviceClassifier.Classify(new DeviceEvidence(0, "F8:ED:FC:21:6E:26", [], HostName: name)).Kind);

    [Fact]
    public void HostnameReason_NamesTheHostname()
    {
        var guess = DeviceClassifier.Classify(new DeviceEvidence(0, null, [], HostName: "SVR-DC.paradiso.local"));
        Assert.Contains("SVR-DC.paradiso.local", guess.Reason);
    }

    [Fact]
    public void ABannerFromTheDevice_BeatsItsHostname() =>
        Assert.Equal(DeviceKind.Printer, DeviceClassifier.Classify(new DeviceEvidence(255, null,
            [new ServiceEvidence("snmp", [161], "HP LaserJet MFP", "")], HostName: "SVR-FILES")).Kind);
}
