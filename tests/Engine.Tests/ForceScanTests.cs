using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using ANetworkScanner.Engine.Discovery;
using ANetworkScanner.Engine.Settings;
using ANetworkScanner.Engine.Targets;
using Xunit;

namespace ANetworkScanner.Engine.Tests;

public class ForceScanTests
{
    private sealed class FakeIcmp(Func<IPAddress, PingOutcome> reply) : IPinger
    {
        public Task<PingOutcome> PingAsync(IPAddress address, int timeoutMs, CancellationToken ct) => Task.FromResult(reply(address));
    }

    private sealed class FakeTcp(Func<IPAddress, int, TcpPortOutcome> reply) : ITcpPinger
    {
        public ConcurrentBag<(string Ip, int Port)> Calls { get; } = [];

        public Task<TcpPingOutcome> PingAsync(IPAddress address, int port, int timeoutMs, CancellationToken ct)
        {
            Calls.Add((address.ToString(), port));
            return Task.FromResult(new TcpPingOutcome(reply(address, port), 1.5));
        }
    }

    private static readonly PingOutcome Silent = new(PingStatus.TimedOut);

    private static DiscoverySettings Settings(bool force = true) => new()
    {
        ProbesPerSecond = 0,
        MaxInFlight = 32,
        TimeoutMs = 100,
        Retries = 0,
        ConnectRetries = 1,
        ForceScan = force,
        ForceScanPorts = [22, 445, 3389],
    };

    private static async Task<Dictionary<string, HostObservation>> Run(DiscoveryEngine engine, string target)
    {
        var map = new Dictionary<string, HostObservation>();
        await foreach (var o in engine.RunAsync(TargetSet.Parse(target))) map[o.Address.ToString()] = o;
        return map;
    }

    [Fact]
    public async Task Off_NeverOpensATcpConnection()
    {
        var tcp = new FakeTcp((_, _) => TcpPortOutcome.Open);
        var results = await Run(new DiscoveryEngine(new FakeIcmp(_ => Silent), Settings(force: false), tcp: tcp), "10.0.0.1-5");

        Assert.Empty(tcp.Calls);
        Assert.DoesNotContain(results.Values, r => r.IsAlive);
    }

    [Fact]
    public async Task ASilentHostWithAnOpenPort_IsListedAsTcpOnly()
    {
        var tcp = new FakeTcp((ip, port) => ip.ToString() == "10.0.0.3" && port == 445 ? TcpPortOutcome.Open : TcpPortOutcome.NoAnswer);
        var results = await Run(new DiscoveryEngine(new FakeIcmp(_ => Silent), Settings(), tcp: tcp), "10.0.0.1-5");

        var host = results["10.0.0.3"];
        Assert.True(host.IsAlive);
        Assert.Equal(DiscoveryMethod.Tcp, host.Method);
        Assert.Equal(0, host.Ttl);
        Assert.Contains("445", host.Detail);
        Assert.Contains("accepted", host.Detail);
        Assert.Single(results.Values, r => r.IsAlive);
    }

    [Fact]
    public async Task ARefusal_AlsoProvesTheHostIsThere()
    {
        var tcp = new FakeTcp((ip, port) => ip.ToString() == "10.0.0.2" && port == 22 ? TcpPortOutcome.Refused : TcpPortOutcome.NoAnswer);
        var results = await Run(new DiscoveryEngine(new FakeIcmp(_ => Silent), Settings(), tcp: tcp), "10.0.0.1-3");

        Assert.True(results["10.0.0.2"].IsAlive);
        Assert.Contains("refused", results["10.0.0.2"].Detail);
        Assert.False(results["10.0.0.1"].IsAlive);
    }

    [Fact]
    public async Task SilenceOnEveryPort_MeansNoHost_AfterRetryingEachPort()
    {
        var tcp = new FakeTcp((_, _) => TcpPortOutcome.NoAnswer);
        var results = await Run(new DiscoveryEngine(new FakeIcmp(_ => Silent), Settings(), tcp: tcp), "10.0.0.7");

        Assert.False(results["10.0.0.7"].IsAlive);
        Assert.Equal(3 * 2, tcp.Calls.Count); // 3 ports x (1 try + 1 retry)
    }

    [Fact]
    public async Task HostsThatAnswerPing_AreNotCheckedOnTcp()
    {
        var tcp = new FakeTcp((_, _) => TcpPortOutcome.Open);
        var icmp = new FakeIcmp(ip => ip.GetAddressBytes()[3] == 1 ? new PingOutcome(PingStatus.Success, 1, 64) : Silent);
        var results = await Run(new DiscoveryEngine(icmp, Settings(), tcp: tcp), "10.0.0.1-2");

        Assert.Equal(DiscoveryMethod.Icmp, results["10.0.0.1"].Method);
        Assert.DoesNotContain(tcp.Calls, c => c.Ip == "10.0.0.1");
        Assert.Equal(DiscoveryMethod.Tcp, results["10.0.0.2"].Method);
    }

    [Fact]
    public async Task HostsAnsweringArp_AreNotCheckedOnTcp()
    {
        var tcp = new FakeTcp((_, _) => TcpPortOutcome.Open);
        var arp = new ArpAnswers("AA:BB:CC:DD:EE:FF");
        var lan = new LocalSubnets([(IPAddress.Parse("10.0.0.99"), 24)]);
        var results = await Run(new DiscoveryEngine(new FakeIcmp(_ => Silent), Settings(), lan, arp, tcp: tcp), "10.0.0.2-3");

        Assert.All(results.Values, r => Assert.Equal(DiscoveryMethod.Arp, r.Method));
        Assert.Empty(tcp.Calls);
    }

    private sealed class ArpAnswers(string mac) : IArpResolver
    {
        public Task<string?> ResolveAsync(IPAddress address, int timeoutMs, CancellationToken ct) => Task.FromResult<string?>(mac);
    }

    [Fact]
    public async Task ARouterSayingUnreachable_MeansThereIsNoHost_SoNoTcpCheckIsMade()
    {
        var tcp = new FakeTcp((_, _) => TcpPortOutcome.Open);
        var icmp = new FakeIcmp(_ => new PingOutcome(PingStatus.Unreachable, Detail: "DestinationHostUnreachable"));
        var results = await Run(new DiscoveryEngine(icmp, Settings(), tcp: tcp), "10.0.0.1-3");

        Assert.Empty(tcp.Calls);
        Assert.DoesNotContain(results.Values, r => r.IsAlive);
    }

    [Fact]
    public async Task UnreachableOverTcp_IsNotRetried()
    {
        var tcp = new FakeTcp((_, _) => TcpPortOutcome.Unreachable);
        await Run(new DiscoveryEngine(new FakeIcmp(_ => Silent), Settings(), tcp: tcp), "10.0.0.7");
        Assert.Equal(3, tcp.Calls.Count); // one try per port, no retries
    }

    [Fact]
    public async Task TheScanEngine_ThenRunsServiceProbesOnTheForcedHost()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        _ = Task.Run(async () =>
        {
            try { using var c = await listener.AcceptTcpClientAsync(); await c.GetStream().WriteAsync("SSH-2.0-forced\r\n"u8.ToArray()); }
            catch { }
        });

        var probe = Assert.Single(Engine.Probes.ProbeLoader.LoadFromJson($$"""
            { "id": "ssh", "ports": [{{port}}], "steps": [ { "read": {} } ], "match": [ { "regex": "^SSH-2.0-(?<sw>\\S+)", "short": "{sw}" } ] }
            """, "t.json").Probes);

        var engine = new ScanEngine(new FakeIcmp(_ => Silent), Settings(),
            tcp: new FakeTcp((_, p) => p == 445 ? TcpPortOutcome.Open : TcpPortOutcome.NoAnswer));

        var probed = new List<ProbeCompleted>();
        HostScanned? scanned = null;
        await foreach (var e in engine.RunAsync(TargetSet.Parse("127.0.0.1"), [probe]))
        {
            if (e is HostScanned h) scanned = h;
            if (e is ProbeCompleted p) probed.Add(p);
        }
        listener.Stop();

        Assert.Equal(DiscoveryMethod.Tcp, scanned!.Host.Method);
        Assert.Equal("forced", Assert.Single(probed).Result.Short);
    }

    // ── The real connector, on loopback ──────────────────────────────────────

    [Fact]
    public async Task SystemTcpPinger_TellsOpenFromRefused_Quickly()
    {
        var open = new TcpListener(IPAddress.Loopback, 0);
        open.Start();
        int openPort = ((IPEndPoint)open.LocalEndpoint).Port;

        var closed = new TcpListener(IPAddress.Loopback, 0);
        closed.Start();
        int closedPort = ((IPEndPoint)closed.LocalEndpoint).Port;
        closed.Stop();

        var pinger = new SystemTcpPinger();
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var a = await pinger.PingAsync(IPAddress.Loopback, openPort, 1000, CancellationToken.None);
        var b = await pinger.PingAsync(IPAddress.Loopback, closedPort, 1000, CancellationToken.None);
        open.Stop();

        Assert.Equal(TcpPortOutcome.Open, a.Outcome);
        Assert.Equal(TcpPortOutcome.Refused, b.Outcome);
        Assert.True(a.ProvesHostIsUp && b.ProvesHostIsUp);
        Assert.True(sw.ElapsedMilliseconds < 800, $"took {sw.ElapsedMilliseconds} ms (Windows would need ~2 s per refusal without the SYN tuning)");
    }

    [Fact]
    public async Task SystemTcpPinger_Cancellation_IsPropagated()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new SystemTcpPinger().PingAsync(IPAddress.Loopback, 9, 1000, cts.Token));
    }

    // ── Settings ─────────────────────────────────────────────────────────────

    [Fact]
    public void ForceScan_IsOffByDefault_WithAUsefulPortList()
    {
        var d = new DiscoverySettings();
        Assert.False(d.ForceScan);
        Assert.Contains(445, d.ForceScanPorts);
        Assert.Contains(22, d.ForceScanPorts);
        Assert.Contains(3389, d.ForceScanPorts);
    }

    [Fact]
    public void Normalized_CleansTheForcedPortList()
    {
        var d = new DiscoverySettings { ForceScanPorts = [80, 80, 0, -5, 70000, 443, .. Enumerable.Range(1000, 50)] }.Normalized();

        Assert.Equal(80, d.ForceScanPorts[0]);
        Assert.Equal(443, d.ForceScanPorts[1]);
        Assert.Equal(d.ForceScanPorts.Length, d.ForceScanPorts.Distinct().Count());
        Assert.All(d.ForceScanPorts, p => Assert.InRange(p, 1, 65535));
        Assert.True(d.ForceScanPorts.Length <= 32);
    }

    [Fact]
    public void ForceScan_SurvivesASettingsRoundTrip()
    {
        var path = Path.Combine(Path.GetTempPath(), "ans-force-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            var store = new SettingsStore(path);
            store.Save(new AppSettings { Discovery = new DiscoverySettings { ForceScan = true, ForceScanPorts = [8080, 22] } });
            var loaded = store.Load().Discovery;
            Assert.True(loaded.ForceScan);
            Assert.Equal([8080, 22], loaded.ForceScanPorts);
        }
        finally { File.Delete(path); }
    }
}
