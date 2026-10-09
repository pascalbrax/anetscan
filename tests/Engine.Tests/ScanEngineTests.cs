using System.Net;
using System.Net.Sockets;
using ANetworkScanner.Engine.Discovery;
using ANetworkScanner.Engine.Probes;
using ANetworkScanner.Engine.Settings;
using ANetworkScanner.Engine.Targets;
using Xunit;

namespace ANetworkScanner.Engine.Tests;

public class ScanEngineTests
{
    private sealed class AlivePinger(params string[] alive) : IPinger
    {
        public Task<PingOutcome> PingAsync(IPAddress address, int timeoutMs, CancellationToken ct) =>
            Task.FromResult(alive.Contains(address.ToString())
                ? new PingOutcome(PingStatus.Success, 0.5, 128, ApiRttMs: 0)
                : new PingOutcome(PingStatus.TimedOut));
    }

    private static readonly DiscoverySettings Fast = new() { ProbesPerSecond = 0, TimeoutMs = 100, Retries = 0 };

    private static ProbeDefinition Probe(string json) =>
        Assert.Single(ProbeLoader.LoadFromJson(json, "t.json").Probes);

    [Fact]
    public async Task ProbesRunOnlyOnLiveHosts_AndResultsAreStreamed()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        _ = Task.Run(async () =>
        {
            while (true)
            {
                try
                {
                    using var c = await listener.AcceptTcpClientAsync();
                    await c.GetStream().WriteAsync("SSH-2.0-test\r\n"u8.ToArray());
                }
                catch { return; }
            }
        });

        var probe = Probe($$"""
            { "id": "ssh", "title": "SSH", "ports": [{{port}}], "steps": [ { "read": {} } ],
              "match": [ { "regex": "^SSH-2.0-(?<sw>\\S+)", "short": "{sw}" } ] }
            """);

        var engine = new ScanEngine(new AlivePinger("127.0.0.1"), Fast);
        var scanned = new List<HostScanned>();
        var probed = new List<ProbeCompleted>();
        await foreach (var e in engine.RunAsync(TargetSet.Parse("127.0.0.1-127.0.0.3"), [probe]))
        {
            if (e is HostScanned h) scanned.Add(h);
            if (e is ProbeCompleted p) probed.Add(p);
        }
        listener.Stop();

        Assert.Equal(3, scanned.Count);
        Assert.Equal(1, scanned.Count(h => h.Host.IsAlive));
        var only = Assert.Single(probed);
        Assert.Equal("127.0.0.1", only.Address.ToString());
        Assert.Equal("test", only.Result.Short);
    }

    [Fact]
    public async Task NoProbes_MeansDiscoveryOnly()
    {
        var engine = new ScanEngine(new AlivePinger("10.0.0.1", "10.0.0.2"), Fast);
        var events = new List<ScanEvent>();
        await foreach (var e in engine.RunAsync(TargetSet.Parse("10.0.0.1-5"), [])) events.Add(e);

        Assert.Equal(5, events.OfType<HostScanned>().Count());
        Assert.Empty(events.OfType<ProbeCompleted>());
    }

    [Fact]
    public async Task EveryProbeRunsOnEveryLiveHost()
    {
        var closed = new TcpListener(IPAddress.Loopback, 0);
        closed.Start();
        int port = ((IPEndPoint)closed.LocalEndpoint).Port;
        closed.Stop();

        var a = Probe($$"""{ "id": "a", "ports": [{{port}}] }""");
        var b = Probe($$"""{ "id": "b", "ports": [{{port}}] }""");
        var engine = new ScanEngine(new AlivePinger("127.0.0.1", "127.0.0.2"), Fast);

        var probed = new List<ProbeCompleted>();
        await foreach (var e in engine.RunAsync(TargetSet.Parse("127.0.0.1-127.0.0.2"), [a, b]))
            if (e is ProbeCompleted p) probed.Add(p);

        Assert.Equal(4, probed.Count);
        Assert.Equal(2, probed.Count(p => p.Address.ToString() == "127.0.0.1"));
        Assert.All(probed, p => Assert.Equal(PortState.Closed, p.Result.State));
    }

    [Fact]
    public async Task Cancel_StopsTheWholePipeline()
    {
        var engine = new ScanEngine(new AlivePinger(), Fast with { Retries = 0 });
        using var cts = new CancellationTokenSource(100);

        var sw = System.Diagnostics.Stopwatch.StartNew();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
        {
            await foreach (var _ in engine.RunAsync(TargetSet.Parse("10.0.0.0/8"), [], cts.Token)) { }
        });
        Assert.True(sw.ElapsedMilliseconds < 3000, $"stop took {sw.ElapsedMilliseconds} ms");
    }
}
