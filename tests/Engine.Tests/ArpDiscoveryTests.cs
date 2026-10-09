using System.Collections.Concurrent;
using System.Net;
using ANetworkScanner.Engine.Discovery;
using ANetworkScanner.Engine.Settings;
using ANetworkScanner.Engine.Targets;
using Xunit;

namespace ANetworkScanner.Engine.Tests;

public class ArpDiscoveryTests
{
    private sealed class FakePinger(Func<IPAddress, int, PingOutcome> behaviour) : IPinger
    {
        public ConcurrentDictionary<string, int> Calls { get; } = new();

        public Task<PingOutcome> PingAsync(IPAddress address, int timeoutMs, CancellationToken ct)
        {
            var attempt = Calls.AddOrUpdate(address.ToString(), 1, (_, n) => n + 1);
            return Task.FromResult(behaviour(address, attempt));
        }
    }

    private sealed class FakeArp(Func<IPAddress, string?> behaviour) : IArpResolver
    {
        public ConcurrentBag<string> Asked { get; } = [];

        public Task<string?> ResolveAsync(IPAddress address, int timeoutMs, CancellationToken ct)
        {
            Asked.Add(address.ToString());
            return Task.FromResult(behaviour(address));
        }
    }

    private static readonly DiscoverySettings Fast = new() { ProbesPerSecond = 0, MaxInFlight = 32, TimeoutMs = 100, Retries = 1 };

    private static readonly LocalSubnets Lan = new([(IPAddress.Parse("172.16.128.102"), 24)]);

    private static int Last(IPAddress a) => a.GetAddressBytes()[3];

    private static async Task<Dictionary<string, HostObservation>> Run(
        DiscoveryEngine engine, string target)
    {
        var map = new Dictionary<string, HostObservation>();
        await foreach (var o in engine.RunAsync(TargetSet.Parse(target))) map[o.Address.ToString()] = o;
        return map;
    }

    private static PingOutcome Silent => new(PingStatus.TimedOut);

    [Fact]
    public void LocalSubnets_RecognisesOnLinkAddresses()
    {
        Assert.True(Lan.IsOnLink(TargetSet.ToValue(IPAddress.Parse("172.16.128.1"))));
        Assert.True(Lan.IsOnLink(TargetSet.ToValue(IPAddress.Parse("172.16.128.254"))));
        Assert.False(Lan.IsOnLink(TargetSet.ToValue(IPAddress.Parse("172.16.129.1"))));
        Assert.False(Lan.IsOnLink(TargetSet.ToValue(IPAddress.Parse("10.0.0.50"))));
        Assert.False(Lan.IsOnLink(TargetSet.ToValue(IPAddress.Parse("172.16.128.0"))), "network address");
        Assert.False(Lan.IsOnLink(TargetSet.ToValue(IPAddress.Parse("172.16.128.255"))), "broadcast address");
        Assert.False(LocalSubnets.None.IsOnLink(TargetSet.ToValue(IPAddress.Parse("172.16.128.1"))));
    }

    [Fact]
    public void LocalSubnets_PointToPoint31_BothAddressesAreHosts()
    {
        var p2p = new LocalSubnets([(IPAddress.Parse("10.9.9.4"), 31)]);
        Assert.True(p2p.IsOnLink(TargetSet.ToValue(IPAddress.Parse("10.9.9.4"))));
        Assert.True(p2p.IsOnLink(TargetSet.ToValue(IPAddress.Parse("10.9.9.5"))));
    }

    [Fact]
    public async Task BroadcastAddress_IsNeverAskedViaArp()
    {
        var pinger = new FakePinger((_, _) => Silent);
        var arp = new FakeArp(_ => "2C:58:B9:8F:24:22"); // a device that answers ARP for everything, even x.x.x.255
        var results = await Run(new DiscoveryEngine(pinger, Fast, Lan, arp), "172.16.128.250-255");

        Assert.DoesNotContain("172.16.128.255", arp.Asked);
        Assert.False(results["172.16.128.255"].IsAlive);
        Assert.True(results["172.16.128.254"].IsAlive);
    }

    [Fact]
    public void LocalSubnets_Detect_ReturnsOnlyUsableAdapters()
    {
        // Real adapters: just make sure detection runs and never reports loopback.
        var detected = LocalSubnets.Detect();
        Assert.False(detected.IsOnLink(TargetSet.ToValue(IPAddress.Parse("127.0.0.1"))));
    }

    [Fact]
    public async Task OnLinkHostThatBlocksPing_IsFoundByArp_WithMac()
    {
        var pinger = new FakePinger((_, _) => Silent);
        var arp = new FakeArp(ip => Last(ip) == 64 ? "4C:CF:7C:48:E3:17" : null);
        var results = await Run(new DiscoveryEngine(pinger, Fast, Lan, arp), "172.16.128.60-70");

        var host = results["172.16.128.64"];
        Assert.True(host.IsAlive);
        Assert.Equal(DiscoveryMethod.Arp, host.Method);
        Assert.Equal("4C:CF:7C:48:E3:17", host.Mac);
        Assert.Equal(0, host.RttMs);
        Assert.Contains("ARP only", host.Detail);
        Assert.Equal(1, results.Values.Count(r => r.IsAlive));
    }

    [Fact]
    public async Task HostAnsweringBoth_GetsBothFlags_RttAndMac()
    {
        var pinger = new FakePinger((_, _) => new PingOutcome(PingStatus.Success, 0.8, 128));
        var arp = new FakeArp(_ => "AA:BB:CC:DD:EE:FF");
        var results = await Run(new DiscoveryEngine(pinger, Fast, Lan, arp), "172.16.128.1-5");

        Assert.All(results.Values, r =>
        {
            Assert.Equal(DiscoveryMethod.Icmp | DiscoveryMethod.Arp, r.Method);
            Assert.Equal("AA:BB:CC:DD:EE:FF", r.Mac);
            Assert.Equal(0.8, r.RttMs);
            Assert.Equal(128, r.Ttl);
        });
    }

    [Fact]
    public async Task OffLinkTargets_NeverUseArp()
    {
        var pinger = new FakePinger((ip, _) => Last(ip) == 50 ? new PingOutcome(PingStatus.Success, 3, 64) : Silent);
        var arp = new FakeArp(_ => "AA:BB:CC:DD:EE:FF"); // would "find" everything if it were consulted
        var results = await Run(new DiscoveryEngine(pinger, Fast, Lan, arp), "10.0.0.45-55");

        Assert.Empty(arp.Asked);
        Assert.Equal(["10.0.0.50"], results.Values.Where(r => r.IsAlive).Select(r => r.Address.ToString()));
        Assert.Null(results["10.0.0.50"].Mac);
        Assert.Equal(DiscoveryMethod.Icmp, results["10.0.0.50"].Method);
    }

    [Fact]
    public async Task WithoutResolver_OnLinkTargetsAreIcmpOnly()
    {
        var pinger = new FakePinger((_, _) => Silent);
        var results = await Run(new DiscoveryEngine(pinger, Fast, Lan, arp: null), "172.16.128.1-10");
        Assert.DoesNotContain(results.Values, r => r.IsAlive);
    }

    [Fact]
    public async Task ThrowingResolver_DoesNotBreakTheHost()
    {
        var pinger = new FakePinger((_, _) => new PingOutcome(PingStatus.Success, 1, 64));
        var arp = new FakeArp(_ => throw new InvalidOperationException("no adapter"));
        var results = await Run(new DiscoveryEngine(pinger, Fast, Lan, arp), "172.16.128.1-5");

        Assert.All(results.Values, r =>
        {
            Assert.True(r.IsAlive);
            Assert.Equal(DiscoveryMethod.Icmp, r.Method);
            Assert.Null(r.Mac);
        });
    }

    [Fact]
    public async Task IcmpRetry_IsSkipped_OnceArpAnswered()
    {
        var pinger = new FakePinger((_, _) => Silent);
        var arp = new FakeArp(_ => "AA:BB:CC:DD:EE:FF");
        var results = await Run(new DiscoveryEngine(pinger, Fast with { Retries = 3 }, Lan, arp), "172.16.128.1-5");

        // The fake ARP answers instantly, so no host needs more than the first ICMP attempt.
        Assert.All(results.Values, r => Assert.True(r.Attempts <= 2, $"{r.Address}: {r.Attempts} attempts"));
    }

    [Fact]
    public async Task IcmpRetry_StillHappens_WhenArpHasNothing()
    {
        var pinger = new FakePinger((_, _) => Silent);
        var arp = new FakeArp(_ => null);
        var results = await Run(new DiscoveryEngine(pinger, Fast with { Retries = 2 }, Lan, arp), "172.16.128.1-3");

        Assert.All(results.Values, r =>
        {
            Assert.False(r.IsAlive);
            Assert.Equal(3, r.Attempts);
        });
    }

    [Fact]
    public async Task SmallScan_ReportsPreciseRtt_LargeScanReportsWholeMilliseconds()
    {
        var pinger = new FakePinger((_, _) => new PingOutcome(PingStatus.Success, RttMs: 1.57, Ttl: 64, ApiRttMs: 2));

        var small = await Run(new DiscoveryEngine(pinger, Fast with { PreciseRttMaxTargets = 10 }), "10.0.0.1-10");
        Assert.All(small.Values, r => Assert.Equal(1.57, r.RttMs));

        var large = await Run(new DiscoveryEngine(pinger, Fast with { PreciseRttMaxTargets = 10 }), "10.0.0.1-11");
        Assert.All(large.Values, r => Assert.Equal(2, r.RttMs));
    }

    [Fact]
    public async Task LargeScan_SubMillisecondReply_IsReportedAsZero()
    {
        var pinger = new FakePinger((_, _) => new PingOutcome(PingStatus.Success, RttMs: 0.4, Ttl: 64, ApiRttMs: 0));
        var results = await Run(new DiscoveryEngine(pinger, Fast with { PreciseRttMaxTargets = 0 }), "10.0.0.1-5");

        Assert.All(results.Values, r =>
        {
            Assert.True(r.IsAlive);
            Assert.Equal(0, r.RttMs);
        });
    }
}
