using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using ANetworkScanner.Engine.Discovery;
using ANetworkScanner.Engine.Settings;
using ANetworkScanner.Engine.Targets;
using Xunit;

namespace ANetworkScanner.Engine.Tests;

public class DiscoveryEngineTests
{
    private sealed class FakePinger(Func<IPAddress, int, Task<PingOutcome>> behaviour) : IPinger
    {
        public ConcurrentDictionary<string, int> Calls { get; } = new();
        public int InFlight;
        public int MaxInFlight;

        public async Task<PingOutcome> PingAsync(IPAddress address, int timeoutMs, CancellationToken ct)
        {
            var attempt = Calls.AddOrUpdate(address.ToString(), 1, (_, n) => n + 1);
            int now = Interlocked.Increment(ref InFlight);
            int max;
            while (now > (max = Volatile.Read(ref MaxInFlight)) &&
                   Interlocked.CompareExchange(ref MaxInFlight, now, max) != max) { }
            try { return await behaviour(address, attempt); }
            finally { Interlocked.Decrement(ref InFlight); }
        }
    }

    private static readonly DiscoverySettings Fast = new()
    {
        ProbesPerSecond = 0, // unlimited
        MaxInFlight = 32,
        TimeoutMs = 100,
        Retries = 1,
    };

    private static async Task<List<HostObservation>> Collect(DiscoveryEngine engine, string target)
    {
        var list = new List<HostObservation>();
        await foreach (var o in engine.RunAsync(TargetSet.Parse(target))) list.Add(o);
        return list;
    }

    private static int LastOctet(IPAddress a) => a.GetAddressBytes()[3];

    [Fact]
    public async Task EveryTargetYieldsExactlyOneObservation()
    {
        var pinger = new FakePinger((ip, _) => Task.FromResult(
            LastOctet(ip) % 2 == 0 ? new PingOutcome(PingStatus.Success, 1.5, 64) : new PingOutcome(PingStatus.TimedOut)));
        var results = await Collect(new DiscoveryEngine(pinger, Fast), "10.0.0.1-100");

        Assert.Equal(100, results.Count);
        Assert.Equal(100, results.Select(r => r.Address.ToString()).Distinct().Count());
        Assert.Equal(50, results.Count(r => r.IsAlive));
        Assert.All(results.Where(r => r.IsAlive), r =>
        {
            Assert.Equal(DiscoveryMethod.Icmp, r.Method);
            Assert.Equal(64, r.Ttl);
            Assert.Equal(1.5, r.RttMs);
        });
    }

    [Fact]
    public async Task Timeouts_AreRetried_ButExplicitAnswersAreNot()
    {
        var pinger = new FakePinger((ip, attempt) => Task.FromResult(LastOctet(ip) switch
        {
            1 => new PingOutcome(PingStatus.TimedOut),                                   // never answers
            2 => attempt == 1 ? new PingOutcome(PingStatus.TimedOut)                     // answers on retry
                              : new PingOutcome(PingStatus.Success, 2, 128),
            _ => new PingOutcome(PingStatus.Unreachable, Detail: "DestinationHostUnreachable"),
        }));
        var results = (await Collect(new DiscoveryEngine(pinger, Fast), "10.0.0.1-3")).ToDictionary(r => LastOctet(r.Address));

        Assert.False(results[1].IsAlive);
        Assert.Equal(2, results[1].Attempts);
        Assert.True(results[2].IsAlive);
        Assert.Equal(2, results[2].Attempts);
        Assert.False(results[3].IsAlive);
        Assert.Equal(1, results[3].Attempts);
        Assert.Contains("Unreachable", results[3].Detail);
    }

    [Fact]
    public async Task UnreachableReplyFromARouter_IsNeverAlive()
    {
        var pinger = new FakePinger((_, _) => Task.FromResult(new PingOutcome(PingStatus.Unreachable)));
        var results = await Collect(new DiscoveryEngine(pinger, Fast), "10.0.0.1-20");
        Assert.DoesNotContain(results, r => r.IsAlive);
    }

    [Fact]
    public async Task InFlightProbes_NeverExceedTheLimit()
    {
        var pinger = new FakePinger(async (_, _) =>
        {
            await Task.Delay(20);
            return new PingOutcome(PingStatus.Success, 1);
        });
        var settings = Fast with { MaxInFlight = 8 };
        var results = await Collect(new DiscoveryEngine(pinger, settings), "10.0.0.1-200");

        Assert.Equal(200, results.Count);
        Assert.InRange(pinger.MaxInFlight, 2, 8);
    }

    [Fact]
    public async Task ThrowingPinger_StillReportsEveryTarget()
    {
        var pinger = new FakePinger((ip, _) =>
            LastOctet(ip) == 5 ? throw new InvalidOperationException("boom") : Task.FromResult(new PingOutcome(PingStatus.Success, 1)));
        var results = await Collect(new DiscoveryEngine(pinger, Fast), "10.0.0.1-10");

        Assert.Equal(10, results.Count);
        var failed = results.Single(r => LastOctet(r.Address) == 5);
        Assert.False(failed.IsAlive);
        Assert.Contains("boom", failed.Detail);
    }

    [Fact]
    public async Task Cancel_StopsPromptly_EvenWithHugeTargetSet()
    {
        var pinger = new FakePinger(async (_, _) =>
        {
            await Task.Delay(50);
            return new PingOutcome(PingStatus.TimedOut);
        });
        var engine = new DiscoveryEngine(pinger, Fast with { Retries = 0 });
        using var cts = new CancellationTokenSource();

        var sw = Stopwatch.StartNew();
        int seen = 0;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
        {
            await foreach (var _ in engine.RunAsync(TargetSet.Parse("10.0.0.0/8"), cts.Token))
            {
                if (++seen == 50) cts.Cancel();
            }
        });

        Assert.True(sw.ElapsedMilliseconds < 3000, $"stop took {sw.ElapsedMilliseconds} ms");
        Assert.True(pinger.Calls.Count < 5000, "probing must stop, not run through the /8");
    }

    [Fact]
    public async Task AbandoningTheEnumeration_StopsTheProducer()
    {
        var pinger = new FakePinger(async (_, _) =>
        {
            await Task.Delay(10);
            return new PingOutcome(PingStatus.Success, 1);
        });
        var engine = new DiscoveryEngine(pinger, Fast);

        await foreach (var _ in engine.RunAsync(TargetSet.Parse("10.0.0.0/8"))) break;

        var callsAfterBreak = pinger.Calls.Count;
        await Task.Delay(200);
        Assert.Equal(callsAfterBreak, pinger.Calls.Count);
    }

    [Fact]
    public async Task RateLimit_IsAppliedAcrossAllProbes()
    {
        var pinger = new FakePinger((_, _) => Task.FromResult(new PingOutcome(PingStatus.Success, 1)));
        // 100/s, burst 5 (default) => 60 probes need at least ~(60-5)/100 s.
        var engine = new DiscoveryEngine(pinger, Fast with { ProbesPerSecond = 100 });

        var sw = Stopwatch.StartNew();
        var results = await Collect(engine, "10.0.0.1-60");

        Assert.Equal(60, results.Count);
        Assert.True(sw.ElapsedMilliseconds >= 450, $"finished in {sw.ElapsedMilliseconds} ms - rate limit not applied");
    }
}
