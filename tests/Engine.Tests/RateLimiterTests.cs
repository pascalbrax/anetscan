using System.Diagnostics;
using ANetworkScanner.Engine.Discovery;
using Xunit;

namespace ANetworkScanner.Engine.Tests;

public class RateLimiterTests
{
    [Fact]
    public async Task Unlimited_NeverWaits()
    {
        var limiter = new RateLimiter(0);
        Assert.True(limiter.IsUnlimited);

        var sw = Stopwatch.StartNew();
        for (int i = 0; i < 10_000; i++) await limiter.WaitAsync();
        Assert.True(sw.ElapsedMilliseconds < 500);
    }

    [Fact]
    public async Task Burst_IsGrantedImmediately()
    {
        var limiter = new RateLimiter(10, burst: 5);

        var sw = Stopwatch.StartNew();
        for (int i = 0; i < 5; i++) await limiter.WaitAsync();
        Assert.True(sw.ElapsedMilliseconds < 50, $"burst took {sw.ElapsedMilliseconds} ms");
    }

    [Fact]
    public async Task SustainedRate_IsEnforced()
    {
        // 100/s with no burst: 31 permits need at least 30 intervals = 300 ms.
        var limiter = new RateLimiter(100, burst: 1);

        var sw = Stopwatch.StartNew();
        for (int i = 0; i < 31; i++) await limiter.WaitAsync();
        Assert.InRange(sw.ElapsedMilliseconds, 270, 1500);
    }

    [Fact]
    public async Task ConcurrentWaiters_ShareOneRate()
    {
        var limiter = new RateLimiter(200, burst: 1);

        var sw = Stopwatch.StartNew();
        await Task.WhenAll(Enumerable.Range(0, 41).Select(_ => limiter.WaitAsync().AsTask()));
        Assert.InRange(sw.ElapsedMilliseconds, 180, 1500);
    }

    [Fact]
    public async Task Cancellation_AbortsAWait()
    {
        var limiter = new RateLimiter(1, burst: 1);
        await limiter.WaitAsync();
        using var cts = new CancellationTokenSource(100);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
        {
            await limiter.WaitAsync(cts.Token);
            await limiter.WaitAsync(cts.Token);
        });
    }

    [Theory]
    [InlineData(100, 5)]
    [InlineData(500, 25)]
    [InlineData(2000, 100)]
    [InlineData(1, 1)]
    public void DefaultBurst_IsAbout50Ms(double rate, int expected) =>
        Assert.Equal(expected, RateLimiter.DefaultBurst(rate));
}
