namespace ANetworkScanner.Engine.Discovery;

/// <summary>
/// Async rate limiter using the Generic Cell Rate Algorithm (a token bucket expressed as a
/// single "theoretical arrival time"): permits are handed out evenly at
/// <c>permitsPerSecond</c>, with up to <c>burst</c> permits allowed back-to-back.
/// Every caller reserves its slot under a short lock and then waits outside it, so thousands of
/// concurrent waiters stay ordered and cost nothing while sleeping.
/// </summary>
public sealed class RateLimiter
{
    private readonly object _gate = new();
    private readonly TimeProvider _time;
    private readonly long _intervalTicks;   // timestamp ticks between two permits
    private readonly long _toleranceTicks;  // how far ahead of schedule a permit may be granted
    private long _theoreticalArrival;

    /// <param name="permitsPerSecond">Sustained rate. Zero or less means unlimited.</param>
    /// <param name="burst">Permits allowed instantly after an idle period (at least 1).</param>
    public RateLimiter(double permitsPerSecond, int burst = 1, TimeProvider? timeProvider = null)
    {
        _time = timeProvider ?? TimeProvider.System;
        if (permitsPerSecond <= 0 || double.IsInfinity(permitsPerSecond) || double.IsNaN(permitsPerSecond))
        {
            IsUnlimited = true;
            return;
        }

        burst = Math.Max(1, burst);
        _intervalTicks = Math.Max(1, (long)(_time.TimestampFrequency / permitsPerSecond));
        _toleranceTicks = _intervalTicks * burst;
        _theoreticalArrival = _time.GetTimestamp();
    }

    public bool IsUnlimited { get; }

    public static RateLimiter FromSettings(Settings.DiscoverySettings settings) =>
        new(settings.ProbesPerSecond, DefaultBurst(settings.ProbesPerSecond));

    /// <summary>A burst of about 50 ms worth of permits keeps the pacing smooth despite coarse OS timers.</summary>
    public static int DefaultBurst(double permitsPerSecond) =>
        (int)Math.Clamp(permitsPerSecond / 20, 1, 1000);

    public ValueTask WaitAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (IsUnlimited) return ValueTask.CompletedTask;

        long delayTicks;
        lock (_gate)
        {
            long now = _time.GetTimestamp();
            long next = Math.Max(now, _theoreticalArrival) + _intervalTicks;
            _theoreticalArrival = next;
            delayTicks = next - now - _toleranceTicks;
        }

        if (delayTicks <= 0) return ValueTask.CompletedTask;

        var delay = TimeSpan.FromSeconds((double)delayTicks / _time.TimestampFrequency);
        return new ValueTask(Task.Delay(delay, _time, cancellationToken));
    }
}
