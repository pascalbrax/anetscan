using System.Net;
using System.Runtime.CompilerServices;
using System.Threading.Channels;
using ANetworkScanner.Engine.Settings;
using ANetworkScanner.Engine.Targets;

namespace ANetworkScanner.Engine.Discovery;

/// <summary>How a host was found. Both flags set means it answered ICMP and ARP.</summary>
[Flags]
public enum DiscoveryMethod
{
    None = 0,
    Icmp = 1,
    Arp = 2,
    /// <summary>Neither ping nor ARP answered, but a TCP port opened or refused the connection.</summary>
    Tcp = 4,
}

/// <summary>The outcome for one target address. Every target yields exactly one observation.</summary>
/// <param name="RttMs">ICMP round trip in ms; 0 when the host did not answer ICMP.</param>
/// <param name="Mac">Only known for on-link hosts that answered ARP.</param>
public sealed record HostObservation(
    IPAddress Address,
    bool IsAlive,
    DiscoveryMethod Method,
    double RttMs,
    int Ttl,
    int Attempts,
    string Detail,
    string? Mac = null);

/// <summary>
/// Streams <see cref="HostObservation"/>s as probes finish. Probes are paced by a shared
/// <see cref="RateLimiter"/> and bounded by <see cref="DiscoverySettings.MaxInFlight"/>; nothing is
/// ever queued per target, so a /8 uses the same memory as a /24.
/// <para>
/// ICMP is the primary method. For targets inside a subnet this machine is attached to
/// (<see cref="LocalSubnets"/>), ARP runs alongside it: it finds hosts that drop ping and yields the MAC.
/// ARP is never used for anything behind a router.
/// </para>
/// </summary>
public sealed class DiscoveryEngine
{
    private readonly IPinger _pinger;
    private readonly DiscoverySettings _settings;
    private readonly LocalSubnets _subnets;
    private readonly IArpResolver? _arp;
    private readonly RateLimiter? _sharedLimiter;
    private readonly ITcpPinger? _tcp;

    /// <param name="sharedLimiter">
    /// Lets discovery and later probing draw from one budget, so the configured rate caps the scan as a whole.
    /// When null the engine paces itself with a limiter built from the settings.
    /// </param>
    public DiscoveryEngine(IPinger pinger, DiscoverySettings settings, LocalSubnets? subnets = null,
        IArpResolver? arp = null, RateLimiter? sharedLimiter = null, ITcpPinger? tcp = null)
    {
        _pinger = pinger;
        _settings = settings.Normalized();
        _subnets = subnets ?? LocalSubnets.None;
        _arp = arp;
        _sharedLimiter = sharedLimiter;
        _tcp = _settings.ForceScan && _settings.ForceScanPorts.Length > 0 ? tcp ?? new SystemTcpPinger() : null;
    }

    public async IAsyncEnumerable<HostObservation> RunAsync(
        TargetSet targets,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var results = Channel.CreateBounded<HostObservation>(new BoundedChannelOptions(4096)
        {
            SingleReader = true,
            FullMode = BoundedChannelFullMode.Wait,
        });

        var producer = ProduceAsync(targets, results.Writer, cts.Token);

        try
        {
            await foreach (var observation in results.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
                yield return observation;
        }
        finally
        {
            // Consumer finished or walked away early: stop probing and let the producer unwind.
            await cts.CancelAsync().ConfigureAwait(false);
            try { await producer.ConfigureAwait(false); } catch (OperationCanceledException) { }
        }
    }

    private async Task ProduceAsync(TargetSet targets, ChannelWriter<HostObservation> writer, CancellationToken ct)
    {
        var limiter = _sharedLimiter ?? RateLimiter.FromSettings(_settings);
        bool preciseRtt = targets.Count <= _settings.PreciseRttMaxTargets;
        using var slots = new SemaphoreSlim(_settings.MaxInFlight, _settings.MaxInFlight);

        try
        {
            foreach (var value in targets.EnumerateValues())
            {
                await slots.WaitAsync(ct).ConfigureAwait(false);
                _ = ProbeAsync(value);
            }

            // Wait for the last probes: take every slot back.
            for (int i = 0; i < _settings.MaxInFlight; i++)
                await slots.WaitAsync(ct).ConfigureAwait(false);

            writer.TryComplete();
        }
        catch (OperationCanceledException)
        {
            writer.TryComplete();
            throw;
        }
        catch (Exception ex)
        {
            writer.TryComplete(ex);
        }

        async Task ProbeAsync(uint value)
        {
            var address = TargetSet.ToAddress(value);
            try
            {
                var observation = await ProbeHostAsync(address, _subnets.IsOnLink(value), preciseRtt, limiter, ct)
                    .ConfigureAwait(false);
                await writer.WriteAsync(observation, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Scan stopped; the slot is released below.
            }
            catch (Exception ex)
            {
                // A misbehaving pinger must not silently drop a target: report it as not alive.
                try
                {
                    await writer.WriteAsync(
                        new HostObservation(address, false, DiscoveryMethod.None, 0, 0, 0, $"Error: {ex.Message}"), ct)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException) { }
            }
            finally
            {
                slots.Release();
            }
        }
    }

    private async Task<HostObservation> ProbeHostAsync(
        IPAddress address, bool onLink, bool preciseRtt, RateLimiter limiter, CancellationToken ct)
    {
        // ARP and ICMP run side by side; a silent host is then settled by ARP in milliseconds instead of
        // waiting out ICMP's timeout and retry.
        Task<string?>? arpTask = onLink && _arp is not null ? ResolveArpAsync(address, limiter, ct) : null;

        PingOutcome outcome = default;
        int attempts = 0;

        for (int attempt = 0; attempt <= _settings.Retries; attempt++)
        {
            await limiter.WaitAsync(ct).ConfigureAwait(false);
            attempts++;
            outcome = await _pinger.PingAsync(address, _settings.TimeoutMs, ct).ConfigureAwait(false);

            // Only silence is worth repeating: an explicit reply (even "unreachable") will not change.
            if (outcome.Status != PingStatus.TimedOut) break;
            // The host already proved it is there; do not make the user wait for a ping it will not answer.
            if (arpTask is { IsCompletedSuccessfully: true, Result: not null }) break;
        }

        string? mac = arpTask is null ? null : await arpTask.ConfigureAwait(false);

        bool icmpAlive = outcome.Status == PingStatus.Success;
        var method = (icmpAlive ? DiscoveryMethod.Icmp : 0) | (mac is not null ? DiscoveryMethod.Arp : 0);

        if (method == DiscoveryMethod.None)
        {
            // A router saying "unreachable" means there is no host; only plain silence is worth a second look.
            if (_tcp is not null && outcome.Status == PingStatus.TimedOut &&
                await TcpCheckAsync(address, limiter, ct).ConfigureAwait(false) is { } found)
            {
                var what = found.Result.Outcome == TcpPortOutcome.Open ? "accepted a connection" : "refused a connection";
                return new HostObservation(address, true, DiscoveryMethod.Tcp, 0, 0, attempts,
                    $"no ping or ARP reply; TCP port {found.Port} {what}");
            }

            return new HostObservation(address, false, DiscoveryMethod.None, 0, 0, attempts,
                outcome.Status == PingStatus.TimedOut ? "no reply" : $"{outcome.Status}: {outcome.Detail}");
        }

        double rtt = icmpAlive ? (preciseRtt ? outcome.RttMs : outcome.ApiRttMs) : 0;
        string detail = icmpAlive ? "" : "no ICMP reply (answers ARP only)";
        return new HostObservation(address, true, method, rtt, icmpAlive ? outcome.Ttl : 0, attempts, detail, mac);
    }

    /// <summary>
    /// Tries every forced port at once and returns the first one that proves the host is up (an open port, or a
    /// refusal). A port that stays silent is retried, since one dropped SYN would otherwise look like a firewall.
    /// </summary>
    private async Task<(int Port, TcpPingOutcome Result)?> TcpCheckAsync(IPAddress address, RateLimiter limiter, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var attempts = _settings.ForceScanPorts.Select(port => TryPortAsync(port, cts.Token)).ToList();

        while (attempts.Count > 0)
        {
            var done = await Task.WhenAny(attempts).ConfigureAwait(false);
            attempts.Remove(done);
            var result = await done.ConfigureAwait(false);
            if (result is { } hit)
            {
                await cts.CancelAsync().ConfigureAwait(false); // the rest are no longer needed
                return hit;
            }
        }
        return null;

        async Task<(int Port, TcpPingOutcome Result)?> TryPortAsync(int port, CancellationToken token)
        {
            try
            {
                for (int attempt = 0; attempt <= _settings.ConnectRetries; attempt++)
                {
                    await limiter.WaitAsync(token).ConfigureAwait(false);
                    var outcome = await _tcp!.PingAsync(address, port, _settings.TimeoutMs, token).ConfigureAwait(false);
                    if (outcome.ProvesHostIsUp) return (port, outcome);
                    if (outcome.Outcome != TcpPortOutcome.NoAnswer) return null; // unreachable: retrying will not help
                }
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                // another port already settled the question
            }
            return null;
        }
    }

    private async Task<string?> ResolveArpAsync(IPAddress address, RateLimiter limiter, CancellationToken ct)
    {
        try
        {
            await limiter.WaitAsync(ct).ConfigureAwait(false);
            return await _arp!.ResolveAsync(address, _settings.ArpTimeoutMs, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception)
        {
            // ARP is a bonus on top of ICMP; a failing resolver must not fail the host.
            return null;
        }
    }
}
