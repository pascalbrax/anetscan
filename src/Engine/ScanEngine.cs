using System.Net;
using System.Runtime.CompilerServices;
using System.Threading.Channels;
using ANetworkScanner.Engine.Discovery;
using ANetworkScanner.Engine.Names;
using ANetworkScanner.Engine.Probes;
using ANetworkScanner.Engine.Settings;
using ANetworkScanner.Engine.Targets;

namespace ANetworkScanner.Engine;

public abstract record ScanEvent;

/// <summary>Discovery finished for one target (alive or not). Emitted for every target, in completion order.</summary>
public sealed record HostScanned(HostObservation Host) : ScanEvent;

/// <summary>One probe finished for one live host.</summary>
public sealed record ProbeCompleted(IPAddress Address, ProbeResult Result) : ScanEvent;

/// <summary>Name lookup finished for a live host. <see cref="Name"/> is null when no source knew one.</summary>
public sealed record NameResolved(IPAddress Address, HostName? Name) : ScanEvent;

/// <summary>
/// The whole scan: discovery, then the enabled probes for every host the moment it is found - the two
/// phases overlap. One <see cref="RateLimiter"/> budget covers every packet the scan sends, and a semaphore
/// bounds how many probe connections are open at once.
/// </summary>
public sealed class ScanEngine
{
    private readonly IPinger _pinger;
    private readonly DiscoverySettings _settings;
    private readonly LocalSubnets _subnets;
    private readonly IArpResolver? _arp;
    private readonly IHostNameResolver? _names;
    private readonly ITcpPinger? _tcp;

    /// <param name="names">Only used when <see cref="DiscoverySettings.ResolveNames"/> is on; defaults to DNS, mDNS and NetBIOS.</param>
    public ScanEngine(IPinger pinger, DiscoverySettings settings, LocalSubnets? subnets = null, IArpResolver? arp = null,
        IHostNameResolver? names = null, ITcpPinger? tcp = null)
    {
        _tcp = tcp;
        _pinger = pinger;
        _settings = settings.Normalized();
        _subnets = subnets ?? LocalSubnets.None;
        _arp = arp;
        _names = _settings.ResolveNames ? names ?? HostNameResolver.CreateDefault(_settings.NameTimeoutMs) : null;
    }

    public async IAsyncEnumerable<ScanEvent> RunAsync(
        TargetSet targets,
        IReadOnlyList<ProbeDefinition> probes,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var events = Channel.CreateBounded<ScanEvent>(new BoundedChannelOptions(4096)
        {
            SingleReader = true,
            FullMode = BoundedChannelFullMode.Wait,
        });

        var pump = PumpAsync(targets, probes, events.Writer, cts.Token);

        try
        {
            await foreach (var e in events.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
                yield return e;
        }
        finally
        {
            await cts.CancelAsync().ConfigureAwait(false);
            try { await pump.ConfigureAwait(false); } catch (OperationCanceledException) { }
        }
    }

    private async Task PumpAsync(
        TargetSet targets, IReadOnlyList<ProbeDefinition> probes, ChannelWriter<ScanEvent> writer, CancellationToken ct)
    {
        var limiter = RateLimiter.FromSettings(_settings);
        var discovery = new DiscoveryEngine(_pinger, _settings, _subnets, _arp, limiter, _tcp);
        var runner = new ProbeRunner(limiter, _settings.ConnectRetries);
        using var slots = new SemaphoreSlim(_settings.MaxConcurrentProbes, _settings.MaxConcurrentProbes);
        using var nameSlots = new SemaphoreSlim(64, 64);
        var pending = new List<Task>();

        try
        {
            await foreach (var host in discovery.RunAsync(targets, ct).ConfigureAwait(false))
            {
                await writer.WriteAsync(new HostScanned(host), ct).ConfigureAwait(false);
                if (!host.IsAlive) continue;

                if (_names is not null)
                {
                    pending.RemoveAll(t => t.IsCompleted);
                    pending.Add(ResolveNameAsync(_names, host.Address, limiter, nameSlots, writer, ct));
                }

                foreach (var probe in probes)
                {
                    pending.RemoveAll(t => t.IsCompleted);
                    pending.Add(RunProbeAsync(runner, probe, host.Address, slots, writer, ct));
                }
            }

            await Task.WhenAll(pending).ConfigureAwait(false);
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
    }

    /// <summary>Three sources, three small packets: each costs one token of the shared rate budget.</summary>
    private static async Task ResolveNameAsync(
        IHostNameResolver resolver, IPAddress address, RateLimiter limiter,
        SemaphoreSlim slots, ChannelWriter<ScanEvent> writer, CancellationToken ct)
    {
        try
        {
            await slots.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                for (int i = 0; i < 3; i++) await limiter.WaitAsync(ct).ConfigureAwait(false);
                var name = await resolver.ResolveAsync(address, ct).ConfigureAwait(false);
                await writer.WriteAsync(new NameResolved(address, name), ct).ConfigureAwait(false);
            }
            finally
            {
                slots.Release();
            }
        }
        catch (OperationCanceledException)
        {
            // Scan stopped.
        }
    }

    private static async Task RunProbeAsync(
        ProbeRunner runner, ProbeDefinition probe, IPAddress address,
        SemaphoreSlim slots, ChannelWriter<ScanEvent> writer, CancellationToken ct)
    {
        try
        {
            await slots.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                var result = await runner.RunAsync(probe, address, ct).ConfigureAwait(false);
                await writer.WriteAsync(new ProbeCompleted(address, result), ct).ConfigureAwait(false);
            }
            finally
            {
                slots.Release();
            }
        }
        catch (OperationCanceledException)
        {
            // Scan stopped.
        }
    }
}
