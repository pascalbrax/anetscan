using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;

namespace ANetworkScanner.Engine.Discovery;

public enum PingStatus
{
    /// <summary>The host itself answered the echo request.</summary>
    Success,
    /// <summary>No reply before the timeout.</summary>
    TimedOut,
    /// <summary>A router (or the host) answered "unreachable"/"TTL expired" - the host is NOT alive.</summary>
    Unreachable,
    /// <summary>The probe could not be sent (no route, no interface, ...).</summary>
    Error,
}

/// <param name="RttMs">Round trip measured around the call, fractional milliseconds.</param>
/// <param name="ApiRttMs">Round trip as reported by the Windows ICMP API itself: whole milliseconds (0 means under 1 ms).</param>
public readonly record struct PingOutcome(
    PingStatus Status, double RttMs = 0, int Ttl = 0, string Detail = "", long ApiRttMs = 0);

/// <summary>One ICMP echo. Abstracted so the pipeline can be tested without a network.</summary>
public interface IPinger
{
    Task<PingOutcome> PingAsync(IPAddress address, int timeoutMs, CancellationToken cancellationToken);
}

/// <summary>
/// ICMP echo through the OS (IcmpSendEcho2 under <see cref="Ping"/>): needs no administrator rights and
/// never parses console output, so it is language-independent. Only a genuine echo reply counts as alive;
/// "destination unreachable" replies from routers are reported as <see cref="PingStatus.Unreachable"/>.
/// </summary>
public sealed class SystemPinger : IPinger
{
    // Windows' own ping.exe payload, so firewalls that match on it behave the same.
    private static readonly byte[] Payload = "abcdefghijklmnopqrstuvwabcdefghi"u8.ToArray();

    public async Task<PingOutcome> PingAsync(IPAddress address, int timeoutMs, CancellationToken cancellationToken)
    {
        try
        {
            using var ping = new Ping();
            var started = Stopwatch.GetTimestamp();
            var reply = await ping.SendPingAsync(address, TimeSpan.FromMilliseconds(timeoutMs), Payload,
                new PingOptions(128, dontFragment: true), cancellationToken).ConfigureAwait(false);
            var elapsedMs = Stopwatch.GetElapsedTime(started).TotalMilliseconds;

            // A reply to a broadcast/anycast target (e.g. x.x.x.255) comes from some other device. It proves
            // nothing about the address we probed, so it must not be reported as a live host.
            if (reply.Status == IPStatus.Success && !reply.Address.Equals(address))
                return new PingOutcome(PingStatus.Unreachable, Detail: $"reply came from {reply.Address}");

            return reply.Status switch
            {
                IPStatus.Success => new PingOutcome(PingStatus.Success, elapsedMs, reply.Options?.Ttl ?? 0, ApiRttMs: reply.RoundtripTime),
                IPStatus.TimedOut => new PingOutcome(PingStatus.TimedOut),
                _ => new PingOutcome(PingStatus.Unreachable, Detail: reply.Status.ToString()),
            };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is PingException or InvalidOperationException or System.Net.Sockets.SocketException)
        {
            return new PingOutcome(PingStatus.Error, Detail: ex.InnerException?.Message ?? ex.Message);
        }
    }
}
