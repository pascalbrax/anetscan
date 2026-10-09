using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using ANetworkScanner.Engine.Probes;

namespace ANetworkScanner.Engine.Discovery;

public enum TcpPortOutcome
{
    /// <summary>The connection was accepted: a service is listening.</summary>
    Open,
    /// <summary>The host answered with a reset: nothing listens on that port, but the host is certainly there.</summary>
    Refused,
    /// <summary>No answer: the packet was dropped (firewall), or nobody is there.</summary>
    NoAnswer,
    /// <summary>A router said the destination cannot be reached.</summary>
    Unreachable,
}

public readonly record struct TcpPingOutcome(TcpPortOutcome Outcome, double RttMs = 0)
{
    /// <summary>Open and refused both prove a live host; silence proves nothing.</summary>
    public bool ProvesHostIsUp => Outcome is TcpPortOutcome.Open or TcpPortOutcome.Refused;
}

/// <summary>One TCP connection attempt used as a "ping". Abstracted so the pipeline can be tested without a network.</summary>
public interface ITcpPinger
{
    Task<TcpPingOutcome> PingAsync(IPAddress address, int port, int timeoutMs, CancellationToken cancellationToken);
}

/// <summary>A plain connect, with Windows' SYN retransmission turned off so the outcome arrives in milliseconds.</summary>
public sealed class SystemTcpPinger : ITcpPinger
{
    public async Task<TcpPingOutcome> PingAsync(IPAddress address, int port, int timeoutMs, CancellationToken cancellationToken)
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        ProbeRunner.DisableSynRetransmission(socket, timeoutMs);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeoutMs + 750); // backstop; normally the OS reports the timeout first
        var started = Stopwatch.GetTimestamp();

        try
        {
            await socket.ConnectAsync(address, port, cts.Token).ConfigureAwait(false);
            return new TcpPingOutcome(TcpPortOutcome.Open, Stopwatch.GetElapsedTime(started).TotalMilliseconds);
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
        {
            return new TcpPingOutcome(TcpPortOutcome.Refused, Stopwatch.GetElapsedTime(started).TotalMilliseconds);
        }
        catch (SocketException ex) when (ex.SocketErrorCode is SocketError.HostUnreachable or SocketError.NetworkUnreachable or SocketError.HostDown)
        {
            return new TcpPingOutcome(TcpPortOutcome.Unreachable);
        }
        catch (SocketException)
        {
            return new TcpPingOutcome(TcpPortOutcome.NoAnswer);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new TcpPingOutcome(TcpPortOutcome.NoAnswer);
        }
    }
}
