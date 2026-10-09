using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using ANetworkScanner.Engine.Discovery;

namespace ANetworkScanner.Engine.Probes;

public enum PortState
{
    /// <summary>The port accepted the connection (TCP) or answered (UDP).</summary>
    Open,
    /// <summary>Actively refused (TCP reset) or ICMP port unreachable (UDP): the host is up, nothing listens.</summary>
    Closed,
    /// <summary>No answer at all - a firewall dropping packets, or (UDP) nothing listening.</summary>
    Filtered,
    /// <summary>Something unexpected happened; <see cref="PortResult.Long"/> says what.</summary>
    Error,
}

public sealed record PortResult(int Port, PortState State, string Short, string Long, ProbeLevel Level = ProbeLevel.Info);

/// <param name="State">The best state over all ports: Open, else Error, else Filtered, else Closed.</param>
/// <param name="Short">Text for the results grid cell; empty when no port is open.</param>
/// <param name="Long">Text for the details panel.</param>
/// <param name="Level">The most noteworthy level among the open ports.</param>
public sealed record ProbeResult(
    string ProbeId, string Title, PortState State, string Short, string Long, IReadOnlyList<PortResult> Ports,
    ProbeLevel Level = ProbeLevel.Info);

/// <summary>Executes a <see cref="ProbeDefinition"/> against one host.</summary>
public sealed class ProbeRunner(RateLimiter? limiter = null, int connectRetries = 1)
{
    private readonly int _connectRetries = Math.Clamp(connectRetries, 0, 3);
    private const int MaxResponseBytes = 64 * 1024;
    private readonly RateLimiter _limiter = limiter ?? new RateLimiter(0);

    public async Task<ProbeResult> RunAsync(ProbeDefinition probe, IPAddress address, CancellationToken ct)
    {
        var tasks = probe.Ports.Select(p => RunPortAsync(probe, address, p, ct)).ToArray();
        var ports = await Task.WhenAll(tasks).ConfigureAwait(false);
        return Aggregate(probe, ports);
    }

    private async Task<PortResult> RunPortAsync(ProbeDefinition probe, IPAddress address, PortSpec spec, CancellationToken ct)
    {
        try
        {
            await _limiter.WaitAsync(ct).ConfigureAwait(false);
            return probe.Transport == ProbeTransport.Tcp
                ? await RunTcpAsync(probe, address, spec, ct).ConfigureAwait(false)
                : await RunUdpAsync(probe, address, spec, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new PortResult(spec.Port, PortState.Filtered, "", "timed out");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new PortResult(spec.Port, PortState.Error, "ERR", ex.Message);
        }
    }

    // ── TCP ──────────────────────────────────────────────────────────────────

    private async Task<PortResult> RunTcpAsync(ProbeDefinition probe, IPAddress address, PortSpec spec, CancellationToken ct)
    {
        var (connected, early) = await ConnectAsync(probe, address, spec, ct).ConfigureAwait(false);
        if (connected is null) return early!;
        using var socket = connected;

        var vars = NewVars(address, spec.Port);
        Stream stream = new NetworkStream(socket, ownsSocket: false);
        try
        {
            if (spec.Tls)
            {
                var tls = await TryTlsAsync(stream, address, probe.ConnectTimeoutMs, vars, ct).ConfigureAwait(false);
                if (tls is null)
                    return BuildOpen(probe, spec, [], vars, note: "TLS handshake failed (the port is open but does not speak TLS)");
                stream = tls;
            }

            var response = new List<byte>();
            await RunStepsAsync(probe, stream, vars, response, ct).ConfigureAwait(false);
            return BuildOpen(probe, spec, [.. response], vars, note: null);
        }
        finally
        {
            await stream.DisposeAsync().ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Opens the TCP connection. Windows normally re-sends the SYN after a reset, so a closed port takes about
    /// two seconds to report "refused" and a firewalled one can hang for 21. The initial-RTO socket option turns
    /// that off: refusals arrive in milliseconds and silence is reported after exactly the connect timeout. Since a
    /// single dropped SYN would then look like a firewall, a timeout is retried before the port is called filtered.
    /// </summary>
    private async Task<(Socket? Socket, PortResult? Early)> ConnectAsync(
        ProbeDefinition probe, IPAddress address, PortSpec spec, CancellationToken ct)
    {
        for (int attempt = 0; ; attempt++)
        {
            if (attempt > 0) await _limiter.WaitAsync(ct).ConfigureAwait(false);

            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            DisableSynRetransmission(socket, probe.ConnectTimeoutMs);

            bool timedOut = false;
            try
            {
                // Our own timer is only a backstop; normally the OS reports TimedOut first.
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(probe.ConnectTimeoutMs + 750);
                await socket.ConnectAsync(address, spec.Port, cts.Token).ConfigureAwait(false);
                return (socket, null);
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
            {
                socket.Dispose();
                return (null, new PortResult(spec.Port, PortState.Closed, "", "closed"));
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
            {
                socket.Dispose();
                timedOut = true;
            }
            catch (SocketException ex) when (ex.SocketErrorCode is SocketError.HostUnreachable
                                                or SocketError.NetworkUnreachable or SocketError.HostDown)
            {
                socket.Dispose();
                return (null, new PortResult(spec.Port, PortState.Filtered, "", "filtered (unreachable)"));
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                socket.Dispose();
                timedOut = true;
            }
            catch
            {
                socket.Dispose();
                throw;
            }

            if (timedOut && attempt >= _connectRetries)
                return (null, new PortResult(spec.Port, PortState.Filtered, "", "filtered (no answer)"));
        }
    }

    // SIO_TCP_INITIAL_RTO = _WSAIOW(IOC_VENDOR, 17); TCP_INITIAL_RTO_PARAMETERS { USHORT Rtt; UCHAR MaxSynRetransmissions; }
    private const int SioTcpInitialRto = unchecked((int)0x98000011);
    private const byte NoSynRetransmissions = 0xFE;

    internal static void DisableSynRetransmission(Socket socket, int timeoutMs)
    {
        try
        {
            var parameters = new byte[4];
            BitConverter.GetBytes((ushort)Math.Clamp(timeoutMs, 100, 60_000)).CopyTo(parameters, 0);
            parameters[2] = NoSynRetransmissions;
            socket.IOControl((IOControlCode)SioTcpInitialRto, parameters, null);
        }
        catch (Exception ex) when (ex is SocketException or PlatformNotSupportedException or NotSupportedException)
        {
            // Older Windows or another OS: the default retransmission behaviour still works, only slower.
        }
    }

    private static async Task<SslStream?> TryTlsAsync(
        Stream inner, IPAddress address, int timeoutMs, Dictionary<string, string> vars, CancellationToken ct)
    {
        X509Certificate2? certificate = null;
        var ssl = new SslStream(inner, leaveInnerStreamOpen: true, (_, cert, _, _) =>
        {
            if (cert is not null) certificate = new X509Certificate2(cert);
            return true; // a scanner reports certificates, it does not judge them
        });

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(Math.Max(timeoutMs, 3000));
        try
        {
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = address.ToString(),
            }, cts.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is AuthenticationException or IOException or OperationCanceledException or SocketException)
        {
            ct.ThrowIfCancellationRequested();
            await ssl.DisposeAsync().ConfigureAwait(false);
            return null;
        }

        vars["tls_version"] = ssl.SslProtocol.ToString().Replace("Tls1", "TLS 1.").Replace("Tls", "TLS ");
        if (certificate is not null)
        {
            vars["cert_subject"] = certificate.Subject;
            vars["cert_cn"] = certificate.GetNameInfo(X509NameType.SimpleName, false);
            vars["cert_issuer"] = certificate.Issuer;
            vars["cert_expires"] = certificate.NotAfter.ToString("yyyy-MM-dd");
        }
        return ssl;
    }

    private static async Task RunStepsAsync(
        ProbeDefinition probe, Stream stream, Dictionary<string, string> vars, List<byte> response, CancellationToken ct)
    {
        foreach (var step in probe.Steps)
        {
            try
            {
                switch (step)
                {
                    case SendStep send:
                        var payload = BuildPayload(send, vars);
                        await stream.WriteAsync(payload, ct).ConfigureAwait(false);
                        await stream.FlushAsync(ct).ConfigureAwait(false);
                        break;
                    case ReadStep read:
                        await ReadAsync(stream, read, response, ct).ConfigureAwait(false);
                        break;
                }
            }
            catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
            {
                // The peer closed or reset the connection: keep whatever was received so far.
                return;
            }
        }
    }

    private static async Task ReadAsync(Stream stream, ReadStep read, List<byte> response, CancellationToken ct)
    {
        var buffer = new byte[Math.Min(read.MaxBytes, 8192)];
        int received = 0;
        int searchFrom = Math.Max(0, response.Count - (read.Until?.Length ?? 0));
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(read.TimeoutMs);

        while (received < read.MaxBytes && response.Count < MaxResponseBytes)
        {
            int n;
            try
            {
                n = await stream.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, read.MaxBytes - received)), cts.Token)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                return; // read timeout: use what we have
            }

            if (n == 0) return; // peer closed
            response.AddRange(buffer.AsSpan(0, n).ToArray());
            received += n;

            if (read.Until is null) return;
            if (IndexOf(response, read.Until, searchFrom) >= 0) return;
            searchFrom = Math.Max(0, response.Count - read.Until.Length);
        }
    }

    private static int IndexOf(List<byte> haystack, byte[] needle, int from)
    {
        for (int i = from; i + needle.Length <= haystack.Count; i++)
        {
            int j = 0;
            while (j < needle.Length && haystack[i + j] == needle[j]) j++;
            if (j == needle.Length) return i;
        }
        return -1;
    }

    // ── UDP ──────────────────────────────────────────────────────────────────

    private async Task<PortResult> RunUdpAsync(ProbeDefinition probe, IPAddress address, PortSpec spec, CancellationToken ct)
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        var vars = NewVars(address, spec.Port);
        var response = new List<byte>();
        var buffer = new byte[Math.Min(MaxResponseBytes, 8192)];

        try
        {
            await socket.ConnectAsync(address, spec.Port, ct).ConfigureAwait(false);

            foreach (var step in probe.Steps)
            {
                if (step is SendStep send)
                {
                    await socket.SendAsync(BuildPayload(send, vars), SocketFlags.None, ct).ConfigureAwait(false);
                }
                else if (step is ReadStep read)
                {
                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    cts.CancelAfter(read.TimeoutMs);
                    try
                    {
                        int n = await socket.ReceiveAsync(buffer.AsMemory(0, Math.Min(buffer.Length, read.MaxBytes)),
                            SocketFlags.None, cts.Token).ConfigureAwait(false);
                        response.AddRange(buffer.AsSpan(0, n).ToArray());
                    }
                    catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                    {
                        // no datagram within the timeout
                    }
                }
            }
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset)
        {
            // ICMP port unreachable surfaces as a reset on a connected UDP socket.
            return new PortResult(spec.Port, PortState.Closed, "", "closed (ICMP port unreachable)");
        }

        if (response.Count == 0)
            return new PortResult(spec.Port, PortState.Filtered, "", "no response (closed or filtered)");

        return BuildOpen(probe, spec, [.. response], vars, note: null);
    }

    // ── Results ──────────────────────────────────────────────────────────────

    private static PortResult BuildOpen(
        ProbeDefinition probe, PortSpec spec, byte[] response, Dictionary<string, string> vars, string? note)
    {
        var text = Encoding.Latin1.GetString(response);
        vars["bytes"] = response.Length.ToString();
        vars["banner"] = Banner(text);

        foreach (var extract in probe.Extract)
            CollectGroups(extract.Regex, text, vars, extract.UrlDecode);

        MatchRule? matched = null;
        foreach (var rule in probe.Match)
        {
            if (rule.Hex is not null ? rule.Hex.IsMatch(response) : TryRegex(rule.Regex!, text, vars))
            {
                matched = rule;
                break;
            }
        }

        string shortText = Template.Render(matched?.Short ?? probe.FallbackShort, vars);

        string? longTemplate = matched is not null ? matched.Long ?? probe.FallbackLong : probe.FallbackLong;
        var longBody = longTemplate is not null
            ? Template.Render(longTemplate, vars)
            : DefaultLong(vars, note);
        if (note is not null && longTemplate is not null) longBody += "\n" + note;

        var header = $"[{probe.Title} :{spec.Port}{(spec.Tls ? " TLS" : "")}]";
        var longText = header + "\n" + string.Join("\n", longBody.Split('\n').Select(l => "  " + l.TrimEnd('\r')));
        return new PortResult(spec.Port, PortState.Open, shortText, longText, matched?.Level ?? probe.FallbackLevel);
    }

    private static string DefaultLong(Dictionary<string, string> vars, string? note)
    {
        var lines = new List<string> { "Status : open" };
        if (vars.GetValueOrDefault("tls_version") is { Length: > 0 } tls) lines.Add($"TLS    : {tls}");
        if (vars.GetValueOrDefault("cert_subject") is { Length: > 0 } cert) lines.Add($"Cert   : {cert}");
        if (vars.GetValueOrDefault("banner") is { Length: > 0 } banner) lines.Add($"Banner : {banner}");
        if (note is not null) lines.Add($"Note   : {note}");
        return string.Join("\n", lines);
    }

    private static bool TryRegex(Regex regex, string text, Dictionary<string, string> vars)
    {
        try
        {
            var match = regex.Match(text);
            if (!match.Success) return false;
            AddGroups(regex, match, vars);
            return true;
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    private static void CollectGroups(Regex regex, string text, Dictionary<string, string> vars, bool urlDecode)
    {
        try
        {
            var match = regex.Match(text);
            if (match.Success) AddGroups(regex, match, vars, urlDecode);
        }
        catch (RegexMatchTimeoutException)
        {
            // A pathological pattern: ignore it rather than stall the scan.
        }
    }

    private static void AddGroups(Regex regex, Match match, Dictionary<string, string> vars, bool urlDecode = false)
    {
        foreach (var name in regex.GetGroupNames())
        {
            if (int.TryParse(name, out _)) continue; // numbered groups are not template variables
            var group = match.Groups[name];
            if (!group.Success) continue;
            var value = group.Value;
            if (urlDecode)
            {
                try { value = Uri.UnescapeDataString(value); }
                catch (UriFormatException) { /* keep the raw text */ }
            }
            vars[name] = Clean(value);
        }
    }

    /// <summary>First printable line of the response, so binary replies never garble the UI.</summary>
    private static string Banner(string text)
    {
        var line = text.Split('\n', 2)[0].Trim('\r', ' ', '\t');
        var sb = new StringBuilder();
        foreach (var c in line)
        {
            if (sb.Length >= 120) break;
            sb.Append(c is >= ' ' and <= '~' ? c : '.');
        }
        return sb.ToString();
    }

    private static string Clean(string value)
    {
        var sb = new StringBuilder(value.Length);
        foreach (var c in value.Trim())
            sb.Append(c is >= ' ' and <= '~' or > ' ' ? c : '.');
        return sb.Length > 200 ? sb.ToString(0, 200) : sb.ToString();
    }

    private static ProbeResult Aggregate(ProbeDefinition probe, PortResult[] ports)
    {
        var open = ports.Where(p => p.State == PortState.Open).OrderBy(p => p.Port).ToList();

        PortState state =
            open.Count > 0 ? PortState.Open :
            ports.Any(p => p.State == PortState.Error) ? PortState.Error :
            ports.Any(p => p.State == PortState.Filtered) ? PortState.Filtered : PortState.Closed;

        string shortText, longText;
        if (open.Count > 0)
        {
            shortText = open.Count == 1 && probe.Ports.Count == 1
                ? open[0].Short
                : string.Join(", ", open.Select(p => $"{p.Port}: {p.Short}"));
            longText = string.Join("\n", open.Select(p => p.Long));
        }
        else if (state == PortState.Error)
        {
            var error = ports.First(p => p.State == PortState.Error);
            shortText = error.Short;
            longText = $"[{probe.Title}]\n  {error.Long}";
        }
        else
        {
            shortText = "";
            var summary = string.Join(", ", ports.OrderBy(p => p.Port).Select(p => $"{p.Port} {p.Long}"));
            longText = $"[{probe.Title}]\n  {summary}";
        }

        var level = open.Count > 0 ? open.Max(p => p.Level) : ProbeLevel.Info;
        return new ProbeResult(probe.Id, probe.Title, state, shortText, longText, ports, level);
    }

    // ── Payloads and variables ───────────────────────────────────────────────

    private static Dictionary<string, string> NewVars(IPAddress address, int port) => new(StringComparer.OrdinalIgnoreCase)
    {
        ["ip"] = address.ToString(),
        ["port"] = port.ToString(),
        ["uuid"] = Guid.NewGuid().ToString(),
    };

    private static byte[] BuildPayload(SendStep step, Dictionary<string, string> vars)
    {
        using var ms = new MemoryStream();
        foreach (var part in step.Parts)
        {
            switch (part)
            {
                case TextPart t: ms.Write(Encoding.Latin1.GetBytes(t.Text)); break;
                case HexPart h: ms.Write(h.Bytes); break;
                case VarPart v: ms.Write(Encoding.Latin1.GetBytes(vars.GetValueOrDefault(v.Name, ""))); break;
            }
        }
        return ms.ToArray();
    }
}

