using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ANetworkScanner.Engine.Discovery;
using ANetworkScanner.Engine.Probes;
using Xunit;

namespace ANetworkScanner.Engine.Tests;

/// <summary>Runs probes against real sockets on the loopback interface.</summary>
public class ProbeRunnerTests
{
    private static readonly IPAddress Loopback = IPAddress.Loopback;

    private static ProbeDefinition Probe(string json)
    {
        var r = ProbeLoader.LoadFromJson(json, "test.json");
        Assert.True(r.Problems.Count == 0, string.Join(" | ", r.Problems));
        return Assert.Single(r.Probes);
    }

    /// <summary>Starts a one-shot TCP server; <paramref name="serve"/> handles each accepted connection.</summary>
    private static (int Port, TcpListener Listener) Serve(Func<NetworkStream, Task> serve)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        _ = Task.Run(async () =>
        {
            while (true)
            {
                TcpClient client;
                try { client = await listener.AcceptTcpClientAsync(); }
                catch { return; }
                _ = Task.Run(async () =>
                {
                    using (client)
                    {
                        try { await serve(client.GetStream()); }
                        catch (IOException) { }
                    }
                });
            }
        });
        return (((IPEndPoint)listener.LocalEndpoint).Port, listener);
    }

    private static async Task<byte[]> ReadSome(Stream s, int max = 1024)
    {
        var buf = new byte[max];
        int n = await s.ReadAsync(buf);
        return buf[..n];
    }

    private static Task<ProbeResult> Run(ProbeDefinition p) => new ProbeRunner().RunAsync(p, Loopback, CancellationToken.None);

    [Fact]
    public async Task Banner_IsMatchedAndTemplated()
    {
        var (port, listener) = Serve(async s => await s.WriteAsync("SSH-2.0-OpenSSH_9.6 Ubuntu\r\n"u8.ToArray()));
        using var _ = listener.Server;

        var result = await Run(Probe($$"""
            { "id": "ssh", "title": "SSH", "ports": [{{port}}],
              "steps": [ { "read": { "until": { "text": "\n" } } } ],
              "match": [ { "regex": "^SSH-(?<proto>[\\d.]+)-(?<sw>[^\\r\\n]+)", "short": "{sw}", "long": "Protocol {proto}\nSoftware {sw}" } ] }
            """));

        Assert.Equal(PortState.Open, result.State);
        Assert.Equal("OpenSSH_9.6 Ubuntu", result.Short);
        Assert.Contains($"[SSH :{port}]", result.Long);
        Assert.Contains("  Protocol 2.0", result.Long);
        Assert.Contains("  Software OpenSSH_9.6 Ubuntu", result.Long);
    }

    [Fact]
    public async Task ConnectedButNoMatch_UsesFallback()
    {
        var (port, listener) = Serve(s => s.WriteAsync("garbage"u8.ToArray()).AsTask());
        using var _ = listener.Server;

        var result = await Run(Probe($$"""
            { "id": "x", "ports": [{{port}}], "steps": [ { "read": {} } ],
              "match": [ { "regex": "^NOPE", "short": "nope" } ],
              "fallback": { "short": "open (unknown)" } }
            """));

        Assert.Equal(PortState.Open, result.State);
        Assert.Equal("open (unknown)", result.Short);
        Assert.Contains("Banner : garbage", result.Long);
    }

    [Fact]
    public async Task BinaryPayload_IsSentExactly_AndBinaryReplyIsMatched()
    {
        byte[] request = [0x03, 0x00, 0x00, 0x13, 0x0E, 0xE0, 0x00, 0xFF, 0x80, 0x00];
        byte[]? received = null;
        var (port, listener) = Serve(async s =>
        {
            received = await ReadSome(s);
            await s.WriteAsync(new byte[] { 0x03, 0x00, 0x00, 0x0B, 0x06, 0xD0, 0x00, 0x00, 0x12, 0x34, 0x00 });
        });
        using var _ = listener.Server;

        var result = await Run(Probe($$"""
            { "id": "bin", "title": "Bin", "ports": [{{port}}],
              "steps": [ { "send": { "hex": "03 00 00 13 0E E0 00 FF 80 00" } }, { "read": { "maxBytes": 64 } } ],
              "match": [ { "hex": "03 00 00 ?? ?? D0", "short": "binary hit", "long": "Got the confirm" } ] }
            """));

        Assert.Equal(request, received);
        Assert.Equal("binary hit", result.Short);
        Assert.Contains("Got the confirm", result.Long);
    }

    [Fact]
    public async Task MixedTextHexAndVariables_AreConcatenatedInOrder()
    {
        byte[]? received = null;
        var (port, listener) = Serve(async s =>
        {
            received = await ReadSome(s);
            await s.WriteAsync("ok"u8.ToArray());
        });
        using var _ = listener.Server;

        await Run(Probe($$"""
            { "id": "m", "ports": [{{port}}],
              "steps": [ { "send": [ { "text": "HOST " }, { "var": "ip" }, { "text": ":" }, { "var": "port" }, { "hex": "0D 0A 00 FF" } ] },
                         { "read": {} } ] }
            """));

        Assert.Equal(Encoding.Latin1.GetBytes($"HOST 127.0.0.1:{port}\r\n\0ÿ"), received);
    }

    [Fact]
    public async Task ReadUntil_CollectsAFragmentedReply()
    {
        var (port, listener) = Serve(async s =>
        {
            await s.WriteAsync("HTTP/1.0 200 OK\r\nServ"u8.ToArray());
            await Task.Delay(100);
            await s.WriteAsync("er: tiny/1.0\r\n\r\n"u8.ToArray());
        });
        using var _ = listener.Server;

        var result = await Run(Probe($$"""
            { "id": "h", "ports": [{{port}}],
              "steps": [ { "read": { "until": { "text": "\r\n\r\n" } } } ],
              "extract": [ { "regex": "(?im)^Server:[ \\t]*(?<server>[^\\r\\n]+)" } ],
              "match": [ { "regex": "^HTTP/\\d\\.\\d (?<code>\\d+)", "short": "{code} {server}" } ] }
            """));

        Assert.Equal("200 tiny/1.0", result.Short);
    }

    [Fact]
    public async Task SilentServer_ReadTimesOut_AndStillReportsOpen()
    {
        var (port, listener) = Serve(async s => await Task.Delay(1500));
        using var _ = listener.Server;

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var result = await Run(Probe($$"""
            { "id": "q", "ports": [{{port}}], "steps": [ { "read": { "timeoutMs": 200 } } ] }
            """));

        Assert.Equal(PortState.Open, result.State);
        Assert.Equal("open", result.Short);
        Assert.True(sw.ElapsedMilliseconds < 1200, $"took {sw.ElapsedMilliseconds} ms");
    }

    [Fact]
    public async Task ClosedPort_IsClosed_WithEmptyShort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();

        var result = await Run(Probe($$"""{ "id": "c", "ports": [{{port}}] }"""));

        Assert.Equal(PortState.Closed, result.State);
        Assert.Equal("", result.Short);
        Assert.Contains("closed", result.Long);
    }

    [Fact]
    public async Task ClosedPort_IsReportedInMilliseconds_NotAfterWindowsSynRetries()
    {
        // Without disabling SYN retransmission, Windows needs about 2 s to report a refused connection.
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var result = await Run(Probe($$"""{ "id": "c", "ports": [{{port}}], "connectTimeoutMs": 3000 }"""));

        Assert.Equal(PortState.Closed, result.State);
        Assert.True(sw.ElapsedMilliseconds < 500, $"refusal took {sw.ElapsedMilliseconds} ms");
    }

    [Fact]
    public async Task MultiplePorts_ReportEachOpenPort_WithPrefix()
    {
        var (open1, l1) = Serve(s => s.WriteAsync("A\n"u8.ToArray()).AsTask());
        var (open2, l2) = Serve(s => s.WriteAsync("B\n"u8.ToArray()).AsTask());
        var closed = new TcpListener(IPAddress.Loopback, 0);
        closed.Start();
        int closedPort = ((IPEndPoint)closed.LocalEndpoint).Port;
        closed.Stop();
        using var _1 = l1.Server;
        using var _2 = l2.Server;

        var result = await Run(Probe($$"""
            { "id": "mp", "ports": [{{open2}}, {{closedPort}}, {{open1}}], "steps": [ { "read": {} } ],
              "match": [ { "regex": "^(?<x>[AB])", "short": "svc {x}" } ] }
            """));

        var ordered = new[] { (open1, "A"), (open2, "B") }.OrderBy(t => t.Item1).Select(t => $"{t.Item1}: svc {t.Item2}");
        Assert.Equal(string.Join(", ", ordered), result.Short);
        Assert.Equal(3, result.Ports.Count);
        Assert.Equal(PortState.Closed, result.Ports.Single(p => p.Port == closedPort).State);
    }

    [Fact]
    public async Task Cancellation_IsPropagated()
    {
        var (port, listener) = Serve(async s => await Task.Delay(5000));
        using var _ = listener.Server;
        using var cts = new CancellationTokenSource(150);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new ProbeRunner().RunAsync(
            Probe($$"""{ "id": "z", "ports": [{{port}}], "steps": [ { "read": { "timeoutMs": 10000 } } ] }"""),
            Loopback, cts.Token));
    }

    // ── UDP ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Udp_Request_Reply_IsMatched()
    {
        using var server = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        int port = ((IPEndPoint)server.Client.LocalEndPoint!).Port;
        byte[]? received = null;
        _ = Task.Run(async () =>
        {
            var req = await server.ReceiveAsync();
            received = req.Buffer;
            await server.SendAsync(new byte[] { 0x30, 0x05, 0x02, 0x01, 0x00 }, req.RemoteEndPoint);
        });

        var result = await Run(Probe($$"""
            { "id": "u", "transport": "udp", "ports": [{{port}}],
              "steps": [ { "send": { "hex": "30 29 02 01 00" } }, { "read": { "timeoutMs": 1000 } } ],
              "match": [ { "hex": "30", "short": "answers" } ] }
            """));

        Assert.Equal([0x30, 0x29, 0x02, 0x01, 0x00], received);
        Assert.Equal(PortState.Open, result.State);
        Assert.Equal("answers", result.Short);
    }

    [Fact]
    public async Task Udp_NoAnswer_IsFiltered()
    {
        using var silent = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        int port = ((IPEndPoint)silent.Client.LocalEndPoint!).Port;

        var result = await Run(Probe($$"""
            { "id": "u", "transport": "udp", "ports": [{{port}}],
              "steps": [ { "send": "x" }, { "read": { "timeoutMs": 200 } } ] }
            """));

        Assert.Equal(PortState.Filtered, result.State);
        Assert.Equal("", result.Short);
    }

    [Fact]
    public async Task Udp_ClosedPort_IsClosed()
    {
        int port;
        using (var temp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)))
            port = ((IPEndPoint)temp.Client.LocalEndPoint!).Port;

        var result = await Run(Probe($$"""
            { "id": "u", "transport": "udp", "ports": [{{port}}],
              "steps": [ { "send": "x" }, { "read": { "timeoutMs": 1000 } } ] }
            """));

        Assert.Equal(PortState.Closed, result.State);
    }

    // ── TLS ──────────────────────────────────────────────────────────────────

    private static X509Certificate2 SelfSigned(string cn)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest($"CN={cn}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        return X509CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pfx), null);
    }

    [Fact]
    public async Task Tls_ReportsVersionAndCertificate_AndTalksThroughTheTunnel()
    {
        using var cert = SelfSigned("scanner-test.local");
        var (port, listener) = Serve(async raw =>
        {
            using var ssl = new SslStream(raw);
            await ssl.AuthenticateAsServerAsync(cert);
            await ReadSome(ssl);
            await ssl.WriteAsync("HTTP/1.0 204 No Content\r\nServer: tls-test\r\n\r\n"u8.ToArray());
        });
        using var _ = listener.Server;

        var result = await Run(Probe($$"""
            { "id": "https", "title": "HTTPS", "ports": [ { "port": {{port}}, "tls": true } ],
              "steps": [ { "send": "HEAD / HTTP/1.0\r\n\r\n" }, { "read": { "until": { "text": "\r\n\r\n" } } } ],
              "extract": [ { "regex": "(?im)^Server:[ \\t]*(?<server>[^\\r\\n]+)" } ],
              "match": [ { "regex": "^HTTP/\\d\\.\\d (?<code>\\d+)", "short": "{code} {server}",
                           "long": "TLS  : {tls_version}\nCert : {cert_cn} (expires {cert_expires})" } ] }
            """));

        Assert.Equal(PortState.Open, result.State);
        Assert.Equal("204 tls-test", result.Short);
        Assert.Contains("TLS ", result.Long);
        Assert.Contains("Cert : scanner-test.local", result.Long);
        Assert.Contains($"[HTTPS :{port} TLS]", result.Long);
    }

    [Fact]
    public async Task Tls_PortThatDoesNotSpeakTls_IsOpenWithANote()
    {
        var (port, listener) = Serve(async s =>
        {
            await s.WriteAsync("HTTP/1.0 200 OK\r\n\r\n"u8.ToArray());
            await Task.Delay(300);
        });
        using var _ = listener.Server;

        var result = await Run(Probe($$"""
            { "id": "https", "ports": [ { "port": {{port}}, "tls": true } ], "steps": [ { "read": {} } ] }
            """));

        Assert.Equal(PortState.Open, result.State);
        Assert.Contains("TLS handshake failed", result.Long);
    }
}
