using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using ANetworkScanner.Engine.Probes;
using Xunit;

namespace ANetworkScanner.Engine.Tests;

public class SipProbeTests
{
    private const string PhoneReply =
        "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP scanner.invalid:5060;rport=5060;branch=z9hG4bKx\r\n" +
        "From: <sip:scan@scanner.invalid>;tag=anetscan\r\nTo: <sip:10.0.0.9>;tag=abc\r\nCall-ID: x@scanner.invalid\r\nCSeq: 1 OPTIONS\r\n" +
        "Allow: INVITE, ACK, CANCEL, BYE, OPTIONS, NOTIFY, REFER\r\nUser-Agent: OpenScape Desk Phone CP400 SIP V1 R2.1.0\r\nContent-Length: 0\r\n\r\n";

    private static ProbeDefinition Sip(int port)
    {
        var loaded = ProbeLoader.LoadFromJson(
            File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "probes", "sip.json")).Replace("\"ports\": [5060]", $"\"ports\": [{port}]"),
            "sip.json");
        Assert.True(loaded.Probes.Count == 1, string.Join("; ", loaded.Problems));
        return loaded.Probes[0];
    }

    private static async Task<(ProbeResult Result, string Request)> RunAgainst(string? reply)
    {
        using var server = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        int port = ((IPEndPoint)server.Client.LocalEndPoint!).Port;
        string request = "";
        _ = Task.Run(async () =>
        {
            try
            {
                var received = await server.ReceiveAsync();
                request = Encoding.ASCII.GetString(received.Buffer);
                if (reply is not null) await server.SendAsync(Encoding.ASCII.GetBytes(reply), received.RemoteEndPoint);
            }
            catch { }
        });

        var result = await new ProbeRunner().RunAsync(Sip(port), IPAddress.Loopback, CancellationToken.None);
        return (result, request);
    }

    [Fact]
    public async Task APhone_ShowsItsUserAgent()
    {
        var (result, _) = await RunAgainst(PhoneReply);

        Assert.Equal(PortState.Open, result.State);
        Assert.Equal("OpenScape Desk Phone CP400 SIP V1 R2.1.0", result.Short);
        Assert.Contains("Status : answers SIP (200 OK)", result.Long);
        Assert.Contains("Agent  : OpenScape Desk Phone CP400 SIP V1 R2.1.0", result.Long);
        Assert.Contains("Allow  : INVITE, ACK", result.Long);
        Assert.DoesNotContain("Server :", result.Long); // no Server header: the line is dropped
    }

    [Fact]
    public async Task AProxy_ShowsItsServerHeader()
    {
        var (result, _) = await RunAgainst("SIP/2.0 200 OK\r\nServer: OpenScape Voice V10\r\nContent-Length: 0\r\n\r\n");
        Assert.Equal("OpenScape Voice V10", result.Short);
    }

    [Fact]
    public async Task ASipReplyWithoutNames_IsJustSip()
    {
        var (result, _) = await RunAgainst("SIP/2.0 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n");
        Assert.Equal("SIP", result.Short);
        Assert.Contains("(405 Method Not Allowed)", result.Long);
    }

    [Fact]
    public async Task SomethingElseOnTheSipPort_IsOpenButNotSip()
    {
        var (result, _) = await RunAgainst("hello");
        Assert.Equal("open", result.Short);
    }

    [Fact]
    public async Task SilenceIsNotAnAnswer()
    {
        var (result, _) = await RunAgainst(null);
        Assert.Equal("", result.Short);
    }

    [Fact]
    public async Task TheRequest_IsAWellFormedOptions_WithAFreshBranchAndCallId()
    {
        var (_, first) = await RunAgainst(PhoneReply);
        var (_, second) = await RunAgainst(PhoneReply);

        Assert.StartsWith("OPTIONS sip:127.0.0.1 SIP/2.0\r\n", first);
        Assert.Contains("\r\nTo: <sip:127.0.0.1>\r\n", first);
        Assert.Contains("\r\nCSeq: 1 OPTIONS\r\n", first);
        Assert.EndsWith("Content-Length: 0\r\n\r\n", first);

        var b1 = Regex.Match(first, "branch=z9hG4bK(?<id>[0-9a-f-]{36})").Groups["id"].Value;
        var b2 = Regex.Match(second, "branch=z9hG4bK(?<id>[0-9a-f-]{36})").Groups["id"].Value;
        Assert.True(Guid.TryParse(b1, out _), first);
        Assert.NotEqual(b1, b2);
        Assert.Contains($"Call-ID: {b1}@scanner.invalid", first);
    }
}
