using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using ANetworkScanner.Engine;
using ANetworkScanner.Engine.Probes;
using Xunit;

namespace ANetworkScanner.Engine.Tests;

public class OnvifProbeTests
{
    private const string Camera = """
        <?xml version="1.0" encoding="UTF-8"?>
        <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:dn="http://www.onvif.org/ver10/network/wsdl"><SOAP-ENV:Header><wsa:MessageID>uuid:11111111-2222-3333-4444-555555555555</wsa:MessageID><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</wsa:Action></SOAP-ENV:Header><SOAP-ENV:Body><d:ProbeMatches><d:ProbeMatch><wsa:EndpointReference><wsa:Address>urn:uuid:aaaa</wsa:Address></wsa:EndpointReference><d:Types>dn:NetworkVideoTransmitter</d:Types><d:Scopes>onvif://www.onvif.org/type/video_encoder onvif://www.onvif.org/name/Front%20Door onvif://www.onvif.org/hardware/DS-2CD2143G0-I onvif://www.onvif.org/location/country/switzerland onvif://www.onvif.org/manufacturer/Hikvision</d:Scopes><d:XAddrs>http://10.0.0.77/onvif/device_service http://[fe80::1]/onvif/device_service</d:XAddrs><d:MetadataVersion>10</d:MetadataVersion></d:ProbeMatch></d:ProbeMatches></SOAP-ENV:Body></SOAP-ENV:Envelope>
        """;

    private static string OnvifJson(int port) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "probes", "onvif.json")).Replace("\"ports\": [3702]", $"\"ports\": [{port}]");

    private static ProbeDefinition Load(string json) => Assert.Single(ProbeLoader.LoadFromJson(json, "onvif.json").Probes);

    /// <summary>A UDP "camera" that answers every datagram with <paramref name="reply"/> (or stays silent when null).</summary>
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
                request = Encoding.UTF8.GetString(received.Buffer);
                if (reply is not null) await server.SendAsync(Encoding.UTF8.GetBytes(reply), received.RemoteEndPoint);
            }
            catch { }
        });

        var result = await new ProbeRunner().RunAsync(Load(OnvifJson(port)), IPAddress.Loopback, CancellationToken.None);
        return (result, request);
    }

    [Fact]
    public async Task Camera_ShowsItsModel_AndDecodedDetails()
    {
        var (result, _) = await RunAgainst(Camera);

        Assert.Equal(PortState.Open, result.State);
        Assert.Equal("DS-2CD2143G0-I", result.Short);
        Assert.Contains("Name     : Front Door", result.Long);        // %20 decoded
        Assert.Contains("Maker    : Hikvision", result.Long);
        Assert.Contains("Location : country/switzerland", result.Long);
        Assert.Contains("Service  : http://10.0.0.77/onvif/device_service", result.Long); // the first XAddr, not a namespace URL
        Assert.Contains("Types    : dn:NetworkVideoTransmitter", result.Long);
        Assert.DoesNotContain("w3.org", result.Long);
    }

    [Fact]
    public async Task TheProbeSent_IsAWsDiscoveryProbe_WithAFreshMessageId()
    {
        var (_, first) = await RunAgainst(Camera);
        var (_, second) = await RunAgainst(Camera);

        Assert.Contains("<d:Types>dn:NetworkVideoTransmitter</d:Types>", first);
        Assert.Contains("discovery/Probe</w:Action>", first);
        var id1 = Regex.Match(first, @"<w:MessageID>uuid:(?<id>[0-9a-f-]{36})</w:MessageID>").Groups["id"].Value;
        var id2 = Regex.Match(second, @"<w:MessageID>uuid:(?<id>[0-9a-f-]{36})</w:MessageID>").Groups["id"].Value;
        Assert.True(Guid.TryParse(id1, out _), first);
        Assert.NotEqual(id1, id2);
    }

    [Fact]
    public async Task WithoutAModel_TheNameThenTheMakerThenJustOnvifIsShown()
    {
        string Reply(string scopes) => $"<d:ProbeMatches xmlns:d=\"x\"><d:Types>dn:NetworkVideoTransmitter</d:Types><d:Scopes>{scopes}</d:Scopes></d:ProbeMatches>";

        Assert.Equal("Lobby", (await RunAgainst(Reply("onvif://www.onvif.org/name/Lobby onvif://www.onvif.org/manufacturer/Axis"))).Result.Short);
        Assert.Equal("Axis", (await RunAgainst(Reply("onvif://www.onvif.org/manufacturer/Axis"))).Result.Short);
        Assert.Equal("ONVIF", (await RunAgainst(Reply("onvif://www.onvif.org/type/video_encoder"))).Result.Short);
    }

    [Fact]
    public async Task ATotallyDifferentReply_IsOpenButNotOnvif()
    {
        var (result, _) = await RunAgainst("this is not a SOAP message");
        Assert.Equal(PortState.Open, result.State);
        Assert.Equal("open", result.Short);
        Assert.Contains("not an ONVIF response", result.Long);
    }

    [Fact]
    public async Task NoAnswer_MeansNoOnvifDevice()
    {
        var (result, _) = await RunAgainst(null);
        Assert.NotEqual(PortState.Open, result.State);
        Assert.Equal("", result.Short);
    }

    // ── The format features the conversion needed ────────────────────────────

    private static readonly Dictionary<string, string> Vars = new() { ["model"] = "", ["devname"] = "Lobby", ["maker"] = "Axis" };

    [Theory]
    [InlineData("{model|devname|maker}", "Lobby")]
    [InlineData("{model|maker}", "Axis")]
    [InlineData("{model|missing|\"ONVIF\"}", "ONVIF")]
    [InlineData("{ model | devname }", "Lobby")]
    [InlineData("[{model|\"-\"}]", "[-]")]
    public void Template_FallbackChains_PickTheFirstNonEmptyPart(string template, string expected) =>
        Assert.Equal(expected, Template.Render(template, Vars));

    [Fact]
    public void Template_ALineWhoseChainIsEmpty_IsDropped() =>
        Assert.Equal("kept", Template.Render("Model : {model|missing}\nkept", Vars));

    [Fact]
    public void Loader_AcceptsTheUuidVariable_AndUrlDecodeExtracts()
    {
        var r = ProbeLoader.LoadFromJson("""
            { "id": "t", "ports": [1], "transport": "udp",
              "steps": [ { "send": [ { "text": "id=" }, { "var": "uuid" } ] } ],
              "extract": [ { "regex": "name/(?<n>\\S+)", "decode": "url" } ] }
            """, "t.json");
        Assert.Empty(r.Problems);
        Assert.True(r.Probes[0].Extract[0].UrlDecode);
    }

    [Fact]
    public void Loader_RejectsUnknownDecoders()
    {
        var r = ProbeLoader.LoadFromJson("""{ "id": "t", "ports": [1], "extract": [ { "regex": "(?<n>x)", "decode": "rot13" } ] }""", "t.json");
        Assert.Empty(r.Probes);
        Assert.Contains("decode", r.Problems[0].Message);
    }

    [Fact]
    public void ShippedOnvifProbe_LoadsCleanly_AndIsDescribed()
    {
        var probe = Load(OnvifJson(3702));
        Assert.Equal(ProbeTransport.Udp, probe.Transport);
        Assert.Equal(3702, probe.Ports[0].Port);
        Assert.Equal("UDP 3702", ProbeDescriber.PortsSummary(probe));
        Assert.Contains(ProbeDescriber.DescribeSteps(probe), l => l.Contains("{uuid}"));
    }

    [Fact]
    public void AnOnvifDevice_IsACamera() =>
        Assert.Equal(DeviceKind.Camera, DeviceClassifier.Classify(new DeviceEvidence(64, null,
            [new ServiceEvidence("onvif", [3702], "DS-2CD2143G0-I", "")])).Kind);
}
