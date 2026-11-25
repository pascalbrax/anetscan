using System.Net;
using System.Net.Sockets;
using ANetworkScanner.Engine.Probes;
using Xunit;

namespace ANetworkScanner.Engine.Tests;

public class UbiquitiProbeTests
{
    private static byte[] Tlv(byte type, byte[] value) => [type, 0, (byte)value.Length, .. value];
    private static byte[] Tlv(byte type, string text) => Tlv(type, System.Text.Encoding.Latin1.GetBytes(text));

    /// <summary>A discovery answer shaped like a real airMAX radio's, with invented values.</summary>
    private static byte[] Answer(string model = "NanoStation 5AC", string code = "NS-5ACL", string name = "Roof-Link", string essid = "backhaul", string fw = "XC.qca955x.v8.7.22.48486.260227.1957")
    {
        byte[] mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        byte[] body =
        [
            .. Tlv(0x01, mac),
            .. Tlv(0x02, [.. mac, 10, 1, 2, 3]),
            .. Tlv(0x03, fw),
            .. Tlv(0x0a, [0, 4, 0x91, 0x0d]),
            .. Tlv(0x0b, name),
            .. Tlv(0x0c, code),
            .. Tlv(0x0d, essid),
            .. Tlv(0x0e, [2]),
            .. Tlv(0x13, mac),
            .. Tlv(0x14, model),
        ];
        return [1, 0, (byte)(body.Length >> 8), (byte)body.Length, .. body];
    }

    private static ProbeDefinition Load(int port)
    {
        var json = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "probes", "ubiquiti.json"))
            .Replace("\"ports\": [10001]", $"\"ports\": [{port}]");
        var loaded = ProbeLoader.LoadFromJson(json, "ubiquiti.json");
        Assert.True(loaded.Probes.Count == 1, string.Join("; ", loaded.Problems));
        return loaded.Probes[0];
    }

    private static async Task<(ProbeResult Result, byte[] Request)> RunAgainst(byte[]? reply)
    {
        using var server = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        int port = ((IPEndPoint)server.Client.LocalEndPoint!).Port;
        byte[] request = [];
        _ = Task.Run(async () =>
        {
            try
            {
                var received = await server.ReceiveAsync();
                request = received.Buffer;
                if (reply is not null) await server.SendAsync(reply, received.RemoteEndPoint);
            }
            catch { }
        });

        var result = await new ProbeRunner().RunAsync(Load(port), IPAddress.Loopback, CancellationToken.None);
        return (result, request);
    }

    [Fact]
    public async Task ARadio_ShowsModelFirmwareAndName()
    {
        var (result, request) = await RunAgainst(Answer());

        Assert.Equal(PortState.Open, result.State);
        Assert.Equal("NanoStation 5AC", result.Short);
        Assert.Contains("Model    : NanoStation 5AC", result.Long);
        Assert.Contains("Code     : NS-5ACL", result.Long);
        Assert.Contains("Name     : Roof-Link", result.Long);
        Assert.Contains("SSID     : backhaul", result.Long);
        Assert.Contains("Firmware : XC.qca955x.v8.7.22.48486.260227.1957", result.Long);
        Assert.Equal(new byte[] { 1, 0, 0, 0 }, request);
    }

    [Fact]
    public async Task WithoutTheFullModel_TheShortCodeIsShown()
    {
        byte[] body = [.. Tlv(0x01, new byte[6]), .. Tlv(0x0c, "UAP-AC-Pro")];
        byte[] reply = [1, 0, 0, (byte)body.Length, .. body];

        var (result, _) = await RunAgainst(reply);
        Assert.Equal("UAP-AC-Pro", result.Short);
    }

    [Fact]
    public async Task AnyOtherServiceOnThatPort_IsNotReported()
    {
        var (result, _) = await RunAgainst("hello"u8.ToArray());
        Assert.Equal(PortState.Closed, result.State);
        Assert.Equal("", result.Short);
    }

    [Fact]
    public async Task Silence_IsNotAnAnswer()
    {
        var (result, _) = await RunAgainst(null);
        Assert.Equal("", result.Short);
    }
}
