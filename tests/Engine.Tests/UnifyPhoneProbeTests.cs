using System.Net;
using System.Net.Sockets;
using System.Text;
using ANetworkScanner.Engine.Probes;
using Xunit;

namespace ANetworkScanner.Engine.Tests;

public class UnifyPhoneProbeTests
{
    // The header page of an OpenScape Desk Phone's web interface (readable without logging in), with invented values.
    private static string Banner(string deviceType, string ext, string dns) => $$"""
        HTTP/1.1 200 OK
        Content-Type: text/html; charset=utf-8
        Connection: close

        <!DOCTYPE HTML PUBLIC '-//W3C//DTD HTML 1.0 Strict//EN'>
        <html lang="de"><body>
          <table id='MB_Table'><tr><td>
              <p class='DeviceType'>
        {{deviceType}}
              </p>
          </td>
          <td><table id='MB_Table_Right' align='right'>
            <tr>
              <td align='right' class='Attribute'>
                  Phone number
              </td>
              <td align='left' class='Value'>
        {{ext}}
              </td>
            </tr>
            <tr>
              <td align='right' class='Attribute'>
                  DNS name
              </td>
              <td align='left' class='Value'>
        {{dns}}
              </td>
            </tr>
          </table></td></tr></table>
        </body>
        </html>
        """.Replace("\r\n", "\n").Replace("\n", "\r\n");

    private static ProbeDefinition Load(int port)
    {
        var json = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "probes", "unify-phone.json"))
            .Replace("{ \"port\": 443, \"tls\": true }", port.ToString()); // plain TCP on a loopback port
        var loaded = ProbeLoader.LoadFromJson(json, "unify-phone.json");
        Assert.True(loaded.Probes.Count == 1, string.Join("; ", loaded.Problems));
        return loaded.Probes[0];
    }

    private static async Task<(ProbeResult Result, string Request)> RunAgainst(string? reply)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        string request = "";
        _ = Task.Run(async () =>
        {
            try
            {
                using var client = await listener.AcceptTcpClientAsync();
                var stream = client.GetStream();
                var buffer = new byte[1024];
                int n = await stream.ReadAsync(buffer);
                request = Encoding.ASCII.GetString(buffer, 0, n);
                if (reply is not null) await stream.WriteAsync(Encoding.UTF8.GetBytes(reply));
            }
            catch { }
        });

        var result = await new ProbeRunner().RunAsync(Load(port), IPAddress.Loopback, CancellationToken.None);
        listener.Stop();
        return (result, request);
    }

    [Fact]
    public async Task ACp400_ShowsModelAndExtension()
    {
        var (result, request) = await RunAgainst(Banner("OpenScape Desk Phone CP400", "100", "100.example.lan"));

        Assert.Equal(PortState.Open, result.State);
        Assert.Equal("CP400 100", result.Short);
        Assert.Contains("Model     : CP400", result.Long);
        Assert.Contains("Extension : 100", result.Long);
        Assert.Contains("DNS name  : 100.example.lan", result.Long);
        Assert.StartsWith("GET /main_banner.cmd?lang=en HTTP/1.0\r\n", request);
    }

    [Fact]
    public async Task AnOlderOpenStage_KeepsItsFullName()
    {
        var (result, _) = await RunAgainst(Banner("OpenStage 40", "205", "205.example.lan"));
        Assert.Equal("OpenStage 40 205", result.Short);
    }

    [Fact]
    public async Task APhoneWithoutExtension_StillShowsTheModel()
    {
        var (result, _) = await RunAgainst("HTTP/1.1 200 OK\r\n\r\n<html><p class='DeviceType'>\r\nOpenScape Desk Phone CP200\r\n</p></html>");
        Assert.Equal("CP200", result.Short);
        Assert.DoesNotContain("Extension", result.Long);
    }

    [Fact]
    public async Task AnyOtherWebServer_IsNotReportedAsAPhone()
    {
        var (result, _) = await RunAgainst("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<html><title>Welcome</title></html>");
        Assert.Equal(PortState.Closed, result.State); // not an open service as far as this probe is concerned
        Assert.Equal("", result.Short);
    }
}
