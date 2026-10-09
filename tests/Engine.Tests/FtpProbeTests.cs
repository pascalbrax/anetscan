using System.Net;
using System.Net.Sockets;
using System.Text;
using ANetworkScanner.Engine.Probes;
using Xunit;

namespace ANetworkScanner.Engine.Tests;

/// <summary>The FTP probe must behave like the Python ftp_server_check plugin it replaces (read_banner mode).</summary>
public class FtpProbeTests
{
    private static ProbeDefinition Ftp(int port) =>
        Assert.Single(ProbeLoader.LoadFromJson(
            File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "probes", "ftp.json")).Replace("\"ports\": [21]", $"\"ports\": [{port}]"),
            "ftp.json").Probes);

    /// <summary>A server that sends <paramref name="greeting"/> (or nothing) and records anything the client sends.</summary>
    private static async Task<(ProbeResult Result, string ReceivedFromClient)> RunAgainst(string? greeting)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var received = new StringBuilder();

        _ = Task.Run(async () =>
        {
            try
            {
                using var client = await listener.AcceptTcpClientAsync();
                var stream = client.GetStream();
                if (greeting is not null) await stream.WriteAsync(Encoding.ASCII.GetBytes(greeting));

                var buffer = new byte[256];
                int n = await stream.ReadAsync(buffer); // returns 0 when the probe hangs up
                received.Append(Encoding.ASCII.GetString(buffer, 0, n));
            }
            catch { }
        });

        var result = await new ProbeRunner().RunAsync(Ftp(port), IPAddress.Loopback, CancellationToken.None);
        listener.Stop();
        await Task.Delay(100);
        return (result, received.ToString());
    }

    [Fact]
    public async Task A220Greeting_IsFtp_AndShowsTheSoftware()
    {
        var (result, _) = await RunAgainst("220 ProFTPD 1.3.7a Server (Debian) [::ffff:10.0.0.5]\r\n");

        Assert.Equal(PortState.Open, result.State);
        Assert.Equal("ProFTPD 1.3.7", result.Short);
        Assert.Contains("Status : open", result.Long);
        Assert.Contains("Check  : banner read", result.Long);
        Assert.Contains("Banner : 220 ProFTPD 1.3.7a Server (Debian)", result.Long);
    }

    [Fact]
    public async Task AnUnrecognisedFtpGreeting_ShowsFtpOpen_LikeTheOriginalPlugin()
    {
        var (result, _) = await RunAgainst("220 Welcome to the Acme file drop\r\n");

        Assert.Equal("FTP open", result.Short);
        Assert.Contains("Banner : 220 Welcome to the Acme file drop", result.Long);
        Assert.DoesNotContain("Server :", result.Long); // no software recognised: the line is dropped
    }

    [Theory]
    [InlineData("Pure-FTPd [privsep] [TLS]\r\n", "Pure-FTPd")]
    [InlineData("200 some ftp daemon ready\r\n", "FTP open")]       // no 220, but "FTP" in the banner counts
    [InlineData("ftp server here\r\n", "FTP open")]                  // case-insensitive
    [InlineData("220 Microsoft FTP Service\r\n", "Microsoft FTP Service")]
    [InlineData("220 (vsFTPd 3.0.3)\r\n", "vsFTPd 3.0.3")]
    public async Task TheWordFtpAnywhere_IsEnough(string greeting, string expectedShort)
    {
        var (result, _) = await RunAgainst(greeting);
        Assert.Equal(expectedShort, result.Short);
    }

    [Fact]
    public async Task MultiLineGreeting_IsStillFtp()
    {
        var (result, _) = await RunAgainst("220-Welcome\r\n220 FileZilla Server 1.8.0\r\n");
        Assert.StartsWith("FileZilla Server 1.8.0", result.Short);
    }

    [Fact]
    public async Task SomethingElseOnPort21_IsOpenButNotConfirmed()
    {
        var (result, _) = await RunAgainst("SSH-2.0-OpenSSH_9.6\r\n");

        Assert.Equal(PortState.Open, result.State);
        Assert.Equal("open?", result.Short);
        Assert.Contains("Status : port open, FTP not confirmed", result.Long);
        Assert.Contains("Banner : SSH-2.0-OpenSSH_9.6", result.Long);
    }

    [Fact]
    public async Task NoBanner_IsOpenButNotConfirmed_WithNoneReceived()
    {
        var (result, _) = await RunAgainst(null);

        Assert.Equal(PortState.Open, result.State);
        Assert.Equal("open?", result.Short);
        Assert.Contains("Banner : <none received>", result.Long);
    }

    [Fact]
    public async Task ClosedPort_IsEmpty_LikeTheOriginal()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();

        var result = await new ProbeRunner().RunAsync(Ftp(port), IPAddress.Loopback, CancellationToken.None);

        Assert.Equal(PortState.Closed, result.State);
        Assert.Equal("", result.Short);
    }

    [Fact]
    public async Task TheProbe_SendsNothing()
    {
        var (_, received) = await RunAgainst("220 ProFTPD 1.3.7 Server ready.\r\n");
        Assert.Equal("", received);
        Assert.Empty(Ftp(21).Steps.OfType<SendStep>());
    }

    [Fact]
    public void ShippedFtpProbe_IsDescribedAsABannerRead()
    {
        var steps = ProbeDescriber.DescribeSteps(Ftp(21));
        Assert.Contains(steps, l => l.StartsWith("Read up to 1024 bytes"));
        Assert.DoesNotContain(steps, l => l.StartsWith("Send"));
    }
}
