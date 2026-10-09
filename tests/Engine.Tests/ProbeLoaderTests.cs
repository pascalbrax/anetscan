using ANetworkScanner.Engine.Probes;
using Xunit;

namespace ANetworkScanner.Engine.Tests;

public class ProbeLoaderTests
{
    private const string Minimal = """{ "id": "t", "ports": [22] }""";

    private static ProbeLoadResult Load(string json) => ProbeLoader.LoadFromJson(json, "t.json");

    private static string Problems(ProbeLoadResult r) => string.Join(" | ", r.Problems.Select(p => p.Message));

    // â”€â”€ Hex â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    [Theory]
    [InlineData("03 00 00 13", new byte[] { 3, 0, 0, 0x13 })]
    [InlineData("03000013", new byte[] { 3, 0, 0, 0x13 })]
    [InlineData("03:00:00:13", new byte[] { 3, 0, 0, 0x13 })]
    [InlineData("0A, ff,\n 00", new byte[] { 0x0A, 0xFF, 0 })]
    public void HexBytes_AcceptsCommonSpellings(string text, byte[] expected)
    {
        Assert.True(HexBytes.TryParse(text, out var bytes, out _));
        Assert.Equal(expected, bytes);
    }

    [Theory]
    [InlineData("")]
    [InlineData("0")]
    [InlineData("030")]
    [InlineData("zz")]
    [InlineData("0x03")]
    public void HexBytes_RejectsBadInput(string text)
    {
        Assert.False(HexBytes.TryParse(text, out _, out var error));
        Assert.NotEmpty(error);
    }

    [Fact]
    public void HexPattern_WildcardsAndOffset()
    {
        Assert.True(HexPattern.TryParse("03 00 ?? 13", 0, out var p, out _));
        Assert.True(p.IsMatch([3, 0, 0x55, 0x13, 9]));
        Assert.False(p.IsMatch([3, 1, 0x55, 0x13]));
        Assert.False(p.IsMatch([3, 0, 0x55]), "too short");

        Assert.True(HexPattern.TryParse("AA BB", 2, out var q, out _));
        Assert.True(q.IsMatch([0, 0, 0xAA, 0xBB]));
        Assert.False(q.IsMatch([0xAA, 0xBB, 0, 0]));
    }

    [Theory]
    [InlineData("03 0")]
    [InlineData("03 ?")]
    [InlineData("")]
    [InlineData("03 xx")]
    public void HexPattern_RejectsBadInput(string text) =>
        Assert.False(HexPattern.TryParse(text, 0, out _, out _));

    // â”€â”€ Valid files â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    [Fact]
    public void MinimalProbe_GetsDefaults()
    {
        var r = Load(Minimal);
        Assert.Empty(r.Problems);
        var p = Assert.Single(r.Probes);
        Assert.Equal("T", p.Title);
        Assert.Equal(ProbeTransport.Tcp, p.Transport);
        Assert.Equal(1500, p.ConnectTimeoutMs);
        Assert.Equal("open", p.FallbackShort);
        Assert.Equal(22, Assert.Single(p.Ports).Port);
    }

    [Fact]
    public void FullProbe_IsParsed_WithCommentsAndTrailingCommas()
    {
        var r = Load("""
            {
              // a comment
              "schema": 1, "id": "full-1", "title": "Full", "description": "d", "transport": "tcp",
              "ports": [80, { "port": 443, "tls": true },],
              "connectTimeoutMs": 800,
              "steps": [
                { "send": [ { "text": "GET / HTTP/1.0\r\nHost: " }, { "var": "ip" }, { "hex": "0D 0A 0D 0A" } ] },
                { "read": { "timeoutMs": 500, "maxBytes": 64, "until": { "hex": "0D 0A" } } }
              ],
              "extract": [ { "regex": "Server: (?<server>.+)" } ],
              "match": [ { "regex": "^HTTP", "short": "web" }, { "hex": "FF ??", "offset": 1, "short": "bin", "long": "x" } ],
              "fallback": { "short": "?", "long": "nothing" }
            }
            """);
        Assert.Empty(r.Problems);
        var p = Assert.Single(r.Probes);
        Assert.True(p.Ports[1].Tls);
        Assert.Equal(2, p.Steps.Count);
        var send = Assert.IsType<SendStep>(p.Steps[0]);
        Assert.Equal(3, send.Parts.Count);
        Assert.Equal([0x0D, 0x0A, 0x0D, 0x0A], Assert.IsType<HexPart>(send.Parts[2]).Bytes);
        Assert.Equal([0x0D, 0x0A], Assert.IsType<ReadStep>(p.Steps[1]).Until);
        Assert.Equal(2, p.Match.Count);
        Assert.Equal(1, p.Match[1].Hex!.Offset);
    }

    [Fact]
    public void SendAsPlainString_IsText()
    {
        var r = Load("""{ "id": "t", "ports": [1], "steps": [ { "send": "hello\r\n" } ] }""");
        Assert.Empty(r.Problems);
        var send = Assert.IsType<SendStep>(Assert.Single(r.Probes).Steps[0]);
        Assert.Equal("hello\r\n", Assert.IsType<TextPart>(Assert.Single(send.Parts)).Text);
    }

    // â”€â”€ Rejected files â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    [Theory]
    [InlineData("""{ "id": "t", "ports": [22], "portz": [1] }""", "portz")]
    [InlineData("""{ "ports": [22] }""", "id: required")]
    [InlineData("""{ "id": "Bad Id", "ports": [22] }""", "id:")]
    [InlineData("""{ "id": "t" }""", "ports")]
    [InlineData("""{ "id": "t", "ports": [] }""", "ports")]
    [InlineData("""{ "id": "t", "ports": [0] }""", "port")]
    [InlineData("""{ "id": "t", "ports": [70000] }""", "port")]
    [InlineData("""{ "id": "t", "ports": [22, 22] }""", "twice")]
    [InlineData("""{ "id": "t", "ports": ["22"] }""", "ports[0]")]
    [InlineData("""{ "id": "t", "ports": [22], "transport": "sctp" }""", "transport")]
    [InlineData("""{ "id": "t", "ports": [22], "schema": 2 }""", "schema")]
    [InlineData("""{ "id": "t", "ports": [22], "connectTimeoutMs": 5 }""", "connectTimeoutMs")]
    [InlineData("""{ "id": "t", "ports": [22], "steps": [ { "send": { "hex": "0" } } ] }""", "odd number")]
    [InlineData("""{ "id": "t", "ports": [22], "steps": [ { "send": { "hex": "zz" } } ] }""", "not a hex digit")]
    [InlineData("""{ "id": "t", "ports": [22], "steps": [ { "send": { "text": "a", "hex": "00" } } ] }""", "exactly one")]
    [InlineData("""{ "id": "t", "ports": [22], "steps": [ { "send": { "var": "password" } } ] }""", "only \"ip\"")]
    [InlineData("""{ "id": "t", "ports": [22], "steps": [ { "send": "a", "read": {} } ] }""", "exactly one")]
    [InlineData("""{ "id": "t", "ports": [22], "steps": [ { "read": { "maxBytes": 0 } } ] }""", "maxBytes")]
    [InlineData("""{ "id": "t", "ports": [22], "steps": [ { "send": "â‚¬" } ] }""", "hex part")]
    [InlineData("""{ "id": "t", "ports": [22], "match": [ { "regex": "(", "short": "x" } ] }""", "regular expression")]
    [InlineData("""{ "id": "t", "ports": [22], "match": [ { "short": "x" } ] }""", "exactly one")]
    [InlineData("""{ "id": "t", "ports": [22], "match": [ { "regex": "a", "hex": "00" } ] }""", "exactly one")]
    [InlineData("""{ "id": "t", "ports": [22], "match": [ { "regex": "a", "offset": 1 } ] }""", "offset")]
    [InlineData("""{ "id": "t", "ports": [22], "match": [ { "hex": "0" } ] }""", "odd number")]
    [InlineData("""{ "id": "t", "ports": [{ "port": 53, "tls": true }], "transport": "udp", "steps": [ { "send": "a" } ] }""", "TLS needs tcp")]
    [InlineData("""{ "id": "t", "ports": [161], "transport": "udp" }""", "UDP probe needs a send step")]
    [InlineData("""[1, 2]""", "one JSON object")]
    [InlineData("""{ "id": "t", ports: [22] }""", "invalid JSON")]
    public void InvalidFiles_AreRejected_WithAUsefulMessage(string json, string expectedFragment)
    {
        var r = Load(json);
        Assert.Empty(r.Probes);
        Assert.Contains(expectedFragment, Problems(r), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AllProblemsAreReported_NotJustTheFirst()
    {
        var r = Load("""{ "id": "t", "ports": [0], "steps": [ { "send": { "hex": "0" } } ], "match": [ { "regex": "(" } ] }""");
        Assert.True(r.Problems.Count >= 3, Problems(r));
    }

    [Fact]
    public void ProblemMessages_NameTheFile()
    {
        var r = Load("""{ "ports": [22] }""");
        Assert.All(r.Problems, p => Assert.Equal("t.json", p.File));
    }

    // â”€â”€ Directories â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    [Fact]
    public void LoadDirectories_LaterFolderOverridesById_AndBadFilesAreSkipped()
    {
        var root = Path.Combine(Path.GetTempPath(), "ans-probes-" + Guid.NewGuid().ToString("N"));
        var builtIn = Directory.CreateDirectory(Path.Combine(root, "builtin")).FullName;
        var user = Directory.CreateDirectory(Path.Combine(root, "user")).FullName;
        try
        {
            File.WriteAllText(Path.Combine(builtIn, "a.json"), """{ "id": "a", "title": "Built-in A", "ports": [1] }""");
            File.WriteAllText(Path.Combine(builtIn, "b.json"), """{ "id": "b", "ports": [2] }""");
            File.WriteAllText(Path.Combine(user, "a.json"), """{ "id": "a", "title": "User A", "ports": [3] }""");
            File.WriteAllText(Path.Combine(user, "broken.json"), "{ nope");
            File.WriteAllText(Path.Combine(user, "readme.txt"), "ignored");

            var r = ProbeLoader.LoadDirectories(builtIn, user, Path.Combine(root, "missing"));

            Assert.Equal(["a", "b"], r.Probes.Select(p => p.Id));
            Assert.Equal("User A", r.Probes[0].Title);
            Assert.Equal("broken.json", Assert.Single(r.Problems).File);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void ShippedProbes_AllLoadWithoutProblems()
    {
        var r = ProbeLoader.LoadDirectories(Path.Combine(AppContext.BaseDirectory, "probes"));
        Assert.Empty(r.Problems);
        foreach (var id in new[] { "ssh", "rdp", "http", "vnc", "rtsp", "mail", "smb", "snmp", "onvif", "ftp" })
            Assert.Contains(r.Probes, p => p.Id == id);
    }

    // â”€â”€ Templates â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    private static readonly Dictionary<string, string> Vars = new() { ["code"] = "200", ["server"] = "nginx", ["empty"] = "" };

    [Fact]
    public void Template_FillsKnownVariables() =>
        Assert.Equal("200 nginx", Template.Render("{code} {server}", Vars));

    [Fact]
    public void Template_UnknownAndEmptyVariablesRenderAsNothing() =>
        Assert.Equal("200", Template.Render("{code} {missing}", Vars));

    [Fact]
    public void Template_DropsLinesWhoseValuesAreAllEmpty() =>
        Assert.Equal("Status : 200\nTLS lines are gone", Template.Render(
            "Status : {code}\nServer : {missing}\nCert   : {empty} {missing}\nTLS lines are gone", Vars));

    [Fact]
    public void Template_KeepsPlainTextLines() =>
        Assert.Equal("no variables here", Template.Render("no variables here", Vars));

    [Fact]
    public void Template_BracesCanBeEscaped() =>
        Assert.Equal("{code} = 200", Template.Render("{{code}} = {code}", Vars));
}


