using ANetworkScanner.Engine.Probes;
using Xunit;

namespace ANetworkScanner.Engine.Tests;

public class ProbeManagementTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "ans-mgmt-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
    }

    private string Dir(string name) => Directory.CreateDirectory(Path.Combine(_root, name)).FullName;

    private static ProbeDefinition Load(string json) =>
        Assert.Single(ProbeLoader.LoadFromJson(json, "t.json").Probes);

    // ── Origin tracking ──────────────────────────────────────────────────────

    [Fact]
    public void Loader_MarksOriginAndOverrides()
    {
        var builtIn = Dir("builtin");
        var user = Dir("user");
        File.WriteAllText(Path.Combine(builtIn, "a.json"), """{ "id": "a", "ports": [1] }""");
        File.WriteAllText(Path.Combine(builtIn, "b.json"), """{ "id": "b", "ports": [2] }""");
        File.WriteAllText(Path.Combine(user, "a.json"), """{ "id": "a", "title": "Mine", "ports": [3] }""");
        File.WriteAllText(Path.Combine(user, "c.json"), """{ "id": "c", "ports": [4] }""");

        var probes = ProbeLoader.LoadDirectories(builtIn, user).Probes.ToDictionary(p => p.Id);

        Assert.False(probes["b"].IsUser);
        Assert.False(probes["b"].OverridesBuiltIn);
        Assert.Equal(Path.Combine(builtIn, "b.json"), probes["b"].SourcePath);

        Assert.True(probes["a"].IsUser);
        Assert.True(probes["a"].OverridesBuiltIn);
        Assert.Equal(Path.Combine(user, "a.json"), probes["a"].SourcePath);

        Assert.True(probes["c"].IsUser);
        Assert.False(probes["c"].OverridesBuiltIn);
    }

    [Fact]
    public void Problems_CarryTheFullPath()
    {
        var user = Dir("user");
        var bad = Path.Combine(user, "bad.json");
        File.WriteAllText(bad, "{ nope");
        var problem = Assert.Single(ProbeLoader.LoadDirectories(Dir("builtin"), user).Problems);
        Assert.Equal(bad, problem.FullPath);
    }

    // ── Template ─────────────────────────────────────────────────────────────

    [Fact]
    public void Template_LoadsWithoutProblems_AndUsesTheId()
    {
        var result = ProbeLoader.LoadFromJson(ProbeInstaller.Template("my-probe"), "my-probe.json");
        Assert.Empty(result.Problems);
        var probe = Assert.Single(result.Probes);
        Assert.Equal("my-probe", probe.Id);
        Assert.Equal(8080, Assert.Single(probe.Ports).Port);
    }

    [Fact]
    public void NewId_PicksTheFirstFreeName()
    {
        Assert.Equal("my-probe", ProbeInstaller.NewId([]));
        Assert.Equal("my-probe-2", ProbeInstaller.NewId(["my-probe"]));
        Assert.Equal("my-probe-3", ProbeInstaller.NewId(["MY-PROBE", "my-probe-2"]));
    }

    // ── Save / delete ────────────────────────────────────────────────────────

    [Fact]
    public void CreateFromTemplate_WritesAFileThatLoadsBack()
    {
        var user = Dir("user");
        var path = ProbeInstaller.CreateFromTemplate(user, []);
        Assert.Equal(Path.Combine(user, "my-probe.json"), path);

        var second = ProbeInstaller.CreateFromTemplate(user, ["my-probe"]);
        Assert.Equal(Path.Combine(user, "my-probe-2.json"), second);
        Assert.Equal(2, ProbeLoader.LoadDirectories(Dir("builtin"), user).Probes.Count);
    }

    [Fact]
    public void Save_RefusesToOverwriteUnlessAsked()
    {
        var user = Dir("user");
        ProbeInstaller.Save("{}", "x", user, overwrite: false);
        Assert.Throws<IOException>(() => ProbeInstaller.Save("{}", "x", user, overwrite: false));
        ProbeInstaller.Save("""{ "a": 1 }""", "x", user, overwrite: true);
        Assert.Contains("\"a\"", File.ReadAllText(Path.Combine(user, "x.json")));
    }

    [Fact]
    public void Delete_OnlyRemovesJsonFilesDirectlyInsideTheUserFolder()
    {
        var user = Dir("user");
        var builtIn = Dir("builtin");
        var mine = Path.Combine(user, "mine.json");
        var builtInFile = Path.Combine(builtIn, "ssh.json");
        var note = Path.Combine(user, "notes.txt");
        File.WriteAllText(mine, "{}");
        File.WriteAllText(builtInFile, "{}");
        File.WriteAllText(note, "x");

        Assert.False(ProbeInstaller.Delete(builtInFile, user), "built-in file");
        Assert.False(ProbeInstaller.Delete(note, user), "not a json file");
        Assert.False(ProbeInstaller.Delete(Path.Combine(user, "..", "builtin", "ssh.json"), user), "path tricks");
        Assert.False(ProbeInstaller.Delete(Path.Combine(user, "missing.json"), user), "missing");
        Assert.True(File.Exists(builtInFile));

        Assert.True(ProbeInstaller.Delete(mine, user));
        Assert.False(File.Exists(mine));
    }

    // ── Descriptions ─────────────────────────────────────────────────────────

    [Fact]
    public void PortsSummary_ShowsTlsAndUdp()
    {
        Assert.Equal("80, 443 TLS", ProbeDescriber.PortsSummary(Load("""{ "id": "h", "ports": [80, {"port": 443, "tls": true}] }""")));
        Assert.Equal("UDP 161", ProbeDescriber.PortsSummary(Load("""{ "id": "s", "transport": "udp", "ports": [161], "steps": [ { "send": "x" } ] }""")));
    }

    [Fact]
    public void DescribeSteps_ExplainsTextHexAndVariables()
    {
        var p = Load("""
            { "id": "d", "ports": [80], "connectTimeoutMs": 900,
              "steps": [
                { "send": [ { "text": "GET /\r\nHost: " }, { "var": "ip" }, { "hex": "0D 0A 00 FF" } ] },
                { "read": { "timeoutMs": 700, "maxBytes": 128, "until": { "text": "\r\n\r\n" } } } ] }
            """);
        var lines = ProbeDescriber.DescribeSteps(p);

        Assert.Equal("Connect (80), give up after 900 ms", lines[0]);
        Assert.Equal("Send 17+ bytes: \"GET /\\r\\nHost: \" {ip} <0D 0A 00 FF>", lines[1]);
        Assert.Equal("Read up to 128 bytes, wait 700 ms, until \"\\r\\n\\r\\n\"", lines[2]);
    }

    [Fact]
    public void DescribeSteps_SaysSoWhenOnlyThePortIsChecked()
    {
        var lines = ProbeDescriber.DescribeSteps(Load("""{ "id": "p", "ports": [22] }"""));
        Assert.Contains(lines, l => l.Contains("only says whether the port is open"));
    }

    [Fact]
    public void DescribeMatches_ListsRulesInOrderWithTheFallback()
    {
        var p = Load("""
            { "id": "m", "ports": [1],
              "extract": [ { "regex": "Server: (?<s>.+)" } ],
              "match": [ { "regex": "^SSH-", "short": "ssh" }, { "hex": "03 00 ?? 13", "offset": 2, "short": "bin" } ],
              "fallback": { "short": "open" } }
            """);
        var lines = ProbeDescriber.DescribeMatches(p);

        Assert.Equal("Extract  /Server: (?<s>.+)/", lines[0]);
        Assert.Equal("1. If the reply matches /^SSH-/  →  \"ssh\"", lines[1]);
        Assert.Equal("2. If the reply matches bytes 03 00 ?? 13 at offset 2  →  \"bin\"", lines[2]);
        Assert.Equal("Otherwise: \"open\"", lines[3]);
    }

    [Fact]
    public void ShippedProbes_AllHaveReadableDescriptions()
    {
        var shipped = ProbeLoader.LoadDirectories(Path.Combine(AppContext.BaseDirectory, "probes")).Probes;
        Assert.NotEmpty(shipped);
        foreach (var probe in shipped)
        {
            Assert.NotEmpty(ProbeDescriber.DescribeSteps(probe));
            Assert.NotEmpty(ProbeDescriber.DescribeMatches(probe));
            Assert.NotEmpty(ProbeDescriber.PortsSummary(probe));
        }
    }
}

public class ProbeDescriberPreviewTests
{
    [Fact]
    public void LongText_IsCutWithAnEllipsisOutsideTheQuotes_NotEscaped()
    {
        var probe = Assert.Single(ProbeLoader.LoadFromJson(
            """{ "id": "l", "ports": [1], "steps": [ { "send": "GET /a/very/long/path/that/keeps/going/and/going/and/going HTTP/1.0\r\n" } ] }""", "t.json").Probes);
        var line = ProbeDescriber.DescribeSteps(probe)[1];

        Assert.EndsWith("…\"", line);
        Assert.DoesNotContain(@"\x2026", line);
    }
}
