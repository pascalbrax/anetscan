using System.Diagnostics;
using System.Net;
using System.Text.Json;
using ANetworkScanner.Engine;
using ANetworkScanner.Engine.Discovery;
using ANetworkScanner.Engine.Names;
using ANetworkScanner.Engine.Probes;
using ANetworkScanner.Engine.Settings;
using ANetworkScanner.Engine.Targets;

// Developer harness for the engine: runs a scan and optionally diffs discovery against an nmap baseline.
const string Usage = """
    ScanCli <target> [options]
      --rate N          probes per second (default 500, 0 = unlimited)
      --inflight N      concurrent ICMP probes
      --timeout MS      ICMP timeout
      --retries N       ICMP retries
      --no-arp          discovery by ICMP only
      --probes a,b      run only these probes (default: all in .\probes and the user probes folder)
      --no-probes       discovery only
      --names           also resolve hostnames (reverse DNS, mDNS, NetBIOS)
      --force           also check silent hosts (no ping/ARP reply) on common TCP ports
      --details         print each probe's full details
      --baseline FILE   compare discovery with an nmap baseline fixture
    """;

if (args.Length == 0 || args[0] is "-h" or "--help")
{
    Console.WriteLine(Usage);
    return 1;
}

string target = args[0];
string? baselinePath = null;
bool useArp = true, noProbes = false, details = false, names = false;
HashSet<string>? only = null;
var settings = new DiscoverySettings();

for (int i = 1; i < args.Length; i++)
{
    string Next() => i + 1 < args.Length ? args[++i] : throw new ArgumentException($"Missing value for {args[i]}");
    try
    {
        switch (args[i])
        {
            case "--rate": settings = settings with { ProbesPerSecond = double.Parse(Next()) }; break;
            case "--inflight": settings = settings with { MaxInFlight = int.Parse(Next()) }; break;
            case "--timeout": settings = settings with { TimeoutMs = int.Parse(Next()) }; break;
            case "--retries": settings = settings with { Retries = int.Parse(Next()) }; break;
            case "--baseline": baselinePath = Next(); break;
            case "--probes": only = [.. Next().Split(',', StringSplitOptions.RemoveEmptyEntries)]; break;
            case "--no-arp": useArp = false; break;
            case "--no-probes": noProbes = true; break;
            case "--details": details = true; break;
            case "--force": settings = settings with { ForceScan = true }; break;
            case "--names": names = true; settings = settings with { ResolveNames = true }; break;
            default: Console.Error.WriteLine($"Unknown option {args[i]}\n{Usage}"); return 1;
        }
    }
    catch (Exception ex) when (ex is ArgumentException or FormatException)
    {
        Console.Error.WriteLine(ex.Message);
        return 1;
    }
}

if (!TargetSet.TryParse(target, out var targets, out var error))
{
    Console.Error.WriteLine(error);
    return 1;
}

settings = settings.Normalized();

var probes = new List<ProbeDefinition>();
if (!noProbes)
{
    var loaded = ProbeLoader.LoadDirectories(
        Path.Combine(AppContext.BaseDirectory, "probes"),
        Path.Combine(SettingsStore.DefaultDirectory, "probes"));
    foreach (var problem in loaded.Problems) Console.Error.WriteLine($"probe problem - {problem}");
    probes = [.. loaded.Probes.Where(p => only is null || only.Contains(p.Id))];
}

Console.WriteLine($"Scanning {targets.Count:N0} addresses - {settings.ProbesPerSecond:N0} probes/s, " +
                  $"{settings.MaxInFlight} in flight, {settings.TimeoutMs} ms timeout, {settings.Retries} retries");
var subnets = useArp ? LocalSubnets.Detect() : LocalSubnets.None;
Console.WriteLine("On-link subnets (ARP enabled): " + (subnets.Names.Count == 0 ? "none" : string.Join(", ", subnets.Names)));
Console.WriteLine("Probes: " + (probes.Count == 0 ? "none" : string.Join(", ", probes.Select(p => p.Id))));

using var arp = new SystemArpResolver();
var engine = new ScanEngine(new SystemPinger(), settings, subnets, useArp ? arp : null);

var alive = new Dictionary<string, HostObservation>();
var hostNames = new Dictionary<string, HostName?>();
var probeResults = new Dictionary<string, List<ProbeResult>>();
int scanned = 0;
var sw = Stopwatch.StartNew();
TimeSpan discoveryDone = TimeSpan.Zero;

await foreach (var e in engine.RunAsync(targets, probes))
{
    switch (e)
    {
        case HostScanned h:
            scanned++;
            if (h.Host.IsAlive) alive[h.Host.Address.ToString()] = h.Host;
            if (scanned == targets.Count) discoveryDone = sw.Elapsed;
            break;
        case NameResolved n:
            hostNames[n.Address.ToString()] = n.Name;
            break;
        case ProbeCompleted p:
            if (!probeResults.TryGetValue(p.Address.ToString(), out var list))
                probeResults[p.Address.ToString()] = list = [];
            list.Add(p.Result);
            break;
    }
}
sw.Stop();

var hosts = alive.Values.OrderBy(o => TargetSet.ToValue(o.Address)).ToList();
foreach (var o in hosts)
{
    var resolved = hostNames.GetValueOrDefault(o.Address.ToString());
    var nameText = names ? (resolved is null ? "-" : $"{resolved.Name} [{resolved.SourceText}]") : "";
    Console.WriteLine($"  {o.Address,-16} {o.RttMs,7:F2} ms  ttl {o.Ttl,3}  {o.Method,-9} {o.Mac ?? "",-17} {(names ? nameText.PadRight(52) : "")}{o.Detail}");
    if (!probeResults.TryGetValue(o.Address.ToString(), out var results)) continue;

    foreach (var r in results.Where(r => r.State == PortState.Open).OrderBy(r => r.ProbeId))
    {
        Console.WriteLine($"      {r.Title,-6} {r.Short}");
        if (details)
            foreach (var line in r.Long.Split('\n')) Console.WriteLine($"        {line}");
    }
}

Console.WriteLine($"{hosts.Count} alive of {scanned:N0} scanned; discovery {discoveryDone.TotalSeconds:F2} s, total {sw.Elapsed.TotalSeconds:F2} s");

if (baselinePath is not null)
{
    using var doc = JsonDocument.Parse(File.ReadAllText(baselinePath));
    var scan = doc.RootElement.GetProperty("scans").EnumerateArray()
        .FirstOrDefault(s => s.GetProperty("target").GetString() == target);
    if (scan.ValueKind == JsonValueKind.Undefined)
    {
        Console.Error.WriteLine($"No baseline for \"{target}\" in {baselinePath}");
        return 1;
    }

    var expected = scan.GetProperty("up").EnumerateArray().Select(e => e.GetString()!).ToHashSet();
    var found = alive.Keys.ToHashSet();
    int Order(string ip) => (int)TargetSet.ToValue(IPAddress.Parse(ip));
    var missing = expected.Except(found).OrderBy(Order).ToList();
    var extra = found.Except(expected).OrderBy(Order).ToList();

    Console.WriteLine($"Baseline: {expected.Count} up in {scan.GetProperty("elapsedSeconds").GetDouble():F2} s ({scan.GetProperty("method").GetString()})");
    Console.WriteLine($"  matched {expected.Intersect(found).Count()}, missing {missing.Count}, extra {extra.Count}");
    if (missing.Count > 0) Console.WriteLine("  missing: " + string.Join(", ", missing));
    if (extra.Count > 0) Console.WriteLine("  extra:   " + string.Join(", ", extra));
}

return 0;
