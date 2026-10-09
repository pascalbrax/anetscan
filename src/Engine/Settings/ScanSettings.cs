namespace ANetworkScanner.Engine.Settings;

/// <summary>Default-rate presets offered in the Options window.</summary>
public enum RatePreset
{
    Gentle,
    Normal,
    Aggressive,
    Custom,
}

/// <summary>Tuning for the discovery stage. Defaults are deliberately polite for shared work LANs.</summary>
public sealed record DiscoverySettings
{
    public const double GentleRate = 100;
    public const double NormalRate = 500;
    public const double AggressiveRate = 2000;

    /// <summary>Sustained probe rate across the whole scan. Zero or less disables the limit.</summary>
    public double ProbesPerSecond { get; init; } = NormalRate;

    /// <summary>Upper bound on probes waiting for a reply at the same time.</summary>
    public int MaxInFlight { get; init; } = 256;

    /// <summary>Upper bound on probe connections open at the same time, across all hosts.</summary>
    public int MaxConcurrentProbes { get; init; } = 128;

    /// <summary>Extra connection attempts for a port that stayed silent, before it is reported as filtered.</summary>
    public int ConnectRetries { get; init; } = 1;

    /// <summary>
    /// Look up each live host's name (reverse DNS, mDNS, NetBIOS). Off by default: it asks your DNS server about every
    /// live address and sends small name queries to the hosts themselves.
    /// </summary>
    public bool ResolveNames { get; init; }

    /// <summary>
    /// Also check addresses that answered neither ping nor ARP: connect to <see cref="ForceScanPorts"/> and list the host
    /// when a port opens or is refused. Finds firewalled hosts, at the price of more traffic and a longer scan.
    /// </summary>
    public bool ForceScan { get; init; }

    /// <summary>The TCP ports tried on silent hosts when <see cref="ForceScan"/> is on.</summary>
    public int[] ForceScanPorts { get; init; } = [22, 80, 135, 139, 443, 445, 3389, 21, 23, 25, 5900, 8080];

    /// <summary>How long to wait for the name sources of one host.</summary>
    public int NameTimeoutMs { get; init; } = 1500;

    /// <summary>How long to wait for an echo reply.</summary>
    public int TimeoutMs { get; init; } = 1000;

    /// <summary>Extra attempts for a host that did not answer (timeouts only). One retry catches most dropped packets.</summary>
    public int Retries { get; init; } = 1;

    /// <summary>
    /// Up to this many targets the RTT is timed around each probe (fractional ms). Larger scans keep the
    /// thread pool too busy for that to be trustworthy, so they report the Windows API's whole milliseconds.
    /// </summary>
    public int PreciseRttMaxTargets { get; init; } = 4096;

    /// <summary>How long to wait for an ARP answer from an on-link host.</summary>
    public int ArpTimeoutMs { get; init; } = 1500;

    public static DiscoverySettings FromPreset(RatePreset preset) => preset switch
    {
        RatePreset.Gentle => new() { ProbesPerSecond = GentleRate, MaxInFlight = 64 },
        RatePreset.Aggressive => new() { ProbesPerSecond = AggressiveRate, MaxInFlight = 512 },
        _ => new(),
    };

    /// <summary>Clamps user-edited values into a safe range.</summary>
    public DiscoverySettings Normalized() => this with
    {
        MaxInFlight = Math.Clamp(MaxInFlight, 1, 4096),
        MaxConcurrentProbes = Math.Clamp(MaxConcurrentProbes, 1, 2048),
        TimeoutMs = Math.Clamp(TimeoutMs, 100, 30_000),
        Retries = Math.Clamp(Retries, 0, 5),
        ConnectRetries = Math.Clamp(ConnectRetries, 0, 3),
        NameTimeoutMs = Math.Clamp(NameTimeoutMs, 200, 10_000),
        ForceScanPorts = [.. (ForceScanPorts ?? []).Where(p => p is >= 1 and <= 65535).Distinct().Take(32)],
        PreciseRttMaxTargets = Math.Max(0, PreciseRttMaxTargets),
        ArpTimeoutMs = Math.Clamp(ArpTimeoutMs, 100, 10_000),
    };
}
