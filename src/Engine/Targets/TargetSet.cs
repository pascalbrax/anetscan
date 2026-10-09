using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace ANetworkScanner.Engine.Targets;

/// <summary>
/// An immutable, lazily enumerated set of IPv4 targets. Internally a sorted list of
/// non-overlapping inclusive ranges of host-order <see cref="uint"/> addresses, so a /8 costs
/// a few bytes instead of 16 million strings, and overlapping input items never scan a host twice.
/// </summary>
public sealed class TargetSet
{
    /// <summary>Hard ceiling on one scan (a /8).</summary>
    public const long MaxTargets = 1L << 24;

    private static readonly char[] ItemSeparators = [',', ';', ' ', '\t', '\r', '\n'];

    private readonly (uint Start, uint End)[] _ranges;
    private readonly long[] _before; // number of addresses in all earlier ranges

    public static TargetSet Empty { get; } = new([]);

    private TargetSet((uint Start, uint End)[] ranges)
    {
        _ranges = ranges;
        _before = new long[ranges.Length];
        long count = 0;
        for (int i = 0; i < ranges.Length; i++)
        {
            _before[i] = count;
            count += (long)ranges[i].End - ranges[i].Start + 1;
        }
        Count = count;
    }

    public long Count { get; }

    public bool IsEmpty => Count == 0;

    public IReadOnlyList<(uint Start, uint End)> Ranges => _ranges;

    public IEnumerable<uint> EnumerateValues()
    {
        foreach (var (s, e) in _ranges)
            for (long v = s; v <= e; v++)
                yield return (uint)v;
    }

    public IEnumerable<IPAddress> Enumerate()
    {
        foreach (var v in EnumerateValues())
            yield return ToAddress(v);
    }

    public bool Contains(uint value)
    {
        int lo = 0, hi = _ranges.Length - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (value < _ranges[mid].Start) hi = mid - 1;
            else if (value > _ranges[mid].End) lo = mid + 1;
            else return true;
        }
        return false;
    }

    /// <summary>Position of <paramref name="value"/> in enumeration order, or -1 when it is not a target.</summary>
    public long IndexOf(uint value)
    {
        int lo = 0, hi = _ranges.Length - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (value < _ranges[mid].Start) hi = mid - 1;
            else if (value > _ranges[mid].End) lo = mid + 1;
            else return _before[mid] + (value - _ranges[mid].Start);
        }
        return -1;
    }

    /// <summary>The address at a position in enumeration order (the inverse of <see cref="IndexOf"/>).</summary>
    public uint ValueAt(long index)
    {
        if (index < 0 || index >= Count) throw new ArgumentOutOfRangeException(nameof(index));
        int lo = 0, hi = _ranges.Length - 1;
        while (lo < hi)
        {
            int mid = (lo + hi + 1) >>> 1;
            if (_before[mid] <= index) lo = mid; else hi = mid - 1;
        }
        return (uint)(_ranges[lo].Start + (index - _before[lo]));
    }

    // ── Parsing ──────────────────────────────────────────────────────────────

    public static TargetSet Parse(string input)
    {
        if (!TryParse(input, out var set, out var error))
            throw new FormatException(error);
        return set;
    }

    /// <summary>
    /// Items are separated by commas, semicolons or whitespace. Each item is one of:
    /// <c>192.168.1.7</c> · <c>192.168.1.0/24</c> · <c>192.168.1.10-192.168.1.50</c> ·
    /// <c>192.168.1.10-50</c> · nmap-style octets <c>192.168.1.*</c>, <c>10.0.0-3.1-100</c>.
    /// </summary>
    public static bool TryParse(string? input, out TargetSet set, out string error)
    {
        set = Empty;
        error = "";

        if (string.IsNullOrWhiteSpace(input))
        {
            error = "Enter a target.";
            return false;
        }

        var ranges = new List<(uint Start, uint End)>();
        foreach (var item in input.Split(ItemSeparators, StringSplitOptions.RemoveEmptyEntries))
        {
            if (!TryParseItem(item, ranges, out error))
                return false;
        }

        ranges.Sort((a, b) => a.Start.CompareTo(b.Start));
        var merged = new List<(uint Start, uint End)>(ranges.Count);
        foreach (var r in ranges)
        {
            if (merged.Count > 0 && (long)r.Start <= (long)merged[^1].End + 1)
            {
                if (r.End > merged[^1].End)
                    merged[^1] = (merged[^1].Start, r.End);
            }
            else
            {
                merged.Add(r);
            }
        }

        var result = new TargetSet([.. merged]);
        if (result.Count > MaxTargets)
        {
            error = $"Too many targets ({result.Count:N0}). The limit is {MaxTargets:N0} (a /8).";
            return false;
        }
        if (result.IsEmpty)
        {
            error = "The target produced no hosts.";
            return false;
        }

        set = result;
        return true;
    }

    private static bool TryParseItem(string item, List<(uint Start, uint End)> output, out string error)
    {
        error = "";

        int slash = item.IndexOf('/');
        if (slash >= 0)
            return TryParseCidr(item, slash, output, out error);

        // Full range "a.b.c.d-e.f.g.h": the right side contains dots and the left is a plain address.
        int dash = item.IndexOf('-');
        if (dash > 0 && item.IndexOf('.', dash) >= 0 && TryParseAddress(item[..dash], out var from))
        {
            if (!TryParseAddress(item[(dash + 1)..], out var to))
            {
                error = $"Invalid range end in \"{item}\".";
                return false;
            }
            if (from > to)
            {
                error = $"Range start is greater than range end in \"{item}\".";
                return false;
            }
            output.Add((from, to));
            return true;
        }

        return TryParseOctetPattern(item, output, out error);
    }

    private static bool TryParseCidr(string item, int slash, List<(uint Start, uint End)> output, out string error)
    {
        error = "";
        if (!TryParseAddress(item[..slash], out var address) ||
            !int.TryParse(item[(slash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out var prefix) ||
            prefix > 32)
        {
            error = $"Invalid CIDR \"{item}\".";
            return false;
        }

        uint mask = prefix == 0 ? 0 : uint.MaxValue << (32 - prefix);
        uint network = address & mask;
        uint broadcast = network | ~mask;

        // /32 is one host and /31 is a point-to-point pair (RFC 3021): both addresses are hosts.
        // Anything larger loses the network and broadcast addresses.
        if (prefix >= 31) output.Add((network, broadcast));
        else output.Add((network + 1, broadcast - 1));
        return true;
    }

    private static bool TryParseOctetPattern(string item, List<(uint Start, uint End)> output, out string error)
    {
        error = "";
        var parts = item.Split('.');
        if (parts.Length != 4)
        {
            error = $"Invalid target \"{item}\".";
            return false;
        }

        var lo = new int[4];
        var hi = new int[4];
        for (int i = 0; i < 4; i++)
        {
            if (!TryParseOctetSpec(parts[i], out lo[i], out hi[i]))
            {
                error = $"Invalid target \"{item}\" (octet \"{parts[i]}\").";
                return false;
            }
        }

        long total = (long)(hi[0] - lo[0] + 1) * (hi[1] - lo[1] + 1) * (hi[2] - lo[2] + 1) * (hi[3] - lo[3] + 1);
        if (total > MaxTargets)
        {
            error = $"Too many targets in \"{item}\". The limit is {MaxTargets:N0}.";
            return false;
        }

        // Only the last octet is contiguous: emit one range per combination of the first three.
        for (int a = lo[0]; a <= hi[0]; a++)
        for (int b = lo[1]; b <= hi[1]; b++)
        for (int c = lo[2]; c <= hi[2]; c++)
        {
            uint prefix = ((uint)a << 24) | ((uint)b << 16) | ((uint)c << 8);
            output.Add((prefix | (uint)lo[3], prefix | (uint)hi[3]));
        }
        return true;
    }

    private static bool TryParseOctetSpec(string spec, out int lo, out int hi)
    {
        lo = hi = 0;
        if (spec == "*") { lo = 0; hi = 255; return true; }

        int dash = spec.IndexOf('-');
        if (dash < 0)
        {
            if (!TryOctet(spec, out lo)) return false;
            hi = lo;
            return true;
        }
        if (!TryOctet(spec[..dash], out lo) || !TryOctet(spec[(dash + 1)..], out hi)) return false;
        return lo <= hi;
    }

    private static bool TryOctet(string s, out int value)
    {
        value = 0;
        return s.Length is >= 1 and <= 3 &&
               int.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out value) &&
               value <= 255;
    }

    private static bool TryParseAddress(string s, out uint value)
    {
        value = 0;
        var parts = s.Split('.');
        if (parts.Length != 4) return false;
        foreach (var p in parts)
        {
            if (!TryOctet(p, out var octet)) return false;
            value = (value << 8) | (uint)octet;
        }
        return true;
    }

    public static IPAddress ToAddress(uint value) => new(
        [(byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value]);

    public static uint ToValue(IPAddress address)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("Only IPv4 addresses are supported.", nameof(address));
        var b = address.GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }
}
