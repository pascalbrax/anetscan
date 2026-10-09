using System.Text;
using System.Text.RegularExpressions;

namespace ANetworkScanner.Engine.Probes;

public enum ProbeTransport
{
    Tcp,
    Udp,
}

/// <param name="Tls">Wrap the TCP connection in TLS (certificate validation is deliberately off: this is a scanner).</param>
public sealed record PortSpec(int Port, bool Tls);

/// <summary>One piece of a payload. Text is sent as Latin-1 (one char = one byte), hex is sent verbatim.</summary>
public abstract record PayloadPart;
public sealed record TextPart(string Text) : PayloadPart;
public sealed record HexPart(byte[] Bytes) : PayloadPart;
/// <summary>A value filled in at run time: <c>ip</c>, <c>port</c>, or <c>uuid</c> (a fresh random GUID per run).</summary>
public sealed record VarPart(string Name) : PayloadPart;

public abstract record ProbeStep;
public sealed record SendStep(IReadOnlyList<PayloadPart> Parts) : ProbeStep;

/// <param name="Until">Keep reading until these bytes have been seen (or maxBytes / timeout). Null: one receive.</param>
public sealed record ReadStep(int TimeoutMs, int MaxBytes, byte[]? Until) : ProbeStep;

/// <summary>A regex whose named groups become template variables, whether or not a match rule fires.</summary>
/// <param name="UrlDecode">Decode <c>%20</c>-style escapes in the captured values (ONVIF scopes, URLs).</param>
public sealed record ExtractRule(Regex Regex, bool UrlDecode = false);

/// <summary>
/// A response test. Exactly one of <see cref="Regex"/> (applied to the response as Latin-1 text) or
/// <see cref="Hex"/> (binary pattern with <c>??</c> wildcards, anchored at an offset) is set.
/// The first rule that matches decides the cell text (<see cref="Short"/>) and the details (<see cref="Long"/>).
/// </summary>
public sealed record MatchRule(Regex? Regex, HexPattern? Hex, string? Short, string? Long, ProbeLevel Level = ProbeLevel.Info);

/// <summary>How noteworthy a finding is; the grid colours the result pill accordingly.</summary>
public enum ProbeLevel
{
    /// <summary>Plain information (a banner, a version).</summary>
    Info,
    /// <summary>Something good: strong authentication, encryption.</summary>
    Good,
    /// <summary>Worth a look: weak settings, default credentials accepted, legacy protocol.</summary>
    Warning,
    /// <summary>A real problem.</summary>
    Bad,
}

public sealed record ProbeDefinition(
    string Id,
    string Title,
    string Description,
    ProbeTransport Transport,
    IReadOnlyList<PortSpec> Ports,
    int ConnectTimeoutMs,
    IReadOnlyList<ProbeStep> Steps,
    IReadOnlyList<ExtractRule> Extract,
    IReadOnlyList<MatchRule> Match,
    string FallbackShort,
    string? FallbackLong,
    string SourceFile)
{
    /// <summary>Full path of the .json file (empty for a definition parsed from text).</summary>
    public string SourcePath { get; init; } = "";

    /// <summary>True when the file comes from the user's probes folder rather than the built-in set.</summary>
    public bool IsUser { get; init; }

    /// <summary>A user probe that replaces a built-in one with the same id.</summary>
    public bool OverridesBuiltIn { get; init; }

    /// <summary>Level of the result when a port is open but no match rule applied.</summary>
    public ProbeLevel FallbackLevel { get; init; }
}

/// <summary>A byte pattern such as <c>03 00 00 ?? ?? D0</c>.</summary>
public sealed class HexPattern
{
    private readonly byte[] _values;
    private readonly bool[] _any;

    private HexPattern(byte[] values, bool[] any, int offset)
    {
        _values = values;
        _any = any;
        Offset = offset;
    }

    public int Offset { get; }

    public int Length => _values.Length;

    /// <summary>The pattern as written in a probe file: <c>03 00 ?? 13</c>.</summary>
    public override string ToString() =>
        string.Join(' ', _values.Select((v, i) => _any[i] ? "??" : v.ToString("X2")));

    public static bool TryParse(string text, int offset, out HexPattern pattern, out string error)
    {
        pattern = null!;
        error = "";
        var values = new List<byte>();
        var any = new List<bool>();

        var compact = StripSeparators(text);
        if (compact.Length == 0 || compact.Length % 2 != 0)
        {
            error = compact.Length == 0 ? "the pattern is empty" : "the pattern has an odd number of hex digits";
            return false;
        }

        for (int i = 0; i < compact.Length; i += 2)
        {
            if (compact[i] == '?' && compact[i + 1] == '?')
            {
                values.Add(0);
                any.Add(true);
            }
            else if (Uri.IsHexDigit(compact[i]) && Uri.IsHexDigit(compact[i + 1]))
            {
                values.Add(Convert.ToByte(compact.Substring(i, 2), 16));
                any.Add(false);
            }
            else
            {
                error = $"\"{compact.Substring(i, 2)}\" is not a hex byte or ??";
                return false;
            }
        }

        pattern = new HexPattern([.. values], [.. any], offset);
        return true;
    }

    public bool IsMatch(ReadOnlySpan<byte> data)
    {
        if (data.Length < Offset + _values.Length) return false;
        for (int i = 0; i < _values.Length; i++)
            if (!_any[i] && data[Offset + i] != _values[i]) return false;
        return true;
    }

    /// <summary>Removes spaces, tabs, line breaks, ':', ',', '-' and '_' between bytes.</summary>
    internal static string StripSeparators(string text)
    {
        var sb = new StringBuilder(text.Length);
        foreach (var c in text)
            if (!char.IsWhiteSpace(c) && c is not (':' or ',' or '-' or '_'))
                sb.Append(c);
        return sb.ToString();
    }
}

public static class HexBytes
{
    /// <summary>Parses <c>"03 00 00 13"</c>, <c>"0300 0013"</c> or <c>"03:00:00:13"</c>.</summary>
    public static bool TryParse(string text, out byte[] bytes, out string error)
    {
        bytes = [];
        error = "";
        var compact = HexPattern.StripSeparators(text);
        if (compact.Length == 0) { error = "the hex string is empty"; return false; }
        if (compact.Length % 2 != 0) { error = "the hex string has an odd number of digits"; return false; }
        foreach (var c in compact)
        {
            if (!Uri.IsHexDigit(c)) { error = $"'{c}' is not a hex digit"; return false; }
        }
        bytes = Convert.FromHexString(compact);
        return true;
    }
}
