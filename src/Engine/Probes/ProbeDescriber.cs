using System.Text;

namespace ANetworkScanner.Engine.Probes;

/// <summary>Plain-language descriptions of a probe, for the management panel.</summary>
public static class ProbeDescriber
{
    private const int PreviewBytes = 40;

    /// <summary><c>22</c>, <c>80, 8080, 443 TLS</c>, <c>UDP 161</c>.</summary>
    public static string PortsSummary(ProbeDefinition probe)
    {
        var ports = string.Join(", ", probe.Ports.Select(p => p.Port + (p.Tls ? " TLS" : "")));
        return probe.Transport == ProbeTransport.Udp ? $"UDP {ports}" : ports;
    }

    /// <summary>One line per step: what is sent and what is read.</summary>
    public static IReadOnlyList<string> DescribeSteps(ProbeDefinition probe)
    {
        var lines = new List<string>();
        lines.Add(probe.Transport == ProbeTransport.Tcp
            ? $"Connect ({PortsSummary(probe)}), give up after {probe.ConnectTimeoutMs} ms"
            : $"Open a UDP socket to port {string.Join(", ", probe.Ports.Select(x => x.Port))}");

        foreach (var step in probe.Steps)
        {
            switch (step)
            {
                case SendStep send:
                    lines.Add($"Send {PayloadSize(send)}{(send.Parts.Any(x => x is VarPart) ? "+" : "")} bytes: {Preview(send)}");
                    break;
                case ReadStep read:
                    var until = read.Until is null ? "" : $", until {Quote(read.Until)}";
                    lines.Add($"Read up to {read.MaxBytes} bytes, wait {read.TimeoutMs} ms{until}");
                    break;
            }
        }

        if (!probe.Steps.OfType<ReadStep>().Any() && probe.Transport == ProbeTransport.Tcp)
            lines.Add("Nothing is sent or read: the result only says whether the port is open");
        return lines;
    }

    /// <summary>One line per extract and match rule, in the order they are tried.</summary>
    public static IReadOnlyList<string> DescribeMatches(ProbeDefinition probe)
    {
        var lines = new List<string>();
        foreach (var extract in probe.Extract)
            lines.Add($"Extract  /{extract.Regex}/");

        int number = 1;
        foreach (var rule in probe.Match)
        {
            var test = rule.Hex is not null
                ? $"bytes {rule.Hex}" + (rule.Hex.Offset > 0 ? $" at offset {rule.Hex.Offset}" : "")
                : $"/{rule.Regex}/";
            var shows = rule.Short is null ? "" : $"  →  \"{rule.Short}\"";
            lines.Add($"{number++}. If the reply matches {test}{shows}");
        }

        lines.Add($"Otherwise: \"{probe.FallbackShort}\"");
        return lines;
    }

    private static long PayloadSize(SendStep send) =>
        send.Parts.Sum(p => p switch { TextPart t => (long)t.Text.Length, HexPart h => h.Bytes.Length, _ => 0 });

    private static string Preview(SendStep send)
    {
        // Each part is shortened on its own, so a long XML text never hides the {variables} that follow it.
        const int MaxParts = 8, MaxHexBytes = 32;
        var pieces = new List<string>();

        foreach (var part in send.Parts.Take(MaxParts))
        {
            switch (part)
            {
                case TextPart t:
                    bool cut = t.Text.Length > PreviewBytes;
                    pieces.Add("\"" + Escape(cut ? t.Text[..PreviewBytes] : t.Text) + (cut ? "…\"" : "\""));
                    break;
                case HexPart h:
                    var take = Math.Min(h.Bytes.Length, MaxHexBytes);
                    var hex = string.Join(' ', h.Bytes.Take(take).Select(x => x.ToString("X2")));
                    pieces.Add("<" + hex + (take < h.Bytes.Length ? " …" : "") + ">");
                    break;
                case VarPart v:
                    pieces.Add("{" + v.Name + "}");
                    break;
            }
        }
        if (send.Parts.Count > MaxParts) pieces.Add("…");
        return string.Join(' ', pieces);
    }

    private static string Quote(byte[] bytes) =>
        bytes.All(b => b is >= 0x20 and < 0x7F or (byte)'\r' or (byte)'\n' or (byte)'\t')
            ? "\"" + Escape(Encoding.Latin1.GetString(bytes)) + "\""
            : "<" + Convert.ToHexString(bytes).Chunk(2).Select(c => new string(c)).Aggregate((a, b) => a + " " + b) + ">";

    private static string Escape(string text)
    {
        var sb = new StringBuilder(text.Length);
        foreach (var c in text)
        {
            switch (c)
            {
                case '\r': sb.Append("\\r"); break;
                case '\n': sb.Append("\\n"); break;
                case '\t': sb.Append("\\t"); break;
                case < ' ' or > '~': sb.Append($"\\x{(int)c:X2}"); break;
                default: sb.Append(c); break;
            }
        }
        return sb.ToString();
    }
}
