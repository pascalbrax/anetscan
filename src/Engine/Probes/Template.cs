using System.Text;

namespace ANetworkScanner.Engine.Probes;

/// <summary>
/// Replaces <c>{name}</c> with a variable's value (empty when unknown); <c>{{</c> and <c>}}</c> are literal braces.
/// <c>{a|b|"text"}</c> gives the first of its parts that is not empty: a variable, or a quoted literal as the last resort.
/// A line whose placeholders are all empty is dropped, so optional details (a missing Server header, a plain
/// port without TLS) leave no blank "Server :" labels behind. Trailing spaces are trimmed.
/// </summary>
public static class Template
{
    public static string Render(string template, IReadOnlyDictionary<string, string> vars)
    {
        var lines = new List<string>();
        foreach (var raw in template.Split('\n'))
        {
            var line = RenderLine(raw.TrimEnd('\r'), vars, out int placeholders, out int filled);
            if (placeholders > 0 && filled == 0) continue;
            lines.Add(line.TrimEnd());
        }
        return string.Join("\n", lines).Trim();
    }

    private static string FirstNonEmpty(string spec, IReadOnlyDictionary<string, string> vars)
    {
        foreach (var raw in spec.Split('|'))
        {
            var part = raw.Trim();
            string value = part.Length >= 2 && part[0] == '"' && part[^1] == '"'
                ? part[1..^1]
                : vars.TryGetValue(part, out var found) ? found : "";
            if (value.Length > 0) return value;
        }
        return "";
    }

    private static string RenderLine(string template, IReadOnlyDictionary<string, string> vars, out int placeholders, out int filled)
    {
        placeholders = filled = 0;
        var sb = new StringBuilder(template.Length + 16);
        for (int i = 0; i < template.Length; i++)
        {
            char c = template[i];
            if (c == '{' && i + 1 < template.Length && template[i + 1] == '{') { sb.Append('{'); i++; }
            else if (c == '}' && i + 1 < template.Length && template[i + 1] == '}') { sb.Append('}'); i++; }
            else if (c == '{')
            {
                int end = template.IndexOf('}', i + 1);
                if (end < 0) { sb.Append(c); continue; }
                var spec = template.Substring(i + 1, end - i - 1);
                placeholders++;
                var value = FirstNonEmpty(spec, vars);
                if (value.Length > 0)
                {
                    sb.Append(value);
                    filled++;
                }
                i = end;
            }
            else sb.Append(c);
        }
        return sb.ToString();
    }
}
