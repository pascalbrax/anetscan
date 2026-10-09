using System.Globalization;
using System.Text;
using System.Text.Json;
using ANetworkScanner.App.ViewModels;

namespace ANetworkScanner.App.Services;

/// <summary>Turns result rows into CSV or JSON text.</summary>
public static class Exporter
{
    public static string ToCsv(IReadOnlyList<HostRow> rows)
    {
        var probeTitles = ProbeTitles(rows);
        var sb = new StringBuilder();
        sb.AppendLine(string.Join(',', new[] { "ip", "hostname", "found_by", "rtt_ms", "ttl", "mac", "vendor" }.Concat(probeTitles).Select(Quote)));

        foreach (var row in rows)
        {
            var fields = new List<string>
            {
                row.Address,
                row.Name,
                row.MethodText,
                row.RttMs < 0 ? "" : row.RttMs.ToString("0.##", CultureInfo.InvariantCulture),
                row.Ttl > 0 ? row.Ttl.ToString(CultureInfo.InvariantCulture) : "",
                row.Mac,
                row.Vendor,
            };
            fields.AddRange(probeTitles.Select(t => row.Cells.FirstOrDefault(c => c.Title == t) is { IsOpen: true } c ? c.Text : ""));
            sb.AppendLine(string.Join(',', fields.Select(Quote)));
        }
        return sb.ToString();
    }

    public static string ToJson(IReadOnlyList<HostRow> rows)
    {
        var hosts = rows.Select(r => new Dictionary<string, object?>
        {
            ["ip"] = r.Address,
            ["hostname"] = r.Name.Length > 0 ? r.Name : null,
            ["hostnameSource"] = r.NameSourceText.Length > 0 ? r.NameSourceText : null,
            ["foundBy"] = r.MethodText,
            ["rttMs"] = r.RttMs < 0 ? null : Math.Round(r.RttMs, 2),
            ["ttl"] = r.Ttl > 0 ? r.Ttl : null,
            ["mac"] = r.Mac.Length > 0 ? r.Mac : null,
            ["vendor"] = r.Vendor.Length > 0 ? r.Vendor : null,
            ["services"] = r.Cells.Where(c => c.IsOpen).ToDictionary(
                c => c.Title,
                c => (object)new { summary = c.Text, ports = c.OpenPorts, details = c.Detail }),
        });
        return JsonSerializer.Serialize(new { generated = DateTime.Now.ToString("s", CultureInfo.InvariantCulture), hosts },
            new JsonSerializerOptions { WriteIndented = true });
    }

    private static List<string> ProbeTitles(IReadOnlyList<HostRow> rows) =>
        [.. rows.SelectMany(r => r.Cells.Select(c => c.Title)).Distinct()];

    /// <summary>Quotes a field, and defuses leading =, +, -, @ so a spreadsheet never runs a banner as a formula.</summary>
    private static string Quote(string value)
    {
        if (value.Length > 0 && value[0] is '=' or '+' or '@' || (value.Length > 1 && value[0] == '-' && !char.IsDigit(value[1])))
            value = "'" + value;
        return "\"" + value.Replace("\"", "\"\"") + "\"";
    }
}
