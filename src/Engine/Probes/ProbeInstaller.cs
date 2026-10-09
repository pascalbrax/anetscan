using System.Text;
using System.Text.RegularExpressions;
using ANetworkScanner.Engine.Settings;

namespace ANetworkScanner.Engine.Probes;

/// <summary>Adds, creates and removes the user's own probe files.</summary>
public static class ProbeInstaller
{
    /// <summary>%LocalAppData%\A Network Scanner\probes</summary>
    public static string UserDirectory => Path.Combine(SettingsStore.DefaultDirectory, "probes");

    /// <summary>A starter file that already loads cleanly; the comments explain each part.</summary>
    public static string Template(string id) => $$"""
        {
          // A Network Scanner probe. Save the file in this folder and press "Reload" in the Probes window.
          "schema": 1,
          "id": "{{id}}",
          "title": "My probe",
          "description": "What this probe checks",

          // TCP by default; use "transport": "udp" for UDP services (they need a send step).
          "ports": [8080],

          "steps": [
            // Payloads: plain text with JSON escapes, or exact bytes as hex. Mix them in an array:
            //   { "send": [ { "text": "HELLO " }, { "var": "ip" }, { "hex": "0D 0A" } ] }
            { "send": "HELLO\r\n" },
            { "read": { "timeoutMs": 1500, "maxBytes": 512, "until": { "text": "\n" } } }
          ],

          "match": [
            // The first rule that matches wins. Named groups become {placeholders} in short and long.
            { "regex": "^(?<banner>[^\\r\\n]+)", "short": "{banner}", "long": "Banner : {banner}" }
            // Binary replies: { "hex": "03 00 ?? ?? D0", "short": "binary hit" }
          ],

          "fallback": { "short": "open" }
        }
        """;

    /// <summary>The first free id of the form <c>my-probe</c>, <c>my-probe-2</c>, …</summary>
    public static string NewId(IEnumerable<string> existingIds)
    {
        var taken = existingIds.ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (!taken.Contains("my-probe")) return "my-probe";
        for (int i = 2; ; i++)
            if (!taken.Contains($"my-probe-{i}")) return $"my-probe-{i}";
    }

    public static string FileNameFor(string id) => id + ".json";

    /// <summary>Writes the probe as <c>{id}.json</c> in <paramref name="directory"/> and returns its path.</summary>
    /// <exception cref="IOException">The file exists and <paramref name="overwrite"/> is false.</exception>
    public static string Save(string json, string id, string directory, bool overwrite)
    {
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, FileNameFor(id));
        if (File.Exists(path) && !overwrite) throw new IOException($"{FileNameFor(id)} already exists.");
        File.WriteAllText(path, json, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        return path;
    }

    /// <summary>Creates a new probe from the template and returns its path.</summary>
    public static string CreateFromTemplate(string directory, IEnumerable<string> existingIds)
    {
        var id = NewId(existingIds);
        return Save(Template(id), id, directory, overwrite: false);
    }

    /// <summary>
    /// Deletes a probe file, but only if it lives directly inside <paramref name="directory"/>: the panel can
    /// never remove a built-in probe or a file elsewhere on disk.
    /// </summary>
    public static bool Delete(string path, string directory)
    {
        var full = Path.GetFullPath(path);
        var folder = Path.GetFullPath(directory).TrimEnd(Path.DirectorySeparatorChar);
        if (!string.Equals(Path.GetDirectoryName(full), folder, StringComparison.OrdinalIgnoreCase)) return false;
        if (!full.EndsWith(".json", StringComparison.OrdinalIgnoreCase) || !File.Exists(full)) return false;
        File.Delete(full);
        return true;
    }

    /// <summary>An id turned into a safe file name stem (ids are already restricted, but imports may differ).</summary>
    public static bool IsSafeId(string id) => Regex.IsMatch(id, "^[a-z0-9][a-z0-9_-]{0,39}$");
}
