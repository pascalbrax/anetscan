using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ANetworkScanner.Engine.Probes;

/// <summary>A problem found in a probe file. The file is skipped; the rest of the scan is unaffected.</summary>
public sealed record ProbeProblem(string File, string Message, string? FullPath = null)
{
    public override string ToString() => $"{File}: {Message}";
}

public sealed record ProbeLoadResult(IReadOnlyList<ProbeDefinition> Probes, IReadOnlyList<ProbeProblem> Problems);

/// <summary>
/// Reads probe definitions (JSON only) and validates them strictly: unknown properties, bad hex, bad regexes
/// and out-of-range numbers are all reported with the path of the offending value, so a typo never silently
/// disables a check.
/// </summary>
public static class ProbeLoader
{
    public const int SupportedSchema = 1;
    private const int MaxPayloadBytes = 16 * 1024;
    private const int MaxSteps = 16;
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(250);

    /// <summary>
    /// Loads every <c>*.json</c> file of the given directories. The first directory holds the built-in probes;
    /// every later one is a user folder, and a probe there replaces an earlier one with the same id.
    /// </summary>
    public static ProbeLoadResult LoadDirectories(params string[] directories)
    {
        var byId = new Dictionary<string, ProbeDefinition>(StringComparer.OrdinalIgnoreCase);
        var order = new List<string>();
        var problems = new List<ProbeProblem>();

        for (int index = 0; index < directories.Length; index++)
        {
            var dir = directories[index];
            bool isUser = index > 0;
            if (!Directory.Exists(dir)) continue;

            foreach (var file in Directory.EnumerateFiles(dir, "*.json").Order(StringComparer.OrdinalIgnoreCase))
            {
                string text;
                try { text = File.ReadAllText(file, Encoding.UTF8); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    problems.Add(new ProbeProblem(Path.GetFileName(file), $"cannot read file: {ex.Message}", file));
                    continue;
                }

                var one = LoadFromJson(text, Path.GetFileName(file));
                problems.AddRange(one.Problems.Select(p => p with { FullPath = file }));
                foreach (var probe in one.Probes)
                {
                    bool replaces = byId.TryGetValue(probe.Id, out var previous);
                    if (!replaces) order.Add(probe.Id);
                    byId[probe.Id] = probe with
                    {
                        SourcePath = file,
                        IsUser = isUser,
                        OverridesBuiltIn = replaces && !previous!.IsUser,
                    };
                }
            }
        }

        return new ProbeLoadResult([.. order.Select(id => byId[id])], problems);
    }

    public static ProbeLoadResult LoadFromJson(string json, string fileName)
    {
        var problems = new List<ProbeProblem>();
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(json, new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true,
            });
        }
        catch (JsonException ex)
        {
            problems.Add(new ProbeProblem(fileName, $"invalid JSON: {ex.Message}"));
            return new ProbeLoadResult([], problems);
        }

        using (doc)
        {
            var errors = new List<string>();
            var probe = Parse(doc.RootElement, fileName, errors);
            problems.AddRange(errors.Select(e => new ProbeProblem(fileName, e)));
            return new ProbeLoadResult(errors.Count == 0 && probe is not null ? [probe] : [], problems);
        }
    }

    // ── Parsing ──────────────────────────────────────────────────────────────

    private static ProbeDefinition? Parse(JsonElement root, string fileName, List<string> errors)
    {
        if (root.ValueKind != JsonValueKind.Object)
        {
            errors.Add("the file must contain one JSON object");
            return null;
        }

        CheckKeys(root, "", ["schema", "id", "title", "description", "transport", "ports", "connectTimeoutMs",
            "steps", "extract", "match", "fallback"], errors);

        if (TryGet(root, "schema", out var schemaEl) && !(schemaEl.ValueKind == JsonValueKind.Number &&
            schemaEl.TryGetInt32(out var schema) && schema == SupportedSchema))
            errors.Add($"schema: only version {SupportedSchema} is supported");

        string id = GetString(root, "id", "id", errors, required: true) ?? "";
        if (id.Length > 0 && !Regex.IsMatch(id, "^[a-z0-9][a-z0-9_-]{0,39}$"))
            errors.Add("id: use 1-40 lowercase letters, digits, '-' or '_'");

        string title = GetString(root, "title", "title", errors, required: false) ?? id.ToUpperInvariant();
        string description = GetString(root, "description", "description", errors, required: false) ?? "";

        var transport = ProbeTransport.Tcp;
        var transportText = GetString(root, "transport", "transport", errors, required: false);
        if (transportText is not null)
        {
            if (transportText.Equals("tcp", StringComparison.OrdinalIgnoreCase)) transport = ProbeTransport.Tcp;
            else if (transportText.Equals("udp", StringComparison.OrdinalIgnoreCase)) transport = ProbeTransport.Udp;
            else errors.Add("transport: must be \"tcp\" or \"udp\"");
        }

        var ports = ParsePorts(root, errors, transport);
        int connectTimeout = GetInt(root, "connectTimeoutMs", "connectTimeoutMs", 100, 30_000, 1500, errors);
        var steps = ParseSteps(root, errors);
        var extract = ParseExtract(root, errors);
        var match = ParseMatch(root, errors);

        string fallbackShort = "open";
        string? fallbackLong = null;
        var fallbackLevel = ProbeLevel.Info;
        if (TryGet(root, "fallback", out var fb))
        {
            if (fb.ValueKind != JsonValueKind.Object) errors.Add("fallback: must be an object");
            else
            {
                CheckKeys(fb, "fallback.", ["short", "long", "level"], errors);
                fallbackLevel = GetLevel(fb, "fallback.level", errors);
                fallbackShort = GetString(fb, "short", "fallback.short", errors, required: false) ?? "open";
                fallbackLong = GetString(fb, "long", "fallback.long", errors, required: false);
            }
        }

        if (transport == ProbeTransport.Udp && !steps.OfType<SendStep>().Any())
            errors.Add("steps: a UDP probe needs a send step (UDP services only answer a request)");

        if (errors.Count > 0) return null;
        return new ProbeDefinition(id, title, description, transport, ports, connectTimeout, steps, extract, match,
            fallbackShort, fallbackLong, fileName)
        {
            FallbackLevel = fallbackLevel,
        };
    }

    private static List<PortSpec> ParsePorts(JsonElement root, List<string> errors, ProbeTransport transport)
    {
        var ports = new List<PortSpec>();
        if (!TryGet(root, "ports", out var el) || el.ValueKind != JsonValueKind.Array || el.GetArrayLength() == 0)
        {
            errors.Add("ports: a non-empty array is required");
            return ports;
        }
        if (el.GetArrayLength() > 32) errors.Add("ports: at most 32 ports per probe");

        int index = 0;
        foreach (var item in el.EnumerateArray())
        {
            string path = $"ports[{index++}]";
            int port = 0;
            bool tls = false;

            if (item.ValueKind == JsonValueKind.Number && item.TryGetInt32(out port)) { }
            else if (item.ValueKind == JsonValueKind.Object)
            {
                CheckKeys(item, path + ".", ["port", "tls"], errors);
                port = GetInt(item, "port", path + ".port", 1, 65535, -1, errors);
                if (TryGet(item, "tls", out var tlsEl))
                {
                    if (tlsEl.ValueKind is JsonValueKind.True or JsonValueKind.False) tls = tlsEl.GetBoolean();
                    else errors.Add($"{path}.tls: must be true or false");
                }
            }
            else
            {
                errors.Add($"{path}: must be a port number or an object like {{\"port\": 443, \"tls\": true}}");
                continue;
            }

            if (port is < 1 or > 65535)
            {
                if (port != -1) errors.Add($"{path}: port must be 1-65535");
                continue;
            }
            if (tls && transport == ProbeTransport.Udp) errors.Add($"{path}.tls: TLS needs tcp");
            if (ports.Any(p => p.Port == port)) errors.Add($"{path}: port {port} is listed twice");
            ports.Add(new PortSpec(port, tls));
        }
        return ports;
    }

    private static List<ProbeStep> ParseSteps(JsonElement root, List<string> errors)
    {
        var steps = new List<ProbeStep>();
        if (!TryGet(root, "steps", out var el)) return steps;
        if (el.ValueKind != JsonValueKind.Array) { errors.Add("steps: must be an array"); return steps; }
        if (el.GetArrayLength() > MaxSteps) errors.Add($"steps: at most {MaxSteps} steps");

        int index = 0;
        foreach (var item in el.EnumerateArray())
        {
            string path = $"steps[{index++}]";
            if (item.ValueKind != JsonValueKind.Object) { errors.Add($"{path}: must be an object"); continue; }
            CheckKeys(item, path + ".", ["send", "read"], errors);

            bool hasSend = TryGet(item, "send", out var send);
            bool hasRead = TryGet(item, "read", out var read);
            if (hasSend == hasRead) { errors.Add($"{path}: needs exactly one of \"send\" or \"read\""); continue; }

            if (hasSend)
            {
                var parts = ParsePayload(send, path + ".send", errors);
                if (parts is not null) steps.Add(new SendStep(parts));
            }
            else
            {
                steps.Add(ParseRead(read, path + ".read", errors));
            }
        }
        return steps;
    }

    private static ReadStep ParseRead(JsonElement read, string path, List<string> errors)
    {
        if (read.ValueKind != JsonValueKind.Object)
        {
            errors.Add($"{path}: must be an object");
            return new ReadStep(1000, 1024, null);
        }
        CheckKeys(read, path + ".", ["timeoutMs", "maxBytes", "until"], errors);
        int timeout = GetInt(read, "timeoutMs", path + ".timeoutMs", 50, 30_000, 1500, errors);
        int maxBytes = GetInt(read, "maxBytes", path + ".maxBytes", 1, 65_536, 1024, errors);

        byte[]? until = null;
        if (TryGet(read, "until", out var untilEl))
        {
            var parts = ParsePayload(untilEl, path + ".until", errors);
            if (parts is not null)
            {
                if (parts.Any(p => p is VarPart)) errors.Add($"{path}.until: variables are not allowed here");
                else until = [.. parts.SelectMany(p => p switch { TextPart t => Encoding.Latin1.GetBytes(t.Text), HexPart h => h.Bytes, _ => [] })];
            }
        }
        return new ReadStep(timeout, maxBytes, until);
    }

    /// <summary>
    /// A payload is a string (text), an object <c>{"text":..}</c> / <c>{"hex":..}</c> / <c>{"var":..}</c>,
    /// or an array mixing those, sent in order.
    /// </summary>
    private static List<PayloadPart>? ParsePayload(JsonElement el, string path, List<string> errors)
    {
        var parts = new List<PayloadPart>();
        int errorsBefore = errors.Count;

        void AddPart(JsonElement part, string partPath)
        {
            if (part.ValueKind == JsonValueKind.String)
            {
                AddText(part.GetString()!, partPath);
                return;
            }
            if (part.ValueKind != JsonValueKind.Object)
            {
                errors.Add($"{partPath}: must be a string or an object with text, hex or var");
                return;
            }
            CheckKeys(part, partPath + ".", ["text", "hex", "var"], errors);
            int kinds = new[] { "text", "hex", "var" }.Count(k => TryGet(part, k, out _));
            if (kinds != 1) { errors.Add($"{partPath}: needs exactly one of text, hex or var"); return; }

            if (TryGet(part, "text", out _))
            {
                var text = GetString(part, "text", partPath + ".text", errors, required: true);
                if (text is not null) AddText(text, partPath + ".text");
            }
            else if (TryGet(part, "hex", out _))
            {
                var hex = GetString(part, "hex", partPath + ".hex", errors, required: true);
                if (hex is null) return;
                if (HexBytes.TryParse(hex, out var bytes, out var error)) parts.Add(new HexPart(bytes));
                else errors.Add($"{partPath}.hex: {error}");
            }
            else
            {
                var name = GetString(part, "var", partPath + ".var", errors, required: true);
                if (name is null) return;
                if (name is "ip" or "port" or "uuid") parts.Add(new VarPart(name));
                else errors.Add($"{partPath}.var: only \"ip\", \"port\" and \"uuid\" are available");
            }
        }

        void AddText(string text, string textPath)
        {
            if (text.Any(c => c > 0xFF))
                errors.Add($"{textPath}: text is sent as single bytes; use a hex part for characters above U+00FF");
            else parts.Add(new TextPart(text));
        }

        if (el.ValueKind == JsonValueKind.Array)
        {
            int i = 0;
            foreach (var part in el.EnumerateArray()) AddPart(part, $"{path}[{i++}]");
        }
        else AddPart(el, path);

        if (errors.Count > errorsBefore) return null;
        long size = parts.Sum(p => p switch { TextPart t => t.Text.Length, HexPart h => h.Bytes.Length, _ => 5 });
        if (size == 0) { errors.Add($"{path}: the payload is empty"); return null; }
        if (size > MaxPayloadBytes) { errors.Add($"{path}: payload is larger than {MaxPayloadBytes} bytes"); return null; }
        return parts;
    }

    private static List<ExtractRule> ParseExtract(JsonElement root, List<string> errors)
    {
        var rules = new List<ExtractRule>();
        if (!TryGet(root, "extract", out var el)) return rules;
        if (el.ValueKind != JsonValueKind.Array) { errors.Add("extract: must be an array"); return rules; }

        int index = 0;
        foreach (var item in el.EnumerateArray())
        {
            string path = $"extract[{index++}]";
            if (item.ValueKind != JsonValueKind.Object) { errors.Add($"{path}: must be an object"); continue; }
            CheckKeys(item, path + ".", ["regex", "decode"], errors);
            var regex = CompileRegex(item, path + ".regex", errors);

            bool urlDecode = false;
            var decode = GetString(item, "decode", path + ".decode", errors, required: false);
            if (decode is not null)
            {
                if (decode.Equals("url", StringComparison.OrdinalIgnoreCase)) urlDecode = true;
                else errors.Add($"{path}.decode: only \"url\" is supported");
            }
            if (regex is not null) rules.Add(new ExtractRule(regex, urlDecode));
        }
        return rules;
    }

    private static List<MatchRule> ParseMatch(JsonElement root, List<string> errors)
    {
        var rules = new List<MatchRule>();
        if (!TryGet(root, "match", out var el)) return rules;
        if (el.ValueKind != JsonValueKind.Array) { errors.Add("match: must be an array"); return rules; }

        int index = 0;
        foreach (var item in el.EnumerateArray())
        {
            string path = $"match[{index++}]";
            if (item.ValueKind != JsonValueKind.Object) { errors.Add($"{path}: must be an object"); continue; }
            CheckKeys(item, path + ".", ["regex", "hex", "offset", "short", "long", "level"], errors);

            bool hasRegex = TryGet(item, "regex", out _);
            bool hasHex = TryGet(item, "hex", out _);
            if (hasRegex == hasHex) { errors.Add($"{path}: needs exactly one of \"regex\" or \"hex\""); continue; }
            if (hasRegex && TryGet(item, "offset", out _)) errors.Add($"{path}.offset: only applies to hex patterns");

            Regex? regex = null;
            HexPattern? hex = null;
            if (hasRegex) regex = CompileRegex(item, path + ".regex", errors);
            else
            {
                var text = GetString(item, "hex", path + ".hex", errors, required: true);
                int offset = GetInt(item, "offset", path + ".offset", 0, 4096, 0, errors);
                if (text is not null)
                {
                    if (HexPattern.TryParse(text, offset, out var pattern, out var error)) hex = pattern;
                    else errors.Add($"{path}.hex: {error}");
                }
            }

            var shortText = GetString(item, "short", path + ".short", errors, required: false);
            var longText = GetString(item, "long", path + ".long", errors, required: false);
            var level = GetLevel(item, path + ".level", errors);
            if (regex is not null || hex is not null)
                rules.Add(new MatchRule(regex, hex, shortText, longText, level));
        }
        return rules;
    }

    // ── Helpers ───

    private static ProbeLevel GetLevel(JsonElement obj, string path, List<string> errors)
    {
        var name = obj.TryGetProperty("level", out _) ? GetString(obj, "level", path, errors, required: false) : null;
        switch (name?.ToLowerInvariant())
        {
            case null: return ProbeLevel.Info;
            case "info": return ProbeLevel.Info;
            case "good": return ProbeLevel.Good;
            case "warning" or "warn": return ProbeLevel.Warning;
            case "bad": return ProbeLevel.Bad;
            default:
                errors.Add($"{path}: must be \"info\", \"good\", \"warning\" or \"bad\"");
                return ProbeLevel.Info;
        }
    }

    private static Regex? CompileRegex(JsonElement owner, string path, List<string> errors)
    {
        var pattern = GetString(owner, "regex", path, errors, required: true);
        if (pattern is null) return null;
        try
        {
            return new Regex(pattern, RegexOptions.CultureInvariant, RegexTimeout);
        }
        catch (ArgumentException ex)
        {
            errors.Add($"{path}: invalid regular expression ({ex.Message})");
            return null;
        }
    }

    private static bool TryGet(JsonElement obj, string name, out JsonElement value)
    {
        foreach (var property in obj.EnumerateObject())
        {
            if (property.NameEquals(name))
            {
                value = property.Value;
                return true;
            }
        }
        value = default;
        return false;
    }

    private static void CheckKeys(JsonElement obj, string pathPrefix, string[] allowed, List<string> errors)
    {
        foreach (var property in obj.EnumerateObject())
            if (!allowed.Contains(property.Name))
                errors.Add($"{pathPrefix}{property.Name}: unknown property (allowed: {string.Join(", ", allowed)})");
    }

    private static string? GetString(JsonElement obj, string name, string path, List<string> errors, bool required)
    {
        if (!TryGet(obj, name, out var el))
        {
            if (required) errors.Add($"{path}: required");
            return null;
        }
        if (el.ValueKind != JsonValueKind.String)
        {
            errors.Add($"{path}: must be a string");
            return null;
        }
        return el.GetString();
    }

    /// <returns><paramref name="fallback"/> when the property is absent; -1 is only used as a sentinel for "invalid".</returns>
    private static int GetInt(JsonElement obj, string name, string path, int min, int max, int fallback, List<string> errors)
    {
        if (!TryGet(obj, name, out var el))
        {
            if (fallback == -1) errors.Add($"{path}: required");
            return fallback;
        }
        if (el.ValueKind != JsonValueKind.Number || !el.TryGetInt32(out var value) || value < min || value > max)
        {
            errors.Add($"{path}: must be a whole number from {min} to {max}");
            return fallback;
        }
        return value;
    }
}
