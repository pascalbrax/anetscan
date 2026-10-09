using System.Globalization;

namespace ANetworkScanner.Engine.Vendors;

/// <summary>
/// MAC address to manufacturer lookup, built from the IEEE OUI registry (<c>oui.txt</c>): the first three bytes
/// of a factory MAC identify the company that registered the block.
/// </summary>
public sealed class MacVendors
{
    private static readonly string[] Suffixes =
    [
        ", Inc.", " Inc.", ", Inc", " Inc", ", Ltd.", " Ltd.", ", Ltd", " Ltd", " Co.,Ltd.", " Co., Ltd.", " Co.,Ltd", " Co.,LTD.", " CO.,LTD.",
        " Co., Ltd", " Co. Ltd.", " Co.Ltd", " Corporation", " Corp.", " Corp", " GmbH", " LLC", " L.L.C.", " S.A.", " S.p.A.", " SpA",
        " AG", " B.V.", " BV", " Limited", " Company", " PLC", " plc", " S.r.l.", " Srl", " A/S", " AB", " Oy", " N.V.", " Pty Ltd", " Pte Ltd", " Co.", " Co",
    ];

    private readonly Dictionary<uint, string> _byOui;

    public static MacVendors Empty { get; } = new([]);

    private MacVendors(Dictionary<uint, string> byOui) => _byOui = byOui;

    public int Count => _byOui.Count;

    /// <summary>Reads <c>oui.txt</c>. Only the one-line "(hex)" records matter; address lines are skipped.</summary>
    public static MacVendors Load(TextReader reader)
    {
        var map = new Dictionary<uint, string>(45_000);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            // "28-6F-B9   (hex)\t\tNokia Shanghai Bell Co., Ltd."
            int marker = line.IndexOf("(hex)", StringComparison.Ordinal);
            if (marker < 8) continue;

            if (!TryParseOui(line.AsSpan(0, 8), out var oui)) continue;
            var name = line[(marker + 5)..].Trim();
            if (name.Length == 0 || name.Equals("Private", StringComparison.OrdinalIgnoreCase)) continue;
            map[oui] = name;
        }
        return new MacVendors(map);
    }

    public static MacVendors LoadFile(string path)
    {
        using var reader = new StreamReader(path);
        return Load(reader);
    }

    /// <summary>The registered company, or null when the prefix is unknown (or deliberately private).</summary>
    public string? Lookup(string? mac) =>
        TryParseMac(mac, out var oui) && _byOui.TryGetValue(oui, out var name) ? name : null;

    /// <summary>
    /// What to show next to a MAC: the company, <c>Private address</c> for a randomized (locally administered)
    /// address, or an empty string.
    /// </summary>
    public string Describe(string? mac, bool shorten = true)
    {
        if (DeviceClassifier.IsRandomizedMac(mac)) return "Private address";
        var name = Lookup(mac);
        return name is null ? "" : shorten ? Shorten(name) : name;
    }

    /// <summary>"Cisco Systems, Inc" becomes "Cisco Systems": the legal suffix is noise in a table.</summary>
    public static string Shorten(string name)
    {
        var shortened = name.Trim();
        bool changed = true;
        while (changed)
        {
            changed = false;
            foreach (var suffix in Suffixes)
            {
                if (shortened.Length > suffix.Length + 1 && shortened.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                {
                    shortened = shortened[..^suffix.Length].TrimEnd(' ', ',', '.');
                    changed = true;
                }
            }
        }
        return shortened.Length == 0 ? name.Trim() : shortened;
    }

    /// <summary>Accepts <c>AA:BB:CC:DD:EE:FF</c>, <c>aa-bb-cc-dd-ee-ff</c>, <c>aabb.ccdd.eeff</c> or <c>AABBCC</c> (at least 3 bytes).</summary>
    public static bool TryParseMac(string? mac, out uint oui)
    {
        oui = 0;
        if (string.IsNullOrEmpty(mac)) return false;

        Span<char> hex = stackalloc char[6];
        int count = 0;
        foreach (var c in mac)
        {
            if (c is ':' or '-' or '.' or ' ') continue;
            if (!Uri.IsHexDigit(c)) return false;
            if (count < 6) hex[count] = c;
            count++;
        }
        return count >= 6 && uint.TryParse(hex, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out oui);
    }

    private static bool TryParseOui(ReadOnlySpan<char> text, out uint oui)
    {
        oui = 0;
        // "28-6F-B9"
        if (text.Length != 8 || text[2] != '-' || text[5] != '-') return false;
        Span<char> hex = stackalloc char[6];
        text[..2].CopyTo(hex);
        text.Slice(3, 2).CopyTo(hex[2..]);
        text.Slice(6, 2).CopyTo(hex[4..]);
        return uint.TryParse(hex, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out oui);
    }
}
