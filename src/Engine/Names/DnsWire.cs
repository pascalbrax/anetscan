using System.Net;
using System.Text;

namespace ANetworkScanner.Engine.Names;

/// <summary>
/// The little of the DNS wire format a hostname lookup needs: build a reverse (PTR) query, and read the answer.
/// The same format is used by classic DNS (port 53) and multicast DNS (port 5353).
/// </summary>
public static class DnsWire
{
    private const int HeaderSize = 12;
    private const int MaxNameLength = 255;
    private const ushort TypePtr = 12;

    /// <summary>The query for "which name belongs to this address?" (the name <c>4.3.2.1.in-addr.arpa</c>).</summary>
    /// <param name="recursionDesired">True for a normal DNS server; false for mDNS.</param>
    /// <param name="unicastResponse">The mDNS "QU" bit: ask the host to answer us directly, not the multicast group.</param>
    public static byte[] BuildPtrQuery(IPAddress address, ushort id, bool recursionDesired, bool unicastResponse = false)
    {
        var octets = address.GetAddressBytes();
        using var ms = new MemoryStream();

        WriteUInt16(ms, id);
        WriteUInt16(ms, recursionDesired ? (ushort)0x0100 : (ushort)0);
        WriteUInt16(ms, 1); // one question
        WriteUInt16(ms, 0);
        WriteUInt16(ms, 0);
        WriteUInt16(ms, 0);

        for (int i = octets.Length - 1; i >= 0; i--)
        {
            var label = octets[i].ToString();
            ms.WriteByte((byte)label.Length);
            ms.Write(Encoding.ASCII.GetBytes(label));
        }
        foreach (var label in new[] { "in-addr", "arpa" })
        {
            ms.WriteByte((byte)label.Length);
            ms.Write(Encoding.ASCII.GetBytes(label));
        }
        ms.WriteByte(0);

        WriteUInt16(ms, TypePtr);
        WriteUInt16(ms, unicastResponse ? (ushort)0x8001 : (ushort)1);
        return ms.ToArray();
    }

    public enum ResponseKind
    {
        /// <summary>Not a well-formed answer to our question (wrong id, truncated, not a response).</summary>
        Invalid,
        /// <summary>A real answer carrying a name.</summary>
        Name,
        /// <summary>A real answer saying there is no name (NXDOMAIN, or nothing useful in it).</summary>
        NoName,
    }

    /// <summary>Reads the first PTR answer. <paramref name="expectedId"/> null accepts any id (multicast answers carry id 0).</summary>
    public static ResponseKind ParsePtrResponse(ReadOnlySpan<byte> message, ushort? expectedId, out string? name)
    {
        name = null;
        if (message.Length < HeaderSize) return ResponseKind.Invalid;

        ushort id = ReadUInt16(message, 0);
        ushort flags = ReadUInt16(message, 2);
        if (expectedId is { } want && id != want) return ResponseKind.Invalid;
        if ((flags & 0x8000) == 0) return ResponseKind.Invalid; // a query, not a response

        int questions = ReadUInt16(message, 4);
        int answers = ReadUInt16(message, 6);
        if ((flags & 0x000F) != 0) return ResponseKind.NoName; // NXDOMAIN, SERVFAIL, ...

        int pos = HeaderSize;
        for (int q = 0; q < questions; q++)
        {
            if (!SkipName(message, ref pos) || pos + 4 > message.Length) return ResponseKind.Invalid;
            pos += 4;
        }

        for (int a = 0; a < answers; a++)
        {
            if (!SkipName(message, ref pos) || pos + 10 > message.Length) return ResponseKind.Invalid;
            ushort type = ReadUInt16(message, pos);
            int rdLength = ReadUInt16(message, pos + 8);
            int rdStart = pos + 10;
            if (rdStart + rdLength > message.Length) return ResponseKind.Invalid;

            if (type == TypePtr)
            {
                int cursor = rdStart;
                var text = ReadName(message, ref cursor);
                if (text is not null)
                {
                    name = text;
                    return ResponseKind.Name;
                }
            }
            pos = rdStart + rdLength;
        }
        return ResponseKind.NoName;
    }

    // ── Names ────────────────────────────────────────────────────────────────

    /// <summary>Reads a possibly compressed domain name and advances <paramref name="pos"/> past its first encoding.</summary>
    public static string? ReadName(ReadOnlySpan<byte> message, ref int pos)
    {
        var labels = new List<string>();
        int cursor = pos;
        int? resume = null;
        int total = 0;

        for (int hops = 0; hops < 64; hops++)
        {
            if (cursor >= message.Length) return null;
            int length = message[cursor];

            if (length == 0)
            {
                pos = resume ?? cursor + 1;
                return string.Join('.', labels);
            }

            if ((length & 0xC0) == 0xC0) // compression pointer
            {
                if (cursor + 1 >= message.Length) return null;
                resume ??= cursor + 2;
                cursor = ((length & 0x3F) << 8) | message[cursor + 1];
                continue;
            }

            if ((length & 0xC0) != 0 || cursor + 1 + length > message.Length) return null;
            total += length + 1;
            if (total > MaxNameLength) return null;
            labels.Add(Encoding.UTF8.GetString(message.Slice(cursor + 1, length)));
            cursor += 1 + length;
        }
        return null; // pointer loop
    }

    private static bool SkipName(ReadOnlySpan<byte> message, ref int pos)
    {
        while (true)
        {
            if (pos >= message.Length) return false;
            int length = message[pos];
            if (length == 0) { pos++; return true; }
            if ((length & 0xC0) == 0xC0) { pos += 2; return pos <= message.Length; }
            pos += 1 + length;
        }
    }

    private static void WriteUInt16(Stream s, ushort value)
    {
        s.WriteByte((byte)(value >> 8));
        s.WriteByte((byte)value);
    }

    private static ushort ReadUInt16(ReadOnlySpan<byte> data, int offset) => (ushort)((data[offset] << 8) | data[offset + 1]);
}
