using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace ANetworkScanner.Engine.Names;

public enum NameSource
{
    /// <summary>Reverse DNS: the name your DNS server has registered for the address.</summary>
    Dns,
    /// <summary>Multicast DNS: the name the device announces about itself (Apple, Linux/Avahi, printers).</summary>
    MDns,
    /// <summary>NetBIOS: the computer name a Windows machine reports.</summary>
    NetBios,
}

public sealed record HostName(string Name, NameSource Source)
{
    public string SourceText => Source switch
    {
        NameSource.Dns => "DNS",
        NameSource.MDns => "mDNS",
        _ => "NetBIOS",
    };
}

/// <summary>One way of asking "what is this host called?". Returns null when there is no answer.</summary>
public interface INameSource
{
    NameSource Kind { get; }

    Task<string?> QueryAsync(IPAddress address, int timeoutMs, CancellationToken cancellationToken);
}

/// <summary>Sends one datagram and waits for an answer that the caller accepts. Never blocks a thread.</summary>
internal static class UdpExchange
{
    public static async Task<byte[]?> RequestAsync(
        IPEndPoint remote, byte[] request, int timeoutMs, Func<byte[], bool> accept, CancellationToken cancellationToken)
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeoutMs);
        var buffer = new byte[2048];

        try
        {
            await socket.ConnectAsync(remote, cts.Token).ConfigureAwait(false);
            await socket.SendAsync(request, SocketFlags.None, cts.Token).ConfigureAwait(false);

            while (true)
            {
                int n = await socket.ReceiveAsync(buffer, SocketFlags.None, cts.Token).ConfigureAwait(false);
                var reply = buffer.AsSpan(0, n).ToArray();
                if (accept(reply)) return reply;
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return null; // timed out
        }
        catch (SocketException)
        {
            return null; // ICMP port unreachable or no route: nothing to learn here
        }
    }
}

/// <summary>Reverse DNS through the DNS servers of the active network adapters.</summary>
public sealed class DnsPtrSource : INameSource
{
    private readonly IReadOnlyList<IPEndPoint> _servers;

    public DnsPtrSource(IReadOnlyList<IPEndPoint>? servers = null) => _servers = servers ?? DefaultServers();

    public NameSource Kind => NameSource.Dns;

    public static IReadOnlyList<IPEndPoint> DefaultServers()
    {
        try
        {
            return [.. NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .SelectMany(n => n.GetIPProperties().DnsAddresses)
                .Where(a => a.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(a))
                .Distinct()
                .Take(3)
                .Select(a => new IPEndPoint(a, 53))];
        }
        catch (NetworkInformationException)
        {
            return [];
        }
    }

    /// <summary>Addresses that only mean something inside a local network: RFC 1918, link-local, loopback, CGNAT.</summary>
    public static bool IsPrivate(IPAddress address)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork) return false;
        var b = address.GetAddressBytes();
        return b[0] == 10
            || (b[0] == 172 && b[1] is >= 16 and <= 31)
            || (b[0] == 192 && b[1] == 168)
            || (b[0] == 169 && b[1] == 254)
            || b[0] == 127
            || (b[0] == 100 && b[1] is >= 64 and <= 127);
    }

    public async Task<string?> QueryAsync(IPAddress address, int timeoutMs, CancellationToken cancellationToken)
    {
        // A private address means nothing to a public resolver, and asking it would tell that provider about
        // hosts on this network: such lookups only go to DNS servers that are themselves on a private network.
        var servers = IsPrivate(address) ? _servers.Where(s => IsPrivate(s.Address)).ToList() : _servers.ToList();
        if (servers.Count == 0) return null;
        int perServer = Math.Max(200, timeoutMs / Math.Min(servers.Count, 2));

        foreach (var server in servers)
        {
            ushort id = (ushort)RandomNumberGenerator.GetInt32(1, 65536);
            var query = DnsWire.BuildPtrQuery(address, id, recursionDesired: true);
            var kind = DnsWire.ResponseKind.Invalid;
            string? name = null;

            var reply = await UdpExchange.RequestAsync(server, query, perServer, message =>
            {
                kind = DnsWire.ParsePtrResponse(message, id, out name);
                return kind != DnsWire.ResponseKind.Invalid;
            }, cancellationToken).ConfigureAwait(false);

            if (reply is null) continue;              // this server did not answer: try the next one
            return kind == DnsWire.ResponseKind.Name ? name : null; // it answered: that is the verdict
        }
        return null;
    }
}

/// <summary>Multicast DNS asked directly of the host (unicast to port 5353), so no multicast traffic is involved.</summary>
public sealed class MdnsSource(int port = 5353) : INameSource
{
    public NameSource Kind => NameSource.MDns;

    public async Task<string?> QueryAsync(IPAddress address, int timeoutMs, CancellationToken cancellationToken)
    {
        var query = DnsWire.BuildPtrQuery(address, id: 0, recursionDesired: false, unicastResponse: true);
        string? name = null;

        var reply = await UdpExchange.RequestAsync(new IPEndPoint(address, port), query, timeoutMs, message =>
            DnsWire.ParsePtrResponse(message, expectedId: null, out name) == DnsWire.ResponseKind.Name,
            cancellationToken).ConfigureAwait(false);

        return reply is null ? null : name;
    }
}

/// <summary>NetBIOS node status (NBSTAT, UDP 137): a Windows machine answers with its own computer name.</summary>
public sealed class NetBiosSource(int port = 137) : INameSource
{
    // Header (id 0, one question) + the wildcard name "*" in NetBIOS first-level encoding + type NBSTAT, class IN.
    private static readonly byte[] Request =
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x20, .. "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"u8, 0x00,
        0x00, 0x21, 0x00, 0x01,
    ];

    public NameSource Kind => NameSource.NetBios;

    public async Task<string?> QueryAsync(IPAddress address, int timeoutMs, CancellationToken cancellationToken)
    {
        string? name = null;
        var reply = await UdpExchange.RequestAsync(new IPEndPoint(address, port), Request, timeoutMs, message =>
        {
            name = ParseNodeStatus(message);
            return name is not null;
        }, cancellationToken).ConfigureAwait(false);

        return reply is null ? null : name;
    }

    /// <summary>
    /// The first unique (not group) name with suffix 0x00: the workstation name. Each entry is 15 name characters,
    /// one suffix byte and two flag bytes; the group bit (0x8000) marks workgroup and domain names.
    /// </summary>
    public static string? ParseNodeStatus(ReadOnlySpan<byte> message)
    {
        // 12-byte header, 34-byte echoed name, then type(2) class(2) ttl(4) rdlength(2), then the name table.
        const int tableStart = 12 + 34 + 10;
        if (message.Length <= tableStart) return null;

        int count = message[tableStart];
        int pos = tableStart + 1;
        for (int i = 0; i < count && pos + 18 <= message.Length; i++, pos += 18)
        {
            byte suffix = message[pos + 15];
            int flags = (message[pos + 16] << 8) | message[pos + 17];
            bool isGroup = (flags & 0x8000) != 0;
            if (suffix != 0x00 || isGroup) continue;

            var name = Encoding.ASCII.GetString(message.Slice(pos, 15)).Trim().TrimEnd('\0');
            if (name.Length > 0 && name.All(c => c is >= ' ' and <= '~')) return name;
        }
        return null;
    }
}
