using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using ANetworkScanner.Engine.Targets;

namespace ANetworkScanner.Engine.Discovery;

/// <summary>
/// The IPv4 subnets this machine is directly attached to. Only addresses inside one of them can be
/// resolved with ARP; anything behind a router is "off-link" and must never be judged by ARP.
/// </summary>
public sealed class LocalSubnets
{
    private readonly (uint Network, uint Mask, string Name)[] _subnets;

    public static LocalSubnets None { get; } = new(Array.Empty<(uint, uint, string)>());

    private LocalSubnets((uint Network, uint Mask, string Name)[] subnets) => _subnets = subnets;

    /// <summary>For tests and manual configuration: (address in the subnet, prefix length).</summary>
    public LocalSubnets(IEnumerable<(IPAddress Address, int PrefixLength)> subnets)
        : this(subnets.Select(s => Build(s.Address, s.PrefixLength, "manual")).ToArray())
    {
    }

    /// <summary>The attached subnets in CIDR form, e.g. <c>172.16.128.0/24</c> - ready to use as a scan target.</summary>
    public IReadOnlyList<string> Cidrs =>
        [.. _subnets.Select(s => $"{TargetSet.ToAddress(s.Network)}/{BitCount(s.Mask)}").Distinct()];

    public IReadOnlyList<string> Names => [.. _subnets.Select(s => $"{TargetSet.ToAddress(s.Network)}/{BitCount(s.Mask)} ({s.Name})")];

    /// <summary>
    /// True when <paramref name="address"/> can be a host on one of the attached subnets. The network and
    /// broadcast addresses of a /30 or larger are not hosts, so they are excluded: some devices answer ARP for
    /// the broadcast address, which would otherwise show up as a phantom host.
    /// </summary>
    public bool IsOnLink(uint address)
    {
        foreach (var (network, mask, _) in _subnets)
        {
            if ((address & mask) != network) continue;
            bool pointToPoint = BitCount(mask) >= 31;
            if (!pointToPoint && (address == network || address == (network | ~mask))) continue;
            return true;
        }
        return false;
    }

    /// <summary>Reads the adapters that are up. Loopback, tunnels and /32 host routes are ignored.</summary>
    public static LocalSubnets Detect()
    {
        var found = new List<(uint, uint, string)>();
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up ||
                    nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
                    continue;

                foreach (var unicast in nic.GetIPProperties().UnicastAddresses)
                {
                    if (unicast.Address.AddressFamily != AddressFamily.InterNetwork || unicast.PrefixLength is < 8 or > 31)
                        continue;
                    found.Add(Build(unicast.Address, unicast.PrefixLength, nic.Name));
                }
            }
        }
        catch (NetworkInformationException)
        {
            // No adapter information: behave as if everything were off-link (ICMP only).
        }

        return new LocalSubnets(found.ToArray());
    }

    private static (uint Network, uint Mask, string Name) Build(IPAddress address, int prefix, string name)
    {
        uint mask = prefix == 0 ? 0 : uint.MaxValue << (32 - prefix);
        return (TargetSet.ToValue(address) & mask, mask, name);
    }

    private static int BitCount(uint mask) => System.Numerics.BitOperations.PopCount(mask);
}
