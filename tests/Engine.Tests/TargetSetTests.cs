using System.Net;
using ANetworkScanner.Engine.Targets;
using Xunit;

namespace ANetworkScanner.Engine.Tests;

public class TargetSetTests
{
    private static string[] Hosts(string input) =>
        [.. TargetSet.Parse(input).Enumerate().Select(a => a.ToString())];

    private static uint V(string ip) => TargetSet.ToValue(IPAddress.Parse(ip));

    [Fact]
    public void SingleAddress() => Assert.Equal(["10.0.0.5"], Hosts("10.0.0.5"));

    [Fact]
    public void Cidr24_ExcludesNetworkAndBroadcast()
    {
        var set = TargetSet.Parse("192.168.1.0/24");
        Assert.Equal(254, set.Count);
        Assert.False(set.Contains(V("192.168.1.0")));
        Assert.False(set.Contains(V("192.168.1.255")));
        Assert.True(set.Contains(V("192.168.1.1")));
        Assert.True(set.Contains(V("192.168.1.254")));
    }

    [Fact]
    public void Cidr31_KeepsBothAddresses() =>
        Assert.Equal(["10.0.0.0", "10.0.0.1"], Hosts("10.0.0.0/31"));

    [Fact]
    public void Cidr32_IsOneHost() => Assert.Equal(["10.0.0.7"], Hosts("10.0.0.7/32"));

    [Fact]
    public void CidrWithHostBits_IsMasked() => Assert.Equal(254, TargetSet.Parse("10.0.0.77/24").Count);

    [Fact]
    public void FullRange_CrossesOctets() =>
        Assert.Equal(["10.0.0.254", "10.0.0.255", "10.0.1.0", "10.0.1.1"], Hosts("10.0.0.254-10.0.1.1"));

    [Fact]
    public void ShortRange_NmapStyle() => Assert.Equal(250, TargetSet.Parse("10.0.0.1-250").Count);

    [Fact]
    public void Wildcard_Includes0And255() => Assert.Equal(256, TargetSet.Parse("172.16.128.*").Count);

    [Fact]
    public void OctetRanges_AcrossSeveralOctets() => Assert.Equal(2 * 100, TargetSet.Parse("10.0.0-1.1-100").Count);

    [Fact]
    public void ListOfItems_IsMergedWithoutDuplicates()
    {
        var set = TargetSet.Parse("10.0.0.1-10, 10.0.0.5-20 10.0.0.21");
        Assert.Equal(21, set.Count);
        Assert.Single(set.Ranges);
    }

    [Fact]
    public void Slash8_DoesNotMaterialiseAddresses() =>
        Assert.Equal((1L << 24) - 2, TargetSet.Parse("10.0.0.0/8").Count);

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("300.1.1.1")]
    [InlineData("10.0.0")]
    [InlineData("10.0.0.0/33")]
    [InlineData("10.0.0.50-10.0.0.10")]
    [InlineData("10.0.0.9-5")]
    [InlineData("hostname.local")]
    [InlineData("0.0.0.0/0")]
    public void InvalidInput_IsRejectedWithMessage(string input)
    {
        Assert.False(TargetSet.TryParse(input, out _, out var error));
        Assert.False(string.IsNullOrEmpty(error));
    }
}

public class TargetSetIndexTests
{
    private static uint V(string ip) => TargetSet.ToValue(System.Net.IPAddress.Parse(ip));

    [Fact]
    public void IndexOf_And_ValueAt_AreInverse_AcrossSeveralRanges()
    {
        var set = TargetSet.Parse("10.0.0.5-10, 10.0.1.0/30, 192.168.1.7");
        Assert.Equal(6 + 2 + 1, set.Count);

        long i = 0;
        foreach (var value in set.EnumerateValues())
        {
            Assert.Equal(i, set.IndexOf(value));
            Assert.Equal(value, set.ValueAt(i));
            i++;
        }
    }

    [Fact]
    public void IndexOf_ReturnsMinusOneForNonTargets()
    {
        var set = TargetSet.Parse("10.0.0.5-10");
        Assert.Equal(-1, set.IndexOf(V("10.0.0.4")));
        Assert.Equal(-1, set.IndexOf(V("10.0.0.11")));
        Assert.Equal(0, set.IndexOf(V("10.0.0.5")));
        Assert.Equal(5, set.IndexOf(V("10.0.0.10")));
    }

    [Fact]
    public void ValueAt_RejectsOutOfRange()
    {
        var set = TargetSet.Parse("10.0.0.5-10");
        Assert.Throws<ArgumentOutOfRangeException>(() => set.ValueAt(-1));
        Assert.Throws<ArgumentOutOfRangeException>(() => set.ValueAt(6));
    }
}
