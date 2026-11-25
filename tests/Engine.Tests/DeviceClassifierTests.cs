using ANetworkScanner.Engine;
using ANetworkScanner.Engine.Probes;
using Xunit;

namespace ANetworkScanner.Engine.Tests;

public class DeviceClassifierTests
{
    private static ServiceEvidence Svc(string id, string text, params int[] ports) => new(id, ports, text, text);

    private static DeviceKind Kind(int ttl, string? mac, params ServiceEvidence[] services) =>
        DeviceClassifier.Classify(new DeviceEvidence(ttl, mac, services)).Kind;

    // Real banners seen on a work LAN.

    [Fact]
    public void HpPrinter_BySnmpDescription() => Assert.Equal(DeviceKind.Printer, Kind(255, "E0:73:E7:E7:70:41",
        Svc("snmp", "HP ETHERNET MULTI-ENVIRONMENT,SN:CNBRR646X3,FN:089B5FF,PID:HP Color LaserJet MFP M283fdw", 161),
        Svc("http", "505 gSOAP/2.7", 80, 443)));

    [Fact]
    public void CiscoGateway_BySshBanner() => Assert.Equal(DeviceKind.NetworkDevice, Kind(254, "A4:B4:39:94:DC:E2",
        Svc("ssh", "Cisco-1.25", 22)));

    [Fact]
    public void AppleAirPort_BySnmp() => Assert.Equal(DeviceKind.NetworkDevice, Kind(255, "90:84:0D:D3:B2:09",
        Svc("snmp", "Apple AirPort - Apple Inc., 2006-2012.  All rights Reserved.", 161)));

    [Fact]
    public void UnifyDeskPhone_BySipUserAgent() => Assert.Equal(DeviceKind.IpPhone, Kind(64, "00:1A:E8:11:22:33",
        Svc("sip", "OpenScape Desk Phone CP400 SIP V1 R2.1.0", 5060)));

    [Fact]
    public void UnifyPhone_ByItsWebBanner() => Assert.Equal(DeviceKind.IpPhone, Kind(63, null,
        Svc("unify-phone", "CP400 100", 443)));

    [Fact]
    public void AProbeTitledIpPhone_ThatFoundNothing_DoesNotMakeAPhone() => Assert.NotEqual(DeviceKind.IpPhone, Kind(64, null,
        new ServiceEvidence("unify-phone", [443], "", "[IP phone :443 TLS] ")));

    [Fact]
    public void UbiquitiRadio_ByItsDiscoveryAnswer() => Assert.Equal(DeviceKind.NetworkDevice, Kind(63, null,
        Svc("ubiquiti", "Rocket Prism 5AC", 10001)));

    [Fact]
    public void AnOpenScapePbx_IsNotAPhone() => Assert.NotEqual(DeviceKind.IpPhone, Kind(64, null,
        Svc("sip", "OpenScape Voice V10", 5060)));

    [Fact]
    public void PhoneMaker_ByMacVendor() => Assert.Equal(DeviceKind.IpPhone,
        DeviceClassifier.Classify(new DeviceEvidence(64, "00:1A:E8:11:22:33", [], true, "Unify Software and Solutions GmbH & Co. KG")).Kind);

    [Fact]
    public void PhoneHostname() => Assert.Equal(DeviceKind.IpPhone,
        DeviceClassifier.Classify(new DeviceEvidence(64, null, [], true, null, "phone-reception.example.lan")).Kind);

    [Fact]
    public void Dropbear_IsAnEmbeddedNetworkDevice()
    {
        var guess = DeviceClassifier.Classify(new DeviceEvidence(64, "F4:E2:C6:26:B5:7A", [Svc("ssh", "dropbear_2024.86", 22)]));
        Assert.Equal(DeviceKind.NetworkDevice, guess.Kind);
        Assert.Contains("Dropbear", guess.Reason);
    }

    [Fact]
    public void WindowsPc_WithRdp() => Assert.Equal(DeviceKind.Computer, Kind(128, "2C:58:B9:8F:24:22",
        Svc("rdp", "NLA", 3389), Svc("smb", "SMB2/3", 445)));

    [Fact]
    public void WindowsPc_WithOnlySmbAndWindowsTtl() => Assert.Equal(DeviceKind.Computer, Kind(128, "50:81:40:7D:02:82",
        Svc("smb", "SMB2/3", 445), Svc("vnc", "RFB 003.008", 5900)));

    [Fact]
    public void UbuntuServer_BySshBanner() => Assert.Equal(DeviceKind.Server, Kind(64, "6C:3B:E5:36:E8:78",
        Svc("ssh", "OpenSSH_9.6p1 Ubuntu-3ubuntu13.19", 22)));

    [Fact]
    public void DebianWithWeb_IsAServer() => Assert.Equal(DeviceKind.Server, Kind(64, "02:0F:B5:70:9A:75",
        Svc("http", "200 Apache/2.4.65 (Debian)", 80), Svc("ssh", "OpenSSH_9.2p1 Debian-2+deb12u7", 22)));

    [Fact]
    public void IpCamera_ByRtsp() => Assert.Equal(DeviceKind.Camera, Kind(64, "00:16:6C:DE:98:3F",
        Svc("rtsp", "400", 554), Svc("http", "200 lighttpd", 80)));

    [Fact]
    public void RandomizedMacWithoutServices_IsAMobileDevice() => Assert.Equal(DeviceKind.Mobile, Kind(0, "2E:DE:3E:98:46:35"));

    [Fact]
    public void WhileProbesAreRunning_AbsenceBasedGuessesWait()
    {
        Assert.Equal(DeviceKind.Unknown, DeviceClassifier.Classify(new DeviceEvidence(0, "2E:DE:3E:98:46:35", [], ProbesComplete: false)).Kind);
        Assert.Equal(DeviceKind.Unknown, DeviceClassifier.Classify(new DeviceEvidence(255, null, [], ProbesComplete: false)).Kind);
        // Positive evidence is used right away.
        Assert.Equal(DeviceKind.Printer, DeviceClassifier.Classify(new DeviceEvidence(255, null, [Svc("snmp", "HP LaserJet", 161)], ProbesComplete: false)).Kind);
    }

    [Fact]
    public void FactoryMacWithoutServices_IsNotGuessedAsMobile() => Assert.Equal(DeviceKind.Unknown, Kind(0, "F8:ED:FC:21:6E:26"));

    [Fact]
    public void HighTtlAlone_PointsToNetworkGear() => Assert.Equal(DeviceKind.NetworkDevice, Kind(255, "90:84:0D:D4:56:E1"));

    [Fact]
    public void NoEvidence_IsUnknown() => Assert.Equal(DeviceKind.Unknown, Kind(0, null));

    [Fact]
    public void PrinterWordsBeatOtherSignals() => Assert.Equal(DeviceKind.Printer, Kind(128, null,
        Svc("smb", "SMB2/3", 445), Svc("snmp", "Brother NC-8300h", 161)));

    [Theory]
    [InlineData("2E:DE:3E:98:46:35", true)]
    [InlineData("02:0F:B5:70:9A:75", true)]
    [InlineData("BA:14:12:4C:6B:FC", true)]
    [InlineData("A6:B2:EA:21:C0:EE", true)]
    [InlineData("F8:ED:FC:21:6E:26", false)]
    [InlineData("00:1B:00:33:10:69", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void RandomizedMac_DetectsTheLocallyAdministeredBit(string? mac, bool expected) =>
        Assert.Equal(expected, DeviceClassifier.IsRandomizedMac(mac));

    // ── The result level declared in probe files ─────────────────────────────

    [Theory]
    [InlineData("info", ProbeLevel.Info)]
    [InlineData("good", ProbeLevel.Good)]
    [InlineData("warning", ProbeLevel.Warning)]
    [InlineData("warn", ProbeLevel.Warning)]
    [InlineData("BAD", ProbeLevel.Bad)]
    public void MatchRuleLevel_IsParsed(string text, ProbeLevel expected)
    {
        var r = ProbeLoader.LoadFromJson($$"""{ "id": "l", "ports": [1], "match": [ { "regex": "x", "level": "{{text}}" } ], "fallback": { "level": "{{text}}" } }""", "t.json");
        Assert.Empty(r.Problems);
        var probe = Assert.Single(r.Probes);
        Assert.Equal(expected, probe.Match[0].Level);
        Assert.Equal(expected, probe.FallbackLevel);
    }

    [Fact]
    public void MatchRuleLevel_DefaultsToInfo_AndRejectsNonsense()
    {
        var ok = ProbeLoader.LoadFromJson("""{ "id": "l", "ports": [1], "match": [ { "regex": "x" } ] }""", "t.json");
        Assert.Equal(ProbeLevel.Info, ok.Probes[0].Match[0].Level);

        var bad = ProbeLoader.LoadFromJson("""{ "id": "l", "ports": [1], "match": [ { "regex": "x", "level": "scary" } ] }""", "t.json");
        Assert.Empty(bad.Probes);
        Assert.Contains("level", bad.Problems[0].Message);
    }
}
