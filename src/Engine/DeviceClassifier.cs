namespace ANetworkScanner.Engine;

public enum DeviceKind
{
    Unknown,
    Computer,
    Server,
    Printer,
    NetworkDevice,
    Camera,
    Mobile,
    IpPhone,
}

/// <param name="Reason">One line saying what the guess is based on, shown as a tooltip.</param>
public sealed record DeviceGuess(DeviceKind Kind, string Reason)
{
    public static DeviceGuess Unknown { get; } = new(DeviceKind.Unknown, "Not enough information to tell");
}

/// <summary>What a probe found on a host.</summary>
public sealed record ServiceEvidence(string ProbeId, IReadOnlyList<int> OpenPorts, string Short, string Detail);

/// <param name="Ttl">TTL of the ICMP reply, or 0 when the host did not answer ping.</param>
/// <param name="Mac">The MAC as <c>AA:BB:CC:DD:EE:FF</c>, or null.</param>
/// <param name="Vendor">The manufacturer from the MAC address, if known.</param>
/// <param name="HostName">The name found by DNS, mDNS or NetBIOS, if resolved.</param>
/// <param name="ProbesComplete">
/// False while probes are still running. Guesses that rest on something being absent (nothing open, so a phone)
/// wait until it is true, so a row never flashes a wrong icon.
/// </param>
public sealed record DeviceEvidence(int Ttl, string? Mac, IReadOnlyList<ServiceEvidence> Services, bool ProbesComplete = true, string? Vendor = null, string? HostName = null);

/// <summary>
/// A best guess of what kind of device a host is, from banners, open services, the TTL and the MAC.
/// Rules run from the most specific evidence (a printer's own words) to the weakest (the TTL), and the first
/// one that fires wins. It is a hint for the icon in the grid, never a verdict.
/// </summary>
public static class DeviceClassifier
{
    private static readonly string[] PrinterWords =
    [
        "laserjet", "officejet", "deskjet", "designjet", "printer", "mfp", "ricoh", "kyocera", "konica",
        "brother", "epson", "lexmark", "xerox", "imagerunner", "jetdirect", "hp ethernet", "bizhub", "sharp mx",
    ];

    private static readonly string[] CameraWords = ["hikvision", "dahua", "onvif", "ip camera", "axis communications", "reolink", "foscam"];

    // "openscape" alone is not here: it also names the PBX servers.
    private static readonly string[] PhoneWords =
    [
        "desk phone", "openstage", "voip phone", "yealink", "snom", "polycom", "grandstream", "fanvil", "mitel 6",
    ];

    private static readonly string[] PhoneVendors = ["unify", "mitel", "yealink", "snom", "polycom", "grandstream", "fanvil"];

    private static readonly string[] NetworkWords =
    [
        "cisco", "mikrotik", "routeros", "ubiquiti", "unifi", "edgeos", "edgerouter", "juniper", "aruba", "netgear",
        "tp-link", "fritz", "airport", "access point", "openwrt", "dd-wrt", "zyxel", "draytek", "fortigate", "fortinet",
        "pfsense", "opnsense", "sophos", "meraki", "switch", "router", "gateway", "dropbear",
    ];

    private static readonly string[] PrinterVendors =
        ["brother", "canon", "seiko epson", "epson", "ricoh", "kyocera", "lexmark", "xerox", "konica", "oki data", "sharp", "toshiba tec"];

    private static readonly string[] CameraVendors =
        ["hikvision", "dahua", "axis communications", "vivotek", "hanwha", "reolink", "foscam", "mobotix", "amcrest", "uniview"];

    private static readonly string[] NetworkVendors =
    [
        "cisco", "ubiquiti", "mikrotik", "routerboard", "tp-link", "netgear", "zyxel", "d-link", "aruba", "ruckus", "cambium",
        "juniper", "fortinet", "arista", "extreme networks", "avm", "draytek", "meraki", "engenius", "linksys",
    ];

    private static readonly string[] StorageVendors = ["synology", "qnap", "asustor", "terramaster"];

    private static readonly string[] ServerWords = ["ubuntu", "debian", "centos", "red hat", "rhel", "fedora", "freebsd", "rocky", "alma", "suse"];

    public static DeviceGuess Classify(DeviceEvidence evidence)
    {
        var services = evidence.Services;
        var text = string.Join(" ", services.Select(s => $"{s.Short} {s.Detail}")).ToLowerInvariant();

        if (FindWord(text, PrinterWords) is { } printer)
            return new(DeviceKind.Printer, $"Its own replies mention \"{printer}\"");

        if (services.Any(s => s.ProbeId == "onvif" && s.OpenPorts.Count > 0))
            return new(DeviceKind.Camera, "It answers ONVIF discovery, the standard for IP cameras");
        if (services.Any(s => s.ProbeId == "rtsp" && s.OpenPorts.Count > 0))
            return new(DeviceKind.Camera, "It serves RTSP video streams");
        if (FindWord(text, CameraWords) is { } camera)
            return new(DeviceKind.Camera, $"Its own replies mention \"{camera}\"");

        if (services.Any(s => s.ProbeId == "unify-phone" && s.OpenPorts.Count > 0 && s.Short.Length > 0))
            return new(DeviceKind.IpPhone, "Its web interface identifies it as a Unify / Mitel phone");
        if (FindWord(text, PhoneWords) is { } phone)
            return new(DeviceKind.IpPhone, $"Its own replies mention \"{phone}\"");

        if (services.Any(s => s.ProbeId == "ubiquiti" && s.OpenPorts.Count > 0 && s.Short.Length > 0))
            return new(DeviceKind.NetworkDevice, "It answers Ubiquiti discovery (radio, access point or router)");

        if (FindWord(text, NetworkWords) is { } network)
            return new(DeviceKind.NetworkDevice, network == "dropbear"
                ? "It runs the Dropbear SSH server used by routers and access points"
                : $"Its own replies mention \"{network}\"");

        if (GuessFromName(evidence.HostName) is { } byName) return byName;

        var vendor = evidence.Vendor?.ToLowerInvariant();
        if (vendor is { Length: > 0 })
        {
            if (FindWord(vendor, PrinterVendors) is { } p) return new(DeviceKind.Printer, $"The MAC address belongs to {evidence.Vendor}, a printer maker");
            if (FindWord(vendor, CameraVendors) is { } c) return new(DeviceKind.Camera, $"The MAC address belongs to {evidence.Vendor}, a camera maker");
            if (FindWord(vendor, PhoneVendors) is { } ph) return new(DeviceKind.IpPhone, $"The MAC address belongs to {evidence.Vendor}, an IP phone maker");
            if (FindWord(vendor, NetworkVendors) is { } n) return new(DeviceKind.NetworkDevice, $"The MAC address belongs to {evidence.Vendor}, a network equipment maker");
            if (FindWord(vendor, StorageVendors) is { } st) return new(DeviceKind.Server, $"The MAC address belongs to {evidence.Vendor}, a storage (NAS) maker");
        }

        bool Has(string id) => services.Any(s => s.ProbeId == id && s.OpenPorts.Count > 0);

        if (Has("rdp"))
            return new(DeviceKind.Computer, "Remote Desktop is open (Windows)");
        if (Has("smb") && evidence.Ttl is > 64 and <= 128)
            return new(DeviceKind.Computer, "File sharing is open and the TTL points to Windows");

        if (Has("ssh") && FindWord(text, ServerWords) is { } distro)
            return new(DeviceKind.Server, $"SSH banner mentions {distro}");

        if (evidence.ProbesComplete && IsRandomizedMac(evidence.Mac) && services.Count(s => s.OpenPorts.Count > 0) == 0)
            return new(DeviceKind.Mobile, "Randomized (private) MAC address with no open services: usually a phone or laptop on Wi-Fi");

        if (Has("smb") || Has("vnc"))
            return new(DeviceKind.Computer, "File sharing or VNC is open");
        if (Has("ssh"))
            return new(DeviceKind.Server, "SSH is open");

        if (evidence.ProbesComplete && evidence.Ttl >= 200)
            return new(DeviceKind.NetworkDevice, $"TTL {evidence.Ttl} is typical of routers, switches and printers");
        if (evidence.Ttl is > 64 and <= 128 && services.Any(s => s.OpenPorts.Count > 0))
            return new(DeviceKind.Computer, "The TTL points to Windows");

        return DeviceGuess.Unknown;
    }

    /// <summary>A "locally administered" MAC (bit 1 of the first byte set) is not a factory address: phones and laptops use them for Wi-Fi privacy.</summary>
    public static bool IsRandomizedMac(string? mac)
    {
        if (string.IsNullOrEmpty(mac) || mac.Length < 2 || !Uri.IsHexDigit(mac[0]) || !Uri.IsHexDigit(mac[1])) return false;
        return (Convert.ToByte(mac[..2], 16) & 0x02) != 0;
    }

    // Hostnames are chosen by people, so only whole words ("svr", "cam") and well-known prefixes count.
    private static readonly (DeviceKind Kind, string[] Words, string[] Prefixes)[] NameRules =
    [
        (DeviceKind.Printer, ["printer", "print", "mfp", "laserjet", "officejet"], ["npi", "brn", "brw", "epson", "canon", "kyocera", "ricoh", "lexmark", "xerox"]),
        (DeviceKind.Camera, ["cam", "ipcam", "camera", "nvr", "dvr"], ["cam-", "ipcam"]),
        (DeviceKind.IpPhone, ["phone", "voip", "sip"], ["phone-", "voip", "sip-", "cp400", "cp200", "openstage"]),
        (DeviceKind.Mobile, ["iphone", "ipad", "android", "galaxy", "pixel", "oneplus", "redmi"], ["iphone", "ipad", "galaxy", "android"]),
        (DeviceKind.NetworkDevice, ["ap", "switch", "sw", "router", "rtr", "gateway", "gw", "fw", "firewall", "unifi"], ["ap-", "sw-", "rtr-", "fw-"]),
        (DeviceKind.Server, ["srv", "svr", "server", "dc", "nas", "esxi", "proxmox", "pve", "docker", "sql"], ["srv", "svr", "esxi", "nas-"]),
        (DeviceKind.Computer, ["desktop", "laptop", "macbook", "imac", "workstation", "pc"], ["desktop-", "laptop-", "macbook", "imac", "pc-"]),
    ];

    private static DeviceGuess? GuessFromName(string? hostName)
    {
        if (string.IsNullOrWhiteSpace(hostName)) return null;

        var label = hostName.Split('.')[0].ToLowerInvariant();
        var words = System.Text.RegularExpressions.Regex.Matches(label, "[a-z]+").Select(m => m.Value).ToHashSet();

        foreach (var (kind, nameWords, prefixes) in NameRules)
        {
            if (prefixes.FirstOrDefault(p => label.StartsWith(p, StringComparison.Ordinal)) is { } prefix)
                return new(kind, $"The hostname \"{hostName}\" starts with \"{prefix.TrimEnd('-')}\"");
            if (nameWords.FirstOrDefault(words.Contains) is { } word)
                return new(kind, $"The hostname \"{hostName}\" contains \"{word}\"");
        }
        return null;
    }

    private static string? FindWord(string text, string[] words) =>
        words.FirstOrDefault(w => text.Contains(w, StringComparison.Ordinal));
}
