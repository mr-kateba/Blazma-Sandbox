using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace Blazma.Analysis.Text;

/// <summary>Normalisation and classification of paths, registry keys and endpoints.</summary>
public static partial class PathRules
{
    private static readonly string[] ExecutableExtensions =
    [
        ".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".sys", ".msi", ".lnk", ".hta",
        ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".bat", ".cmd",
    ];

    private static readonly string[] UserWritableMarkers =
    [
        @"\appdata\", @"\temp\", @"\users\public\", @"\programdata\", @"\downloads\", @"\desktop\", @"\documents\",
    ];

    public static bool IsExecutablePath(string? path) =>
        path is not null && ExecutableExtensions.Contains(Path.GetExtension(path).ToLowerInvariant());

    public static bool IsUserWritableLocation(string? path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        var p = path.ToLowerInvariant();
        return UserWritableMarkers.Any(p.Contains);
    }

    public static string FileName(string? path)
    {
        if (string.IsNullOrEmpty(path)) return string.Empty;
        var i = path.LastIndexOfAny(['\\', '/']);
        return i >= 0 ? path[(i + 1)..] : path;
    }

    /// <summary>Converts NT and device paths to the familiar drive form.</summary>
    public static string NormalizeFilePath(string path)
    {
        if (string.IsNullOrEmpty(path)) return path;
        if (path.StartsWith(@"\??\", StringComparison.Ordinal)) path = path[4..];
        if (path.StartsWith(@"\\?\", StringComparison.Ordinal)) path = path[4..];
        var m = DeviceVolumeRegex().Match(path);
        if (m.Success) path = "C:" + path[m.Length..];
        return path;
    }

    /// <summary>Converts kernel registry paths (\REGISTRY\MACHINE\...) to HKLM/HKCU form.</summary>
    public static string NormalizeRegistryKey(string key)
    {
        if (string.IsNullOrEmpty(key)) return key;
        var k = key.Trim();
        if (k.StartsWith(@"\REGISTRY\MACHINE", StringComparison.OrdinalIgnoreCase)) return "HKLM" + k[@"\REGISTRY\MACHINE".Length..];
        if (k.StartsWith("HKEY_LOCAL_MACHINE", StringComparison.OrdinalIgnoreCase)) return "HKLM" + k["HKEY_LOCAL_MACHINE".Length..];
        if (k.StartsWith("HKEY_CURRENT_USER", StringComparison.OrdinalIgnoreCase)) return "HKCU" + k["HKEY_CURRENT_USER".Length..];
        if (k.StartsWith("HKEY_USERS", StringComparison.OrdinalIgnoreCase)) return "HKU" + k["HKEY_USERS".Length..];
        var m = UserSidRegex().Match(k);
        if (m.Success)
        {
            var rest = k[m.Length..];
            return m.Groups["classes"].Success ? @"HKCU\Software\Classes" + rest : "HKCU" + rest;
        }
        if (k.StartsWith(@"\REGISTRY\USER", StringComparison.OrdinalIgnoreCase)) return "HKU" + k[@"\REGISTRY\USER".Length..];
        return k;
    }

    public static bool IsExternalAddress(string? address)
    {
        if (!IPAddress.TryParse(address, out var ip)) return false;
        return !IsPrivateOrLocal(ip);
    }

    public static bool IsPrivateOrLocal(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip)) return true;
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv4MappedToIPv6) return IsPrivateOrLocal(ip.MapToIPv4());
            if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast) return true;
            var b6 = ip.GetAddressBytes();
            return (b6[0] & 0xFE) == 0xFC || ip.Equals(IPAddress.IPv6None);
        }
        var b = ip.GetAddressBytes();
        return b[0] == 10
            || b[0] == 0
            || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
            || (b[0] == 192 && b[1] == 168)
            || (b[0] == 169 && b[1] == 254)
            || (b[0] == 100 && b[1] >= 64 && b[1] <= 127)
            || b[0] >= 224;
    }

    [GeneratedRegex(@"^\\Device\\HarddiskVolume\d+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex DeviceVolumeRegex();

    [GeneratedRegex(@"^\\REGISTRY\\USER\\S-1-5-21-[\d-]+(?<classes>_Classes)?", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UserSidRegex();
}

/// <summary>Case-insensitive glob matching (* and ?) used by user rule packs, the noise allowlist and the watchlist.</summary>
public static class Glob
{
    public static bool IsMatch(string? text, string? pattern)
    {
        if (pattern is null || pattern == "*") return true;
        if (text is null) return false;
        var regex = "^" + Regex.Escape(pattern).Replace(@"\*", ".*", StringComparison.Ordinal).Replace(@"\?", ".", StringComparison.Ordinal) + "$";
        try
        {
            return Regex.IsMatch(text, regex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }
}
