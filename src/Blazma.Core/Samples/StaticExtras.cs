using Blazma.Core.Events;
using Blazma.Core.Text;

namespace Blazma.Core.Samples;

/// <summary>
/// Something the program is able to do, inferred from its code without running it (imports,
/// strings). A capability is potential, not observed behavior, and is always shown that way.
/// </summary>
public sealed record Capability
{
    public required string Id { get; init; }
    public required LocalizedText Name { get; init; }
    public required LocalizedText Description { get; init; }

    /// <summary>Grouping such as "collection/keylogging" or "defense-evasion/anti-debugging".</summary>
    public required string Namespace { get; init; }

    public Severity Severity { get; init; } = Severity.Low;
    public IReadOnlyList<string> AttackTechniques { get; init; } = [];

    /// <summary>Malware Behavior Catalog identifiers (e.g. "B0009").</summary>
    public IReadOnlyList<string> Mbc { get; init; } = [];

    /// <summary>The imports or strings that matched, e.g. "import: user32!SetWindowsHookExW".</summary>
    public IReadOnlyList<string> Evidence { get; init; } = [];
}

/// <summary>One string of a YARA rule that matched, with where it matched.</summary>
public sealed record YaraStringHit(string Identifier, long Offset, string Preview);

/// <summary>A YARA rule that matched some data. Family names come from the rule's own metadata.</summary>
public sealed record YaraMatch
{
    public required string Rule { get; init; }

    /// <summary>The rule file it came from.</summary>
    public required string Source { get; init; }

    /// <summary>What was scanned: "sample", "dropped:&lt;path&gt;" or "memory:&lt;process&gt;@&lt;address&gt;".</summary>
    public required string Target { get; init; }

    public IReadOnlyList<string> Tags { get; init; } = [];
    public IReadOnlyDictionary<string, string> Meta { get; init; } = new Dictionary<string, string>();
    public IReadOnlyList<YaraStringHit> Strings { get; init; } = [];

    /// <summary>The malware family named by the rule's metadata (family, malware_family or malware), if any.</summary>
    public string? Family =>
        Meta.TryGetValue("family", out var f) || Meta.TryGetValue("malware_family", out f) || Meta.TryGetValue("malware", out f) ? f : null;
}

public enum ArtifactKind
{
    Url,
    Domain,
    IpAddress,
    Email,
    OnionAddress,
    BitcoinAddress,
    EthereumAddress,
    MoneroAddress,
    TelegramBotToken,
    DiscordWebhook,
    PastebinLink,
    UserAgent,
    MutexName,
    Base64Blob,
}

/// <summary>
/// A configuration-like value found in the sample, a dropped file or process memory: C2
/// addresses, wallets, bot tokens. Generic pattern matching, not a family-specific decoder.
/// </summary>
public sealed record ExtractedArtifact(ArtifactKind Kind, string Value, string Source);

/// <summary>What can be said about a web address before opening it.</summary>
public sealed record UrlReport
{
    public required string Url { get; init; }
    public required string Scheme { get; init; }
    public required string Host { get; init; }

    /// <summary>The host as a person would read it, if it uses punycode (xn--).</summary>
    public string? UnicodeHost { get; init; }

    public int? Port { get; init; }
    public bool HostIsIpAddress { get; init; }
    public bool HasEmbeddedCredentials { get; init; }
    public bool IsKnownShortener { get; init; }
    public bool UsesRiskyTopLevelDomain { get; init; }
    public bool MixesScripts { get; init; }

    /// <summary>A well-known brand the host appears to imitate (e.g. "paypal" for "paypa1-login.example").</summary>
    public string? LooksLike { get; init; }

    public int SubdomainDepth { get; init; }
    public IReadOnlyList<LocalizedText> Notes { get; init; } = [];
}

public sealed record ArchiveEntry(string Path, long Size, long CompressedSize, bool Encrypted, FileKind Kind);

/// <summary>The listing of an archive. The archive itself is never run; one entry is extracted and analyzed.</summary>
public sealed record ArchiveInfo
{
    public required string Format { get; init; }
    public bool Encrypted { get; init; }
    public IReadOnlyList<ArchiveEntry> Entries { get; init; } = [];

    /// <summary>Set when the listing was cut short by the safety limits.</summary>
    public string? LimitNote { get; init; }
}
