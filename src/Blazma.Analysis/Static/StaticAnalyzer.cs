using System.Security.Cryptography;
using Blazma.Analysis.Archives;
using Blazma.Core.Abstractions;
using Blazma.Core.Samples;

namespace Blazma.Analysis.Static;

/// <summary>
/// Non-executing analysis: hashes, type, PE metadata, signature, entropy and a limited set
/// of strings. In the app this runs inside Blazma.StaticWorker, a separate short-lived
/// process, so a parser bug triggered by a hostile file cannot reach the UI process.
/// </summary>
public sealed class StaticAnalyzer(ISignatureVerifier signatures, IYaraScanner? yara = null, bool detectCapabilities = true) : IStaticAnalyzer
{
    /// <summary>Files above this are hashed but not parsed in depth.</summary>
    public const long MaxDeepParseBytes = 256L * 1024 * 1024;

    /// <summary>Bytes given to the type detector: enough for Office package names and late PDF headers.</summary>
    private const int TypeProbeBytes = 4096;

    public StaticAnalyzer() : this(new SignatureVerifier()) { }

    public StaticAnalyzer(IYaraScanner? yara, bool detectCapabilities) : this(new SignatureVerifier(), yara, detectCapabilities) { }

    /// <summary>Passwords tried, in order, when the sample is an encrypted archive.</summary>
    public IReadOnlyList<string> ArchivePasswords { get; init; } = ArchiveReader.DefaultPasswords;

    public async Task<StaticReport> AnalyzeAsync(string path, CancellationToken cancellationToken)
    {
        var info = new FileInfo(path);
        if (!info.Exists) throw new FileNotFoundException("The file to analyze was not found.", path);

        var warnings = new List<string>();
        string sha256, sha1;
        await using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.Asynchronous | FileOptions.SequentialScan))
        {
            using var h256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            using var h1 = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
            var buffer = new byte[81920];
            int read;
            while ((read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
            {
                h256.AppendData(buffer, 0, read);
                h1.AppendData(buffer, 0, read);
            }
            sha256 = Convert.ToHexStringLower(h256.GetHashAndReset());
            sha1 = Convert.ToHexStringLower(h1.GetHashAndReset());
        }

        byte[] content;
        if (info.Length <= MaxDeepParseBytes)
        {
            content = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            warnings.Add("The file is larger than 256 MB; only the first 4 MB were inspected.");
            content = new byte[4 * 1024 * 1024];
            await using var s = File.OpenRead(path);
            await s.ReadExactlyAsync(content, cancellationToken).ConfigureAwait(false);
        }

        cancellationToken.ThrowIfCancellationRequested();
        var pe = PeParser.TryParse(content, warnings);
        var kind = FileTypeDetector.Detect(content.AsSpan(0, Math.Min(content.Length, TypeProbeBytes)), info.Name, pe);
        var signature = pe is null
            ? new SignatureInfo(SignatureStatus.NotSigned)
            : signatures.Verify(path, PeParser.HasSignatureDirectory(content));

        if (pe?.CompileTimestamp is { } ts && ts > DateTimeOffset.UtcNow.AddDays(1))
            warnings.Add("The compile timestamp is in the future; it has probably been altered.");

        cancellationToken.ThrowIfCancellationRequested();
        var capabilities = detectCapabilities && (pe is not null || IsScript(kind))
            ? CapabilityDetector.Detect(pe, content)
            : [];

        cancellationToken.ThrowIfCancellationRequested();
        IReadOnlyList<YaraMatch> yaraMatches = [];
        if (yara is { RuleCount: > 0 })
        {
            try
            {
                yaraMatches = yara.Scan(content, info.Name);
            }
            catch (Exception ex) when (ex is InvalidOperationException or ArgumentException or TimeoutException)
            {
                warnings.Add("YARA scanning stopped: " + ex.Message);
            }
        }

        cancellationToken.ThrowIfCancellationRequested();
        var artifacts = ArtifactExtractor.Extract(content, info.Name);

        ArchiveInfo? archive = null;
        if (kind == FileKind.Archive)
        {
            try
            {
                archive = ArchiveReader.TryOpen(path, ArchivePasswords, out _);
                if (archive is null) warnings.Add("The archive could not be opened with the known passwords; choose a password to list it.");
            }
            catch (Exception ex) when (ex is InvalidDataException or ArchiveLimitException or ArchivePasswordException or IOException or NotSupportedException)
            {
                warnings.Add("The archive could not be listed: " + ex.Message);
            }
        }

        cancellationToken.ThrowIfCancellationRequested();
        return new StaticReport
        {
            Sample = new SampleInfo
            {
                FileName = info.Name,
                Size = info.Length,
                Sha256 = sha256,
                Sha1 = sha1,
                Kind = kind,
            },
            Pe = pe,
            Signature = signature,
            Entropy = Math.Round(Entropy.Of(content), 3),
            Strings = StringExtractor.Extract(content),
            Warnings = warnings,
            ImpHash = pe is null ? null : ImpHash.Compute(pe),
            Capabilities = capabilities,
            YaraMatches = yaraMatches,
            Artifacts = artifacts,
            Archive = archive,
        };
    }

    private static bool IsScript(FileKind kind) =>
        kind is FileKind.PowerShell or FileKind.Batch or FileKind.VbScript or FileKind.JScript;
}
