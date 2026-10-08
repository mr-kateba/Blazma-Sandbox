using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Blazma.Core.Samples;

namespace Blazma.Analysis.Static;

/// <summary>
/// Import hash (Mandiant, 2014) computed exactly like Python pefile's <c>get_imphash()</c>, which is
/// what VirusTotal and most threat-intelligence feeds publish. Builds of the same program usually
/// share it even when every byte of code differs, so it groups samples; it is not a verdict.
/// </summary>
public static class ImpHash
{
    private static readonly string[] StrippedExtensions = ["ocx", "sys", "dll"];

    /// <summary>
    /// Returns the lower-case hex MD5, or null when nothing is imported (pefile returns an empty
    /// string there, and an empty hash would wrongly group every import-less file together).
    /// </summary>
    public static string? Compute(PeInfo pe) => Compute(pe.Imports);

    public static string? Compute(IReadOnlyList<PeImport> imports)
    {
        var parts = new List<string>();
        foreach (var import in imports)
        {
            var library = NormalizeLibrary(import.Library);
            if (library is null) continue;
            foreach (var function in import.Functions)
            {
                var name = ResolveFunction(library.Raw, function);
                if (name is not null) parts.Add(library.Stem + "." + name.ToLowerInvariant());
            }
        }
        if (parts.Count == 0) return null;
#pragma warning disable CA5351 // MD5 is part of the imphash definition; it is a fingerprint, not a security control
        return Convert.ToHexStringLower(MD5.HashData(Encoding.UTF8.GetBytes(string.Join(',', parts))));
#pragma warning restore CA5351
    }

    private sealed record LibraryName(string Raw, string Stem);

    /// <summary>
    /// pefile replaces names with characters outside its DOS-filename set by "*invalid*" and
    /// drops empty names; PeParser reports an unreadable name as "?", which pefile also calls invalid.
    /// </summary>
    private static LibraryName? NormalizeLibrary(string library)
    {
        if (library.Length == 0) return null;
        var lower = library == "?" || !library.All(IsDosFilenameChar) ? "*invalid*" : library.ToLowerInvariant();
        var dot = lower.LastIndexOf('.');
        var stem = dot >= 0 && StrippedExtensions.Contains(lower[(dot + 1)..], StringComparer.Ordinal) ? lower[..dot] : lower;
        return new LibraryName(lower, stem);
    }

    /// <summary>Ordinals ("#N" from <see cref="PeParser"/>) become pefile's names or "ordN"; invalid names are skipped as pefile does.</summary>
    private static string? ResolveFunction(string libraryLower, string function)
    {
        if (function.Length > 1 && function[0] == '#' &&
            int.TryParse(function.AsSpan(1), NumberStyles.None, CultureInfo.InvariantCulture, out var ordinal))
        {
            if (ordinal == 0) return null; // pefile drops ordinal 0 (it is falsy there)
            return ImpHashOrdinals.ByLibrary.TryGetValue(libraryLower, out var table) && table.TryGetValue(ordinal, out var known)
                ? known
                : "ord" + ordinal.ToString(CultureInfo.InvariantCulture);
        }
        return function.All(IsFunctionNameChar) ? function : null;
    }

    // pefile.is_valid_function_name: letters, digits and ._?@$()<>
    private static bool IsFunctionNameChar(char c) => char.IsAsciiLetterOrDigit(c) || "._?@$()<>".Contains(c, StringComparison.Ordinal);

    // pefile.is_valid_dos_filename: allowed_filename plus path separators
    private static bool IsDosFilenameChar(char c) => char.IsAsciiLetterOrDigit(c) || "!#$%&'()-@^_`{}~+,.;=[]:\\/".Contains(c, StringComparison.Ordinal);
}
