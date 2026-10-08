using System.Security.Cryptography;
using System.Text;
using Blazma.Core.Abstractions;

namespace Blazma.Storage.Secrets;

/// <summary>
/// Picks the secret protector for this platform and holds the stored-value format shared by
/// all of them: <c>dpapi:&lt;base64&gt;</c> (encrypted for the current Windows user),
/// <c>plain:&lt;base64&gt;</c> (obfuscated only) or, from older settings files, the raw value.
/// </summary>
public static class SecretProtector
{
    public const string DpapiPrefix = "dpapi:";
    public const string PlainPrefix = "plain:";

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>DPAPI on Windows; elsewhere the portable protector, which only obfuscates.</summary>
    public static ISecretProtector CreateDefault() =>
        OperatingSystem.IsWindows() ? new DpapiSecretProtector() : new PortableSecretProtector();

    internal static string EncodePlain(string plaintext) =>
        PlainPrefix + Convert.ToBase64String(Encoding.UTF8.GetBytes(plaintext));

    /// <summary>Strict UTF-8 decoding; null for empty or invalid data.</summary>
    internal static string? Text(byte[] data)
    {
        try
        {
            var text = StrictUtf8.GetString(data);
            return text.Length == 0 ? null : text;
        }
        catch (DecoderFallbackException)
        {
            return null;
        }
    }

    /// <summary>The forms every protector understands: <c>plain:</c> and raw legacy values. Null when unreadable.</summary>
    internal static string? DecodeCommon(string stored)
    {
        if (!stored.StartsWith(PlainPrefix, StringComparison.Ordinal))
            return string.IsNullOrWhiteSpace(stored) ? null : stored; // Saved before secrets were protected: use it as it is.

        try
        {
            return Text(Convert.FromBase64String(stored[PlainPrefix.Length..]));
        }
        catch (FormatException)
        {
            return null;
        }
    }
}

/// <summary>
/// Encrypts secrets with Windows DPAPI for the current user, so another account or another
/// computer cannot read them from the settings file.
/// </summary>
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public sealed class DpapiSecretProtector : ISecretProtector
{
    // Fixed application entropy: another program running as the same user that calls DPAPI
    // without it cannot decrypt Blazma's values by accident.
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("Blazma.Sandbox/secrets/v1");

    public bool IsStrong => true;

    public string Protect(string plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        if (plaintext.Length == 0) return string.Empty;
        var encrypted = ProtectedData.Protect(Encoding.UTF8.GetBytes(plaintext), Entropy, DataProtectionScope.CurrentUser);
        return SecretProtector.DpapiPrefix + Convert.ToBase64String(encrypted);
    }

    public string? Unprotect(string stored)
    {
        if (string.IsNullOrEmpty(stored)) return null;
        if (!stored.StartsWith(SecretProtector.DpapiPrefix, StringComparison.Ordinal)) return SecretProtector.DecodeCommon(stored);
        try
        {
            var encrypted = Convert.FromBase64String(stored[SecretProtector.DpapiPrefix.Length..]);
            return SecretProtector.Text(ProtectedData.Unprotect(encrypted, Entropy, DataProtectionScope.CurrentUser));
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException)
        {
            return null;
        }
    }
}

/// <summary>
/// For platforms without DPAPI. Stores the value base64-encoded: this is obfuscation only. It
/// keeps a key from being read at a glance but protects nothing against anyone who can read
/// the settings file, so <see cref="IsStrong"/> is false and the UI can say so.
/// </summary>
public sealed class PortableSecretProtector : ISecretProtector
{
    public bool IsStrong => false;

    public string Protect(string plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        return plaintext.Length == 0 ? string.Empty : SecretProtector.EncodePlain(plaintext);
    }

    /// <summary>DPAPI values belong to a Windows account and cannot be read here: they give null.</summary>
    public string? Unprotect(string stored)
    {
        if (string.IsNullOrEmpty(stored) || stored.StartsWith(SecretProtector.DpapiPrefix, StringComparison.Ordinal)) return null;
        return SecretProtector.DecodeCommon(stored);
    }
}
