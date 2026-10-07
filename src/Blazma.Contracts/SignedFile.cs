using System.Security.Cryptography;
using System.Text;

namespace Blazma.Contracts;

/// <summary>
/// Files the agent writes to <c>out/</c> end with an HMAC-SHA256 trailer line:
/// <c>\n#mac:&lt;hex&gt;\n</c>. The key is handed to the agent through the read-only
/// <c>in/session.json</c>, which the host removes as soon as the agent has said hello,
/// before the sample starts. A sample that forges or edits monitoring output therefore
/// has to extract the key from the agent's memory first; files that fail verification
/// are rejected and reported as tampering.
/// </summary>
public static class SignedFile
{
    private static readonly byte[] Marker = "\n#mac:"u8.ToArray();
    public const int KeyBytes = 32;

    public static byte[] NewKey() => RandomNumberGenerator.GetBytes(KeyBytes);

    public static byte[] Sign(ReadOnlySpan<byte> content, byte[] key)
    {
        var mac = Convert.ToHexStringLower(HMACSHA256.HashData(key, content));
        var trailer = Encoding.ASCII.GetBytes(mac + "\n");
        var result = new byte[content.Length + Marker.Length + trailer.Length];
        content.CopyTo(result);
        Marker.CopyTo(result, content.Length);
        trailer.CopyTo(result, content.Length + Marker.Length);
        return result;
    }

    /// <summary>Returns the content without the trailer if the MAC is valid; null otherwise.</summary>
    public static byte[]? Verify(ReadOnlySpan<byte> file, byte[] key)
    {
        var at = file.LastIndexOf(Marker);
        if (at < 0) return null;
        var content = file[..at];
        var macText = Encoding.ASCII.GetString(file[(at + Marker.Length)..]).Trim();
        if (macText.Length != 64) return null;
        byte[] expected;
        try { expected = Convert.FromHexString(macText); }
        catch (FormatException) { return null; }
        var actual = HMACSHA256.HashData(key, content);
        return CryptographicOperations.FixedTimeEquals(actual, expected) ? content.ToArray() : null;
    }
}
