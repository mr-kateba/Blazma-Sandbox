using System.Security.Cryptography;

namespace Blazma.Analysis.Static;

/// <summary>
/// Checksum validation for cryptocurrency addresses. A 34-character run of letters and digits is
/// common in binaries; one whose checksum also verifies is almost certainly a real address, so
/// the checksum is what keeps wallet extraction free of false positives.
/// </summary>
internal static class CryptoAddresses
{
    private const string Base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private const string Bech32Alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    private const uint Bech32Constant = 1;
    private const uint Bech32mConstant = 0x2bc830a3;

    /// <summary>A legacy (P2PKH, "1…") or script (P2SH, "3…") Bitcoin address with a valid Base58Check checksum.</summary>
    public static bool IsBitcoinBase58(string address)
    {
        var bytes = DecodeBase58(address);
        if (bytes is not { Length: 25 } || bytes[0] is not (0x00 or 0x05)) return false;
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(bytes.AsSpan(0, 21), hash);
        SHA256.HashData(hash, hash);
        return hash[..4].SequenceEqual(bytes.AsSpan(21, 4));
    }

    /// <summary>
    /// A SegWit Bitcoin address ("bc1…"): bech32 for witness version 0, bech32m for later versions
    /// (BIP 173 and BIP 350), with the program length each version allows.
    /// </summary>
    public static bool IsBitcoinBech32(string address)
    {
        if (address.Length is < 14 or > 74) return false;
        if (address.Any(char.IsUpper) && address.Any(char.IsLower)) return false;
        var a = address.ToLowerInvariant();
        var sep = a.LastIndexOf('1');
        if (sep != 2 || !a.StartsWith("bc", StringComparison.Ordinal) || a.Length - sep - 1 < 7) return false;

        var data = new byte[a.Length - sep - 1];
        for (var i = 0; i < data.Length; i++)
        {
            var v = Bech32Alphabet.IndexOf(a[sep + 1 + i], StringComparison.Ordinal);
            if (v < 0) return false;
            data[i] = (byte)v;
        }

        var check = Polymod([3, 3, 0, 2, 3, .. data]); // "bc" expanded: high bits, 0, low bits
        var version = data[0];
        if (version > 16) return false;
        if (check != (version == 0 ? Bech32Constant : Bech32mConstant)) return false;

        var program = ConvertBits(data.AsSpan(1, data.Length - 7));
        if (program is null || program.Length is < 2 or > 40) return false;
        return version != 0 || program.Length is 20 or 32;
    }

    /// <summary>A Monero address: 95 Base58 characters starting "4" (standard) or "8" (subaddress).</summary>
    /// <remarks>Monero's checksum needs Keccak, which .NET does not provide everywhere; the prefix and length are checked.</remarks>
    public static bool IsMonero(string address) =>
        address.Length == 95 && (address[0] is '4' or '8') && (address[1] is (>= '0' and <= '9') or 'A' or 'B')
        && address.All(c => Base58Alphabet.Contains(c, StringComparison.Ordinal));

    /// <summary>An Ethereum address ("0x" + 40 hex digits) that is not a placeholder such as all zeros.</summary>
    public static bool IsEthereum(string address) =>
        address.Length == 42 && address.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
        && address.Skip(2).All(char.IsAsciiHexDigit) && address.Skip(2).Distinct().Count() >= 6;

    internal static byte[]? DecodeBase58(string text)
    {
        if (text.Length is 0 or > 128) return null;
        var bytes = new List<byte>(text.Length);
        foreach (var c in text)
        {
            var carry = Base58Alphabet.IndexOf(c, StringComparison.Ordinal);
            if (carry < 0) return null;
            for (var i = 0; i < bytes.Count; i++)
            {
                carry += bytes[i] * 58;
                bytes[i] = (byte)(carry & 0xFF);
                carry >>= 8;
            }
            for (; carry > 0; carry >>= 8) bytes.Add((byte)(carry & 0xFF));
        }
        foreach (var c in text)
        {
            if (c != '1') break;
            bytes.Add(0);
        }
        bytes.Reverse();
        return [.. bytes];
    }

    private static uint Polymod(ReadOnlySpan<byte> values)
    {
        ReadOnlySpan<uint> gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
        uint chk = 1;
        foreach (var v in values)
        {
            var top = chk >> 25;
            chk = ((chk & 0x1ffffff) << 5) ^ v;
            for (var i = 0; i < 5; i++)
                if (((top >> i) & 1) != 0) chk ^= gen[i];
        }
        return chk;
    }

    /// <summary>Regroups 5-bit values into bytes; null when the padding is not zero, as BIP 173 requires.</summary>
    private static byte[]? ConvertBits(ReadOnlySpan<byte> data)
    {
        int acc = 0, bits = 0;
        var result = new List<byte>(data.Length * 5 / 8);
        foreach (var v in data)
        {
            acc = ((acc << 5) | v) & 0xFFF;
            bits += 5;
            if (bits >= 8)
            {
                bits -= 8;
                result.Add((byte)((acc >> bits) & 0xFF));
            }
        }
        if (bits >= 5 || ((acc << (8 - bits)) & 0xFF) != 0) return null;
        return [.. result];
    }
}
