using System.Buffers.Binary;
using System.Text;

namespace Blazma.Agent.FakeNet;

/// <summary>
/// Reads the server name (SNI) from the first TLS record a client sends. The name is
/// worth recording even when the client then refuses the simulated server's certificate.
/// </summary>
internal static class TlsClientHello
{
    public static bool TryGetServerName(ReadOnlySpan<byte> data, out string serverName)
    {
        serverName = string.Empty;
        try
        {
            // TLS record: type 22 (handshake), version (2), length (2)
            if (data.Length < 5 || data[0] != 22) return false;
            var recordLength = BinaryPrimitives.ReadUInt16BigEndian(data[3..]);
            var record = data[5..];
            if (record.Length > recordLength) record = record[..recordLength];

            // Handshake: type 1 (client hello), length (3)
            if (record.Length < 4 || record[0] != 1) return false;
            var p = 4;
            p += 2 + 32; // client version, random
            if (p >= record.Length) return false;
            p += 1 + record[p]; // session id
            if (p + 2 > record.Length) return false;
            p += 2 + BinaryPrimitives.ReadUInt16BigEndian(record[p..]); // cipher suites
            if (p >= record.Length) return false;
            p += 1 + record[p]; // compression methods
            if (p + 2 > record.Length) return false;
            var extensionsEnd = Math.Min(record.Length, p + 2 + BinaryPrimitives.ReadUInt16BigEndian(record[p..]));
            p += 2;

            while (p + 4 <= extensionsEnd)
            {
                var type = BinaryPrimitives.ReadUInt16BigEndian(record[p..]);
                var length = BinaryPrimitives.ReadUInt16BigEndian(record[(p + 2)..]);
                p += 4;
                if (p + length > extensionsEnd) return false;
                if (type == 0) return ReadServerNameList(record.Slice(p, length), out serverName);
                p += length;
            }
            return false;
        }
        catch (ArgumentOutOfRangeException)
        {
            return false;
        }
    }

    private static bool ReadServerNameList(ReadOnlySpan<byte> ext, out string serverName)
    {
        serverName = string.Empty;
        if (ext.Length < 2) return false;
        var listEnd = Math.Min(ext.Length, 2 + BinaryPrimitives.ReadUInt16BigEndian(ext));
        var p = 2;
        while (p + 3 <= listEnd)
        {
            var nameType = ext[p];
            var length = BinaryPrimitives.ReadUInt16BigEndian(ext[(p + 1)..]);
            p += 3;
            if (p + length > listEnd) return false;
            if (nameType == 0 && length is > 0 and <= 253)
            {
                var name = Encoding.ASCII.GetString(ext.Slice(p, length));
                if (!HostsFile.IsValidHostName(name)) return false;
                serverName = name.ToLowerInvariant();
                return true;
            }
            p += length;
        }
        return false;
    }
}
