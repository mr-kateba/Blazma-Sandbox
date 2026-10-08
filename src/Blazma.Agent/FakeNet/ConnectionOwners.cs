using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using static Blazma.Agent.Native.NativeMethods;

namespace Blazma.Agent.FakeNet;

/// <summary>Finds which process owns the client side of a loopback connection, so simulated traffic is attributed to the sample.</summary>
[SupportedOSPlatform("windows")]
internal static class ConnectionOwners
{
    public static int? Find(int clientPort, int serverPort)
    {
        var size = 0;
        GetExtendedTcpTable(0, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (size <= 0 || size > 16 * 1024 * 1024) return null;
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buffer, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != 0) return null;
            var count = Marshal.ReadInt32(buffer);
            const int rowSize = 24; // state, localAddr, localPort, remoteAddr, remotePort, owningPid
            for (var i = 0; i < count; i++)
            {
                var row = buffer + 4 + i * rowSize;
                var localPort = PortOf(Marshal.ReadInt32(row, 8));
                var remotePort = PortOf(Marshal.ReadInt32(row, 16));
                if (localPort == clientPort && remotePort == serverPort) return Marshal.ReadInt32(row, 20);
            }
            return null;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>Ports are stored in network byte order in the low 16 bits.</summary>
    private static int PortOf(int raw) => BinaryPrimitives.ReverseEndianness((ushort)(raw & 0xFFFF));
}
