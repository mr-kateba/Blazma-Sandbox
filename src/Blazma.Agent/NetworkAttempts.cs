using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Globalization;
using System.Net;

namespace Blazma.Agent;

/// <summary>
/// Reads the remote address from the binary socket address (SOCKADDR) that the Winsock-AFD
/// and TCPIP providers put in their connect events. Pure, so it is tested anywhere.
/// </summary>
internal static class SocketAddressParser
{
    private const ushort AfInet = 2;
    private const ushort AfInet6 = 23;

    /// <summary>
    /// SOCKADDR_IN (family, port big-endian, 4 address bytes) or SOCKADDR_IN6 (family, port, flow
    /// info, 16 address bytes, scope). An IPv4-mapped IPv6 address (dual-stack sockets, e.g. .NET's
    /// default) is returned as plain IPv4 so the same server is one destination.
    /// </summary>
    public static bool TryParse(ReadOnlySpan<byte> data, out string address, out int port)
    {
        address = string.Empty;
        port = 0;
        if (data.Length < 8) return false;
        var family = BinaryPrimitives.ReadUInt16LittleEndian(data);
        port = BinaryPrimitives.ReadUInt16BigEndian(data[2..]);
        switch (family)
        {
            case AfInet:
                address = new IPAddress(data.Slice(4, 4)).ToString();
                return true;
            case AfInet6 when data.Length >= 24:
                var ip = new IPAddress(data.Slice(8, 16));
                address = ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4().ToString() : ip.ToString();
                return true;
            default:
                port = 0;
                return false;
        }
    }

    /// <summary>
    /// Accepts what an ETW parser hands over for the field: the raw bytes (the manifest declares
    /// win:Binary), or text when a decoder formatted it ("1.2.3.4:80", "[2001:db8::1]:443", hex).
    /// </summary>
    public static bool TryParse(object? payload, out string address, out int port)
    {
        address = string.Empty;
        port = 0;
        switch (payload)
        {
            case byte[] bytes:
                return TryParse(bytes, out address, out port);
            case string text when text.Length > 0:
                var t = text.Trim();
                if (t.StartsWith("0x", StringComparison.OrdinalIgnoreCase) && t.Length % 2 == 0)
                {
                    try { return TryParse(Convert.FromHexString(t.AsSpan(2)), out address, out port); }
                    catch (FormatException) { return false; }
                }
                if (!IPEndPoint.TryParse(t, out var endpoint)) return false;
                var ip = endpoint.Address.IsIPv4MappedToIPv6 ? endpoint.Address.MapToIPv4() : endpoint.Address;
                address = ip.ToString();
                port = endpoint.Port;
                return true;
            default:
                return false;
        }
    }
}

/// <summary>The ETW providers and event ids that report connection attempts, with the remote address.</summary>
internal static class AttemptEvents
{
    /// <summary>
    /// Microsoft-Windows-Winsock-AFD: the socket layer. Its connect and send-to events carry the
    /// remote socket address as the program asked for it, so an attempt is seen even when it never
    /// reaches the wire (no network adapter, no route), which the kernel TcpIp events miss: those
    /// only report connections that succeeded.
    /// </summary>
    internal static readonly Guid WinsockAfd = new("E53C6823-7BB8-44BB-90DC-3F86090D48A6");

    /// <summary>Microsoft-Windows-TCPIP: its connect-failure events name the remote address, the status and the process.</summary>
    internal static readonly Guid TcpIp = new("2F07E2EE-15DB-40F1-90EF-9D7BA282188A");

    /// <summary>Event ids of the Winsock-AFD manifest (Windows 10 and 11).</summary>
    internal static class Afd
    {
        public const ulong KeywordSourceWinsock = 0x4;
        public const int Create = 1000;                   // AfdCreate/Open: Endpoint, AddressFamily, SocketType, Protocol
        public const int Close = 1001;                    // AfdClose/Closed
        public const int SendToWithAddress = 1007;        // AfdSendToWithAddress: Endpoint, Status, Address (SOCKADDR)
        public const int Connect = 1017;                  // AfdConnect: Endpoint, Status (no address)
        public const int ConnectWithAddress = 1018;       // AfdConnectWithAddress: Endpoint, Status, Address (SOCKADDR)
        public const int ConnectEx = 1020;                // AfdConnectEx: Endpoint, Status (no address)
        public const int ConnectExWithAddress = 1021;     // AfdConnectExWithAddress: Endpoint, Status, Address (SOCKADDR)
        public static readonly int[] Enabled = [Create, Close, SendToWithAddress, Connect, ConnectWithAddress, ConnectEx, ConnectExWithAddress];
    }

    /// <summary>Event ids of the TCPIP manifest: connect failures (version 1 adds ProcessId).</summary>
    internal static class Tcp
    {
        public const ulong KeywordConnectPath = 0x400000000;
        public const int FailedAddressFamily = 1018;      // TcpConnectTcbFailedAf
        public const int FailedCompartment = 1019;        // TcpConnectTcbFailedCompartment
        public const int FailedInspect = 1020;            // TcpConnectTcbFailedInspect: refused by the filtering platform
        public const int FailedRoute = 1021;              // TcpConnectTcbFailedRoute: no route (no network)
        public const int Failure = 1034;                  // TcpConnectTcbFailure: refused, timed out, reset
        public const int FailedPortAcquire = 1050;        // TcpConnectFailedPortAcquire
        public static readonly int[] Enabled = [FailedAddressFamily, FailedCompartment, FailedInspect, FailedRoute, Failure, FailedPortAcquire];
    }
}

/// <summary>Turns the numbers ETW parsers return (int, uint, long, ulong or text) into one type.</summary>
internal static class EtwValue
{
    public static long? Number(object? value) => value switch
    {
        null => null,
        int i => i,
        uint u => u,
        long l => l,
        ulong ul => unchecked((long)ul),
        short s => s,
        ushort us => us,
        byte b => b,
        string t when t.StartsWith("0x", StringComparison.OrdinalIgnoreCase) && ulong.TryParse(t.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var h) => unchecked((long)h),
        string t when long.TryParse(t, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) => n,
        _ => null,
    };

    /// <summary>
    /// True for an NTSTATUS error (severity bits 11). Success, STATUS_PENDING (0x103: a
    /// non-blocking connect still in progress) and warnings are not failures.
    /// </summary>
    public static bool IsFailure(long? status) => status is { } s && unchecked((uint)s) >= 0xC0000000;

    /// <summary>An NTSTATUS as Windows prints it: "0xC000023C".</summary>
    public static string Hex(long status) => "0x" + unchecked((uint)status).ToString("X8", CultureInfo.InvariantCulture);
}

/// <summary>What the agent writes for one observed attempt (see <see cref="ConnectAttempts.Attempt"/>).</summary>
internal enum AttemptReport
{
    /// <summary>Already reported: only the counter changed.</summary>
    None,

    /// <summary>First attempt to this destination by this process.</summary>
    Attempted,

    /// <summary>First failure for this destination by this process.</summary>
    Failed,
}

/// <summary>
/// Folds connection attempts together: a program that retries the same server every second
/// must give one row with a count, not thousands of events. The first attempt and the first
/// failure per (process, address, port, protocol) are reported right away; the totals at
/// the end (<see cref="Totals"/>). Bounded, because a scanning sample tries many addresses.
/// </summary>
internal sealed class ConnectAttempts(int maxDestinations = ConnectAttempts.DefaultMaxDestinations)
{
    public const int DefaultMaxDestinations = 2000;

    private readonly ConcurrentDictionary<(int Pid, string Address, int Port, string Protocol), Entry> _entries = new();
    private long _overflow;

    /// <summary>Attempts not tracked because <c>maxDestinations</c> was reached.</summary>
    public long Overflow => Interlocked.Read(ref _overflow);

    /// <summary>One attempt (a connect or send naming the address). <paramref name="failed"/>: Windows already said it failed.</summary>
    public AttemptReport Attempt(int pid, string address, int port, string protocol, bool failed = false, long? status = null)
    {
        if (Get(pid, address, port, protocol, create: true) is not { } entry) return AttemptReport.None;
        lock (entry)
        {
            entry.Count++;
            return failed ? MarkFailed(entry, status) : MarkReported(entry);
        }
    }

    /// <summary>
    /// The outcome of an attempt, reported by another event (a completion, or the TCP/IP stack's
    /// failure event). It is the same attempt, so it is not counted again; without an attempt
    /// seen before, it counts as one.
    /// </summary>
    public AttemptReport Failure(int pid, string address, int port, string protocol, long? status)
    {
        if (Get(pid, address, port, protocol, create: false) is not { } entry) return Attempt(pid, address, port, protocol, failed: true, status);
        lock (entry) return MarkFailed(entry, status);
    }

    private Entry? Get(int pid, string address, int port, string protocol, bool create)
    {
        var key = (pid, address, port, protocol);
        if (_entries.TryGetValue(key, out var entry)) return entry;
        if (!create) return null;
        if (_entries.Count >= maxDestinations)
        {
            Interlocked.Increment(ref _overflow);
            return null;
        }
        return _entries.GetOrAdd(key, _ => new Entry());
    }

    private static AttemptReport MarkReported(Entry entry)
    {
        if (entry.Reported) return AttemptReport.None;
        entry.Reported = true;
        return AttemptReport.Attempted;
    }

    private static AttemptReport MarkFailed(Entry entry, long? status)
    {
        entry.Failed = true;
        if (status is not null) entry.LastFailure = status;
        if (entry.FailureReported) return AttemptReport.None;
        entry.FailureReported = entry.Reported = true;
        return AttemptReport.Failed;
    }

    public IReadOnlyList<AttemptTotal> Totals() =>
        _entries.Select(kv =>
        {
            lock (kv.Value) return new AttemptTotal(kv.Key.Pid, kv.Key.Address, kv.Key.Port, kv.Key.Protocol, kv.Value.Count, kv.Value.Failed, kv.Value.LastFailure);
        }).ToList();

    private sealed class Entry
    {
        public int Count;
        public bool Reported;
        public bool FailureReported;
        public bool Failed;
        public long? LastFailure;
    }
}

internal sealed record AttemptTotal(int Pid, string Address, int Port, string Protocol, int Count, bool Failed, long? LastFailure);

/// <summary>The DNS client reports answers as text: "type:  5 cdn.example;::ffff:203.0.113.7;". Only the addresses matter.</summary>
internal static class DnsAnswers
{
    /// <param name="dropLoopback">True with the simulated internet, whose hosts file answers 127.0.0.1 for everything.</param>
    public static IReadOnlyList<string> Addresses(string? results, bool dropLoopback)
    {
        if (string.IsNullOrWhiteSpace(results)) return [];
        var list = new List<string>();
        foreach (var part in results.Split([';', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!IPAddress.TryParse(part, out var ip)) continue; // "type: 5 name" (CNAME) and other records
            if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
            if (dropLoopback && IPAddress.IsLoopback(ip)) continue;
            var text = ip.ToString();
            if (!list.Contains(text, StringComparer.OrdinalIgnoreCase)) list.Add(text);
            if (list.Count >= 32) break;
        }
        return list;
    }
}
