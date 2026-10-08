using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;
using Blazma.Contracts;
using static Blazma.Agent.Native.NativeMethods;

namespace Blazma.Agent.Collect;

/// <summary>
/// Dumps suspicious memory of the analyzed processes: executable private memory, RWX
/// regions and images with no file behind them. Runs a few times during the analysis, so
/// code unpacked by a process that later exits is still caught. Same bytes are sent once.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class MemoryDumper(EventSink sink, long maxTotalBytes)
{
    private const int MaxRegionsPerProcess = 8;
    private readonly HashSet<string> _hashes = new(StringComparer.OrdinalIgnoreCase);
    private long _written;
    private int _index;
    private readonly object _lock = new();

    public int Regions => _index;

    public void Scan(IEnumerable<(int Pid, string Name)> processes)
    {
        lock (_lock)
        {
            foreach (var (pid, name) in processes)
            {
                if (_written >= maxTotalBytes || _index >= Protocol.Limits.MaxMemoryRegions) return;
                ScanProcess(pid, name);
            }
        }
    }

    private unsafe void ScanProcess(int pid, string name)
    {
        var process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, (uint)pid);
        if (process == 0) return;
        try
        {
            var regions = new List<RegionInfo>();
            nint address = 0;
            var guard = 0;
            while (guard++ < 100_000 && VirtualQueryEx(process, address, out var mbi, sizeof(MEMORY_BASIC_INFORMATION)) != 0)
            {
                if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0 && (mbi.Protect & 0xF0) != 0)
                {
                    var backed = mbi.Type != MEM_IMAGE || HasMappedFile(process, mbi.BaseAddress);
                    regions.Add(new RegionInfo((ulong)mbi.BaseAddress, mbi.RegionSize, mbi.Protect, mbi.Type, backed, StartsWithPe(process, mbi.BaseAddress)));
                }
                var next = (long)mbi.BaseAddress + (long)mbi.RegionSize;
                if (next <= (long)address) break;
                address = (nint)next;
            }

            foreach (var selected in RegionSelector.Select(regions, MaxRegionsPerProcess, Protocol.Limits.MaxMemoryRegionBytes))
            {
                if (_written + selected.Region.Size > maxTotalBytes || _index >= Protocol.Limits.MaxMemoryRegions) return;
                var data = new byte[selected.Region.Size];
                nint read;
                fixed (byte* p = data)
                {
                    if (!ReadProcessMemory(process, (nint)selected.Region.Base, p, data.Length, out read) || read <= 0) continue;
                }
                if (read < data.Length) Array.Resize(ref data, (int)read);
                var sha = Convert.ToHexStringLower(SHA256.HashData(data));
                if (!_hashes.Add(sha)) continue;

                _index++;
                _written += data.Length;
                sink.WriteSigned(Protocol.MemoryDataName(_index), data);
                sink.WriteSigned(Protocol.MemoryMetaName(_index), JsonSerializer.SerializeToUtf8Bytes(new MemoryRegionDto
                {
                    ProcessId = pid,
                    ProcessName = name,
                    BaseAddress = selected.Region.Base,
                    Size = data.Length,
                    Protection = selected.Protection,
                    Kind = selected.Kind,
                    Sha256 = sha,
                }, ProtocolJson.Default.MemoryRegionDto));
            }
        }
        finally
        {
            CloseHandle(process);
        }
    }

    private static unsafe bool HasMappedFile(nint process, nint address)
    {
        var buffer = stackalloc char[260];
        return GetMappedFileName(process, address, buffer, 260) > 0;
    }

    private static unsafe bool StartsWithPe(nint process, nint address)
    {
        var head = stackalloc byte[2];
        return ReadProcessMemory(process, address, head, 2, out var read) && read == 2 && head[0] == (byte)'M' && head[1] == (byte)'Z';
    }
}
