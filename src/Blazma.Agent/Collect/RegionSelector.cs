namespace Blazma.Agent.Collect;

internal sealed record RegionInfo(ulong Base, long Size, uint Protect, uint Type, bool IsImageBacked, bool StartsWithPe);

internal sealed record SelectedRegion(RegionInfo Region, string Kind, string Protection);

/// <summary>
/// Picks the memory regions worth dumping: executable private memory (unpacked or
/// injected code), RWX regions, and program images with no file behind them (hollowing).
/// Regions holding a PE header come first because they are the strongest signal.
/// </summary>
internal static class RegionSelector
{
    private const uint MEM_PRIVATE = 0x20000, MEM_IMAGE = 0x1000000;
    private const uint PAGE_EXECUTE = 0x10, PAGE_EXECUTE_READ = 0x20, PAGE_EXECUTE_READWRITE = 0x40, PAGE_EXECUTE_WRITECOPY = 0x80;
    public const long MinRegionBytes = 4096;

    public static IReadOnlyList<SelectedRegion> Select(IEnumerable<RegionInfo> regions, int maxRegions, long maxBytesPerRegion)
    {
        var picked = new List<(SelectedRegion Region, int Rank)>();
        foreach (var r in regions)
        {
            if (r.Size < MinRegionBytes) continue;
            var exec = (r.Protect & 0xFF) is PAGE_EXECUTE or PAGE_EXECUTE_READ or PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_WRITECOPY;
            var rwx = (r.Protect & 0xFF) is PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_WRITECOPY;
            string? kind = null;
            var rank = 0;
            if (r.Type == MEM_IMAGE && !r.IsImageBacked && exec) { kind = "unbacked-image"; rank = 4; }
            else if (r.Type == MEM_PRIVATE && rwx) { kind = "rwx"; rank = 2; }
            else if (r.Type == MEM_PRIVATE && exec) { kind = "private-exec"; rank = 1; }
            if (kind is null) continue;
            if (r.StartsWithPe) rank += 10;
            picked.Add((new SelectedRegion(r with { Size = Math.Min(r.Size, maxBytesPerRegion) }, kind, Describe(r.Protect)), rank));
        }
        return picked.OrderByDescending(p => p.Rank).ThenByDescending(p => p.Region.Region.Size).Take(maxRegions).Select(p => p.Region).ToList();
    }

    public static string Describe(uint protect) => (protect & 0xFF) switch
    {
        PAGE_EXECUTE => "X",
        PAGE_EXECUTE_READ => "RX",
        PAGE_EXECUTE_READWRITE => "RWX",
        PAGE_EXECUTE_WRITECOPY => "RWX (copy-on-write)",
        0x02 => "R",
        0x04 => "RW",
        _ => $"0x{protect:X}",
    };
}
