using System.Security.Cryptography;
using System.Text;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Sandbox.Imaging;

namespace Blazma.Sandbox.Providers.Demo;

/// <summary>
/// Synthetic artifacts for demo runs so every screen can be explored without Windows:
/// drawn screenshots, a placeholder "dropped" file and a placeholder memory region. None of
/// it is executable; the bytes only contain text that the analyzers can find.
/// </summary>
internal static class DemoArtifacts
{
    private const int Width = 960, Height = 600;

    /// <summary>Draws a desktop with an installer window at a given progress (0..1).</summary>
    public static CollectedScreenshot Screenshot(string folder, int index, TimeSpan at, double progress)
    {
        var px = new byte[Width * Height * 4];
        Fill(px, 0, 0, Width, Height, 0x1C, 0x1C, 0x22);                 // desktop
        Fill(px, 0, Height - 36, Width, 36, 0x12, 0x12, 0x16);            // taskbar
        Fill(px, 240, 150, 480, 300, 0xF2, 0xF2, 0xF5);                   // window
        Fill(px, 240, 150, 480, 32, 0xFF, 0x6D, 0x00);                    // title bar
        Fill(px, 270, 330, 420, 18, 0xD8, 0xD8, 0xDE);                    // progress track
        Fill(px, 270, 330, (int)(420 * Math.Clamp(progress, 0, 1)), 18, 0x34, 0xD3, 0x99);
        Fill(px, 590, 400, 100, 30, 0xFF, 0x6D, 0x00);                    // "Next" button
        Directory.CreateDirectory(Path.Combine(folder, "screenshots"));
        var path = Path.Combine(folder, "screenshots", $"{index:D4}.png");
        File.WriteAllBytes(path, PngEncoder.EncodeBgra(Width, Height, px));
        return new CollectedScreenshot(at, path, Width, Height);
    }

    public static CollectedDroppedFile DroppedUpdater(string folder, string userProfile)
    {
        var text = "BLAZMA DEMO PLACEHOLDER - not a program.\n" +
                   "update-url=http://cdn.contoso-update.example/v2/payload.bin\n" +
                   "mutex=Global\\ContosoUpdaterMutex\n" +
                   "ua=Mozilla/5.0 (Windows NT 10.0; Win64; x64) ContosoUpdate/2.1\n";
        return Store(folder, "dropped", 1, Encoding.ASCII.GetBytes(text), bytes =>
            new CollectedDroppedFile($@"{userProfile}\AppData\Roaming\ContosoUpdate\updater.exe", "setup.exe", "", "", bytes.Length));
    }

    public static CollectedMemoryRegion InjectedRegion(string folder)
    {
        var data = new byte[16 * 1024];
        "MZ"u8.CopyTo(data);
        Encoding.ASCII.GetBytes("BLAZMA DEMO PLACEHOLDER: decoded configuration\0c2=https://gate.contoso-update.example/api\0backup=203.0.113.24:4443\0")
            .CopyTo(data, 0x200);
        var stored = Store(folder, "memory", 1, data, bytes =>
            new CollectedDroppedFile("", "updater.exe", "", "", bytes.Length));
        return new CollectedMemoryRegion(6044, "updater.exe", 0x1F0000, data.Length, "RWX", MemoryRegionKind.ReadWriteExecute, stored.StoredPath, stored.Sha256);
    }

    private static CollectedDroppedFile Store(string folder, string sub, int index, byte[] bytes, Func<byte[], CollectedDroppedFile> describe)
    {
        var dir = Directory.CreateDirectory(Path.Combine(folder, sub)).FullName;
        var path = Path.Combine(dir, $"{index:D4}.bin");
        File.WriteAllBytes(path, bytes);
        return describe(bytes) with { StoredPath = path, Sha256 = Convert.ToHexStringLower(SHA256.HashData(bytes)) };
    }

    private static void Fill(byte[] px, int x, int y, int w, int h, byte r, byte g, byte b)
    {
        for (var yy = Math.Max(0, y); yy < Math.Min(Height, y + h); yy++)
            for (var xx = Math.Max(0, x); xx < Math.Min(Width, x + w); xx++)
            {
                var o = (yy * Width + xx) * 4;
                px[o] = b; px[o + 1] = g; px[o + 2] = r; px[o + 3] = 255;
            }
    }
}
