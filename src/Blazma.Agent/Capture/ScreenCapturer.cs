using System.Runtime.Versioning;
using System.Security.Cryptography;
using Blazma.Agent.Native;
using Blazma.Contracts;
using static Blazma.Agent.Native.NativeMethods;

namespace Blazma.Agent.Capture;

/// <summary>
/// Periodic screenshots of the sandbox desktop (never the host's), sent as raw frames.
/// Identical consecutive frames are skipped so an idle desktop costs nothing.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class ScreenCapturer(EventSink sink, int intervalSeconds, int maxFrames, int maxWidth = 1280) : IDisposable
{
    private Timer? _timer;
    private int _index;
    private byte[]? _lastHash;
    private int _busy;

    public int Captured => _index;

    public void Start()
    {
        if (intervalSeconds <= 0 || maxFrames <= 0) return;
        _timer = new Timer(_ => CaptureOnce(), null, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(intervalSeconds));
    }

    /// <summary>Takes one screenshot now (also called at the end of the run).</summary>
    public void CaptureOnce()
    {
        if (Interlocked.Exchange(ref _busy, 1) == 1) return;
        try
        {
            if (_index >= maxFrames) return;
            if (Grab() is not { } frame) return;
            var hash = SHA256.HashData(frame.Pixels);
            if (_lastHash is not null && hash.AsSpan().SequenceEqual(_lastHash)) return;
            _lastHash = hash;
            var (pixels, w, h) = FrameScaler.Downscale(frame.Pixels, frame.Width, frame.Height, maxWidth);
            sink.WriteSigned(Protocol.ScreenshotName(++_index), RawFrame.Encode(w, h, Math.Max(0, sink.NowRelativeMs), pixels));
        }
        catch (Exception ex)
        {
            // A missed screenshot is not worth failing the run for; this runs on a timer, where an exception would end the agent.
            AgentLog.Limited("screenshot", "A screenshot failed", ex);
        }
        finally
        {
            Volatile.Write(ref _busy, 0);
        }
    }

    private static unsafe (byte[] Pixels, int Width, int Height)? Grab()
    {
        var x = GetSystemMetrics(SM_XVIRTUALSCREEN);
        var y = GetSystemMetrics(SM_YVIRTUALSCREEN);
        var width = Math.Min(GetSystemMetrics(SM_CXVIRTUALSCREEN), 3840);
        var height = Math.Min(GetSystemMetrics(SM_CYVIRTUALSCREEN), 2160);
        if (width <= 0 || height <= 0) return null;

        var screen = GetDC(0);
        if (screen == 0) return null;
        var memory = CreateCompatibleDC(screen);
        var bitmap = CreateCompatibleBitmap(screen, width, height);
        try
        {
            if (memory == 0 || bitmap == 0) return null;
            var old = SelectObject(memory, bitmap);
            var copied = BitBlt(memory, 0, 0, width, height, screen, x, y, SRCCOPY | CAPTUREBLT);
            SelectObject(memory, old);
            if (!copied) return null;

            // GetDIBits takes a BITMAPINFO; leave room for a colour table even though 32-bit BI_RGB has none.
            var infoBuffer = stackalloc byte[sizeof(BITMAPINFOHEADER) + 256 * 4];
            var info = (BITMAPINFOHEADER*)infoBuffer;
            *info = new BITMAPINFOHEADER
            {
                biSize = (uint)sizeof(BITMAPINFOHEADER),
                biWidth = width,
                biHeight = -height, // negative: top row first
                biPlanes = 1,
                biBitCount = 32,
            };
            var pixels = new byte[width * height * 4];
            fixed (byte* p = pixels)
            {
                var lines = GetDIBits(memory, bitmap, 0, (uint)height, p, info, DIB_RGB_COLORS);
                if (lines != height) return null;
            }
            return (pixels, width, height);
        }
        finally
        {
            if (bitmap != 0) DeleteObject(bitmap);
            if (memory != 0) DeleteDC(memory);
            ReleaseDC(0, screen);
        }
    }

    public void Dispose() => _timer?.Dispose();
}
