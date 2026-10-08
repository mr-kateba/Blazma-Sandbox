namespace Blazma.Agent.Capture;

/// <summary>Shrinks a BGRA frame by averaging blocks of pixels. Keeps screenshots small without a graphics library.</summary>
internal static class FrameScaler
{
    public static (byte[] Pixels, int Width, int Height) Downscale(byte[] bgra, int width, int height, int maxWidth)
    {
        if (width <= maxWidth) return (bgra, width, height);
        var factor = (int)Math.Ceiling(width / (double)maxWidth);
        var w = width / factor;
        var h = height / factor;
        var output = new byte[w * h * 4];
        var area = factor * factor;
        for (var y = 0; y < h; y++)
        {
            for (var x = 0; x < w; x++)
            {
                int b = 0, g = 0, r = 0;
                for (var dy = 0; dy < factor; dy++)
                {
                    var row = ((y * factor + dy) * width + x * factor) * 4;
                    for (var dx = 0; dx < factor; dx++, row += 4)
                    {
                        b += bgra[row];
                        g += bgra[row + 1];
                        r += bgra[row + 2];
                    }
                }
                var o = (y * w + x) * 4;
                output[o] = (byte)(b / area);
                output[o + 1] = (byte)(g / area);
                output[o + 2] = (byte)(r / area);
                output[o + 3] = 255;
            }
        }
        return (output, w, h);
    }
}
