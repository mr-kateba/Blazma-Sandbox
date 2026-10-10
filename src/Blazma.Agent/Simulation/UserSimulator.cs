using System.Runtime.Versioning;
using Blazma.Agent.Native;
using static Blazma.Agent.Native.NativeMethods;

namespace Blazma.Agent.Simulation;

/// <summary>
/// A pretend user: moves the mouse now and then and presses the usual installer buttons
/// (accept, Next, Install, OK) in windows of other processes. Some samples wait for exactly
/// this before doing anything. Only standard Win32 buttons are pressed, and never one that
/// cancels or declines (see <see cref="InstallerButtons"/>).
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class UserSimulator(Action<string> note) : IDisposable
{
    private readonly int _self = Environment.ProcessId;
    private readonly Random _random = new();
    private readonly Dictionary<nint, int> _clicksPerButton = [];
    private Timer? _mouse;
    private Timer? _buttons;
    private int _busy;

    public int Clicks { get; private set; }

    public void Start()
    {
        _mouse = new Timer(_ =>
        {
            try { MoveMouse(); }
            catch (Exception ex) { AgentLog.Limited("simulated-mouse", "Moving the mouse failed", ex); }
        }, null, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(2));
        _buttons = new Timer(_ => PressButtons(), null, TimeSpan.FromSeconds(4), TimeSpan.FromSeconds(3));
    }

    private void MoveMouse()
    {
        var w = Math.Max(200, GetSystemMetrics(SM_CXVIRTUALSCREEN));
        var h = Math.Max(200, GetSystemMetrics(SM_CYVIRTUALSCREEN));
        SetCursorPos(_random.Next(50, w - 50), _random.Next(50, h - 50));
    }

    private void PressButtons()
    {
        if (Interlocked.Exchange(ref _busy, 1) == 1) return;
        try
        {
            var windows = new List<nint>();
            EnumWindows((hwnd, _) =>
            {
                if (IsWindowVisible(hwnd) && GetWindowThreadProcessId(hwnd, out var pid) != 0 && pid != _self) windows.Add(hwnd);
                return windows.Count < 200;
            }, 0);

            foreach (var window in windows)
            {
                var buttons = new List<(nint Hwnd, string Text, int Type)>();
                EnumChildWindows(window, (child, _) =>
                {
                    if (ClassOf(child).Equals("Button", StringComparison.OrdinalIgnoreCase))
                    {
                        var style = GetWindowLong(child, GWL_STYLE);
                        if ((style & WS_VISIBLE) != 0 && (style & WS_DISABLED) == 0) buttons.Add((child, TextOf(child), style & BS_TYPEMASK));
                    }
                    return buttons.Count < 100;
                }, 0);

                // Tick "I accept" first, then press one advancing button per window per round.
                foreach (var b in buttons.Where(b => InstallerButtons.Decide(b.Text, b.Type) == ButtonAction.Accept)) Click(b.Hwnd, b.Text, onlyOnce: true);
                var next = buttons.FirstOrDefault(b => InstallerButtons.Decide(b.Text, b.Type) == ButtonAction.Advance);
                if (next.Hwnd != 0) Click(next.Hwnd, next.Text, onlyOnce: false);
            }
        }
        catch (Exception ex)
        {
            // Runs on a timer, where an exception would end the agent.
            AgentLog.Limited("simulated-buttons", "Pressing installer buttons failed", ex);
        }
        finally
        {
            Volatile.Write(ref _busy, 0);
        }
    }

    private void Click(nint button, string text, bool onlyOnce)
    {
        _clicksPerButton.TryGetValue(button, out var count);
        if (onlyOnce && count > 0) return;
        if (count >= 5) return; // a button that keeps coming back is probably a loop; leave it
        _clicksPerButton[button] = count + 1;
        if (PostMessage(button, BM_CLICK, 0, 0))
        {
            Clicks++;
            note($"Simulated user pressed \"{InstallerButtons.Normalize(text)}\"");
        }
    }

    private static unsafe string ClassOf(nint hwnd)
    {
        var buffer = stackalloc char[64];
        var n = GetClassName(hwnd, buffer, 64);
        return n > 0 ? new string(buffer, 0, n) : string.Empty;
    }

    private static unsafe string TextOf(nint hwnd)
    {
        var buffer = stackalloc char[128];
        // A hung window must not hang the simulator: time out instead of SendMessage.
        if (SendMessageTimeout(hwnd, WM_GETTEXT, 128, buffer, SMTO_ABORTIFHUNG, 500, out var length) == 0) return string.Empty;
        var n = (int)Math.Clamp(length, 0, 127);
        return new string(buffer, 0, n);
    }

    public void Dispose()
    {
        _mouse?.Dispose();
        _buttons?.Dispose();
    }
}
