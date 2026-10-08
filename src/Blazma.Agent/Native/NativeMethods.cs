using System.Runtime.InteropServices;

namespace Blazma.Agent.Native;

/// <summary>Win32 functions the agent uses. Every call site checks return values; failures degrade a feature, never the run.</summary>
internal static partial class NativeMethods
{
    // ---- GDI / screen capture ----
    public const int SM_XVIRTUALSCREEN = 76, SM_YVIRTUALSCREEN = 77, SM_CXVIRTUALSCREEN = 78, SM_CYVIRTUALSCREEN = 79;
    public const uint SRCCOPY = 0x00CC0020, CAPTUREBLT = 0x40000000;
    public const uint DIB_RGB_COLORS = 0;

    [StructLayout(LayoutKind.Sequential)]
    public struct BITMAPINFOHEADER
    {
        public uint biSize;
        public int biWidth;
        public int biHeight;
        public ushort biPlanes;
        public ushort biBitCount;
        public uint biCompression;
        public uint biSizeImage;
        public int biXPelsPerMeter;
        public int biYPelsPerMeter;
        public uint biClrUsed;
        public uint biClrImportant;
    }

    [LibraryImport("user32.dll")] public static partial int GetSystemMetrics(int index);
    [LibraryImport("user32.dll")] public static partial nint GetDC(nint hwnd);
    [LibraryImport("user32.dll")] public static partial int ReleaseDC(nint hwnd, nint hdc);
    [LibraryImport("gdi32.dll")] public static partial nint CreateCompatibleDC(nint hdc);
    [LibraryImport("gdi32.dll")] public static partial nint CreateCompatibleBitmap(nint hdc, int width, int height);
    [LibraryImport("gdi32.dll")] public static partial nint SelectObject(nint hdc, nint obj);
    [LibraryImport("gdi32.dll")] [return: MarshalAs(UnmanagedType.Bool)] public static partial bool DeleteObject(nint obj);
    [LibraryImport("gdi32.dll")] [return: MarshalAs(UnmanagedType.Bool)] public static partial bool DeleteDC(nint hdc);
    [LibraryImport("gdi32.dll")] [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool BitBlt(nint dest, int x, int y, int width, int height, nint src, int srcX, int srcY, uint rop);
    [LibraryImport("gdi32.dll")]
    public static unsafe partial int GetDIBits(nint hdc, nint bitmap, uint start, uint lines, byte* bits, BITMAPINFOHEADER* info, uint usage);

    // ---- Windows and input (user simulation) ----
    public const uint WM_GETTEXT = 0x000D, WM_GETTEXTLENGTH = 0x000E, BM_CLICK = 0x00F5, BM_GETCHECK = 0x00F0;
    public const int GWL_STYLE = -16;
    public const int WS_VISIBLE = 0x10000000, WS_DISABLED = 0x08000000;
    public const int BS_TYPEMASK = 0x0F, BS_PUSHBUTTON = 0, BS_DEFPUSHBUTTON = 1, BS_CHECKBOX = 2, BS_AUTOCHECKBOX = 3, BS_RADIOBUTTON = 4, BS_AUTORADIOBUTTON = 9;
    public const uint SMTO_ABORTIFHUNG = 0x0002;

    public delegate bool EnumWindowsProc(nint hwnd, nint lParam);

    // Delegate callbacks need the classic marshaller; the source generator does not support them.
#pragma warning disable SYSLIB1054
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool EnumWindows(EnumWindowsProc callback, nint lParam);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool EnumChildWindows(nint parent, EnumWindowsProc callback, nint lParam);
#pragma warning restore SYSLIB1054
    [LibraryImport("user32.dll", EntryPoint = "GetClassNameW", StringMarshalling = StringMarshalling.Utf16)]
    public static unsafe partial int GetClassName(nint hwnd, char* buffer, int max);
    [LibraryImport("user32.dll", EntryPoint = "GetWindowLongW")] public static partial int GetWindowLong(nint hwnd, int index);
    [LibraryImport("user32.dll")] public static partial uint GetWindowThreadProcessId(nint hwnd, out uint processId);
    [LibraryImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] public static partial bool IsWindowVisible(nint hwnd);
    [LibraryImport("user32.dll", EntryPoint = "SendMessageTimeoutW")]
    public static unsafe partial nint SendMessageTimeout(nint hwnd, uint msg, nint wParam, char* lParam, uint flags, uint timeoutMs, out nint result);
    [LibraryImport("user32.dll", EntryPoint = "PostMessageW")] [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool PostMessage(nint hwnd, uint msg, nint wParam, nint lParam);
    [LibraryImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] public static partial bool SetCursorPos(int x, int y);

    // ---- Process memory ----
    public const uint PROCESS_QUERY_INFORMATION = 0x0400, PROCESS_VM_READ = 0x0010;
    public const uint MEM_COMMIT = 0x1000, MEM_PRIVATE = 0x20000, MEM_IMAGE = 0x1000000;
    public const uint PAGE_EXECUTE = 0x10, PAGE_EXECUTE_READ = 0x20, PAGE_EXECUTE_READWRITE = 0x40, PAGE_EXECUTE_WRITECOPY = 0x80, PAGE_GUARD = 0x100, PAGE_NOACCESS = 0x01;

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
        public nint BaseAddress;
        public nint AllocationBase;
        public uint AllocationProtect;
        public ushort PartitionId;
        public nint RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)] public static partial nint OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint pid);
    [LibraryImport("kernel32.dll")] [return: MarshalAs(UnmanagedType.Bool)] public static partial bool CloseHandle(nint handle);
    [LibraryImport("kernel32.dll")] public static partial nint VirtualQueryEx(nint process, nint address, out MEMORY_BASIC_INFORMATION info, nint length);
    [LibraryImport("kernel32.dll")] [return: MarshalAs(UnmanagedType.Bool)]
    public static unsafe partial bool ReadProcessMemory(nint process, nint address, byte* buffer, nint size, out nint read);
    [LibraryImport("psapi.dll", EntryPoint = "GetMappedFileNameW")]
    public static unsafe partial uint GetMappedFileName(nint process, nint address, char* name, uint size);

    // ---- TCP connection owners ----
    public const int AF_INET = 2, TCP_TABLE_OWNER_PID_ALL = 5;

    [LibraryImport("iphlpapi.dll")]
    public static partial uint GetExtendedTcpTable(nint table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool order, int addressFamily, int tableClass, uint reserved);

    // ---- DNS cache ----
    [LibraryImport("dnsapi.dll")] [return: MarshalAs(UnmanagedType.Bool)] public static partial bool DnsFlushResolverCache();
}
