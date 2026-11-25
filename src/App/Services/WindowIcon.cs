using System.Runtime.InteropServices;
using Microsoft.UI.Xaml;
using WinRT.Interop;

namespace ANetworkScanner.App.Services;

/// <summary>
/// Gives a <see cref="Window"/> the app icon (title bar, taskbar button, Alt+Tab). The exe's own
/// icon (<c>ApplicationIcon</c> in App.csproj) only covers Explorer and shortcuts; a running WinUI 3
/// window keeps the generic default until the window icon is set. Call this from the constructor of
/// every window the app opens.
/// </summary>
public static class WindowIcon
{
    private const string IconRelativePath = @"Assets\AppIcon.ico";
    private const uint WM_SETICON = 0x0080;

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern uint ExtractIconEx(string file, int index, IntPtr[]? large, IntPtr[]? small, uint count);

    [DllImport("user32.dll")]
    private static extern IntPtr SendMessage(IntPtr hwnd, uint message, IntPtr wParam, IntPtr lParam);

    public static void Apply(Window window)
    {
        var path = Path.Combine(AppContext.BaseDirectory, IconRelativePath);
        if (File.Exists(path))
        {
            window.AppWindow.SetIcon(path);
            return;
        }

        // The Assets folder did not come along (exe copied on its own): use the icon built into the exe.
        var exe = Environment.ProcessPath;
        if (exe is null) return;

        var large = new IntPtr[1];
        var small = new IntPtr[1];
        if (ExtractIconEx(exe, 0, large, small, 1) == 0) return;

        var hwnd = WindowNative.GetWindowHandle(window);
        SendMessage(hwnd, WM_SETICON, (IntPtr)1, large[0]); // ICON_BIG: taskbar and Alt+Tab
        SendMessage(hwnd, WM_SETICON, (IntPtr)0, small[0]); // ICON_SMALL: title bar
    }
}
