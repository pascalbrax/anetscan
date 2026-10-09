using Microsoft.UI.Xaml;

namespace ANetworkScanner.App.Services;

/// <summary>
/// Gives a <see cref="Window"/> the app icon (title bar, taskbar button, Alt+Tab). The exe's own
/// icon (<c>ApplicationIcon</c> in App.csproj) only covers Explorer and shortcuts; a running WinUI 3
/// window keeps the generic default until <c>AppWindow.SetIcon</c> is called. Call this from the
/// constructor of every window the app opens.
/// </summary>
public static class WindowIcon
{
    private const string IconRelativePath = @"Assets\AppIcon.ico";

    public static void Apply(Window window)
    {
        var path = Path.Combine(AppContext.BaseDirectory, IconRelativePath);
        if (File.Exists(path))
            window.AppWindow.SetIcon(path);
    }
}
