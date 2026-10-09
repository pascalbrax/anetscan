using Microsoft.UI.Xaml;

namespace ANetworkScanner.App;

public partial class App : Application
{
    private Window? _window;

    public App()
    {
        InitializeComponent();
        UnhandledException += OnUnhandledException;
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        // "ANetworkScanner.exe 192.168.1.0/24" starts scanning that target right away.
        var args2 = Environment.GetCommandLineArgs();
        _window = new MainWindow(args2.Length > 1 ? string.Join(' ', args2.Skip(1)) : null);
        _window.Activate();
    }

    private static void OnUnhandledException(object sender, Microsoft.UI.Xaml.UnhandledExceptionEventArgs e)
    {
        try
        {
            var logDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "A Network Scanner", "logs");
            Directory.CreateDirectory(logDir);
            File.AppendAllText(
                Path.Combine(logDir, "crash.log"),
                $"{DateTime.Now:O}{Environment.NewLine}{e.Exception}{Environment.NewLine}{Environment.NewLine}");
        }
        catch
        {
            // Logging must never throw from inside the crash handler.
        }

        e.Handled = true;
    }
}
