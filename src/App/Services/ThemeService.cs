using ANetworkScanner.Engine.Settings;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.UI;

namespace ANetworkScanner.App.Services;

/// <summary>
/// Applies the chosen theme (follow Windows, light, or dark) to every window and dialog, and tells the rest of the app
/// when the effective theme changes, so brushes that are set from code can be refreshed.
/// </summary>
public static class ThemeService
{
    private sealed record Entry(Window Window, FrameworkElement Root);

    private static readonly List<Entry> Windows = [];

    public static AppTheme Choice { get; private set; } = AppTheme.System;

    /// <summary>The theme actually in effect: never "System".</summary>
    public static ElementTheme Effective { get; private set; } = ElementTheme.Light;

    /// <summary>Raised after the effective theme changed (a new choice, or Windows switched while following it).</summary>
    public static event Action? Changed;

    /// <summary>Puts a window under theme control. Call once per window, after its content exists.</summary>
    public static void Register(Window window, FrameworkElement root, AppTheme choice)
    {
        Choice = choice;
        Windows.Add(new Entry(window, root));
        window.Closed += (_, _) => Windows.RemoveAll(e => e.Window == window);
        root.ActualThemeChanged += (_, _) => Refresh();
        Apply(window, root);
        Refresh();
    }

    public static void SetChoice(AppTheme choice)
    {
        Choice = choice;
        foreach (var entry in Windows.ToList()) Apply(entry.Window, entry.Root);
        Refresh();
    }

    /// <summary>A ContentDialog is its own popup and does not inherit the window's theme: give it the window's.</summary>
    public static void Style(ContentDialog dialog, FrameworkElement root) => dialog.RequestedTheme = root.ActualTheme;

    private static void Apply(Window window, FrameworkElement root)
    {
        root.RequestedTheme = Choice switch
        {
            AppTheme.Light => ElementTheme.Light,
            AppTheme.Dark => ElementTheme.Dark,
            _ => ElementTheme.Default,
        };
        UpdateCaptionButtons(window, ResolvedTheme(root));
    }

    private static ElementTheme ResolvedTheme(FrameworkElement root) => Choice switch
    {
        AppTheme.Light => ElementTheme.Light,
        AppTheme.Dark => ElementTheme.Dark,
        _ => root.ActualTheme == ElementTheme.Dark ? ElementTheme.Dark : ElementTheme.Light,
    };

    private static void Refresh()
    {
        if (Windows.Count == 0) return;
        var theme = ResolvedTheme(Windows[0].Root);
        foreach (var entry in Windows) UpdateCaptionButtons(entry.Window, theme);

        if (theme == Effective) return;
        Effective = theme;
        Changed?.Invoke();
    }

    /// <summary>The minimise, maximise and close buttons are drawn by Windows: tell them which colours suit the theme.</summary>
    private static void UpdateCaptionButtons(Window window, ElementTheme theme)
    {
        var bar = window.AppWindow.TitleBar;
        bool dark = theme == ElementTheme.Dark;

        bar.ButtonBackgroundColor = Colors.Transparent;
        bar.ButtonInactiveBackgroundColor = Colors.Transparent;
        bar.ButtonForegroundColor = dark ? Colors.White : Colors.Black;
        bar.ButtonHoverForegroundColor = dark ? Colors.White : Colors.Black;
        bar.ButtonPressedForegroundColor = dark ? Colors.White : Colors.Black;
        bar.ButtonInactiveForegroundColor = dark ? Color.FromArgb(255, 150, 150, 150) : Color.FromArgb(255, 120, 120, 120);
        bar.ButtonHoverBackgroundColor = dark ? Color.FromArgb(40, 255, 255, 255) : Color.FromArgb(25, 0, 0, 0);
        bar.ButtonPressedBackgroundColor = dark ? Color.FromArgb(25, 255, 255, 255) : Color.FromArgb(15, 0, 0, 0);
    }
}
