using ANetworkScanner.App.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;

namespace ANetworkScanner.App.ViewModels;

/// <summary>
/// Brushes for things coloured from code (status dots, result pills). They come from the light or dark theme
/// dictionaries according to <see cref="ThemeService.Effective"/>, so they match the window even when the app is
/// forced to a theme that differs from Windows'.
/// </summary>
public static class Palette
{
    private static readonly Dictionary<(ElementTheme Theme, string Key), Brush> Cache = [];

    public static Brush Primary => Get("TextFillColorPrimaryBrush");
    public static Brush Secondary => Get("TextFillColorSecondaryBrush");
    public static Brush Tertiary => Get("TextFillColorTertiaryBrush");

    public static Brush Success => Get("SystemFillColorSuccessBrush");
    public static Brush Caution => Get("SystemFillColorCautionBrush");
    public static Brush Critical => Get("SystemFillColorCriticalBrush");
    public static Brush Accent => Get("AccentFillColorDefaultBrush");
    public static Brush Divider => Get("DividerStrokeColorDefaultBrush");

    public static Brush NeutralBackground => Get("SystemFillColorNeutralBackgroundBrush");
    public static Brush SuccessBackground => Get("SystemFillColorSuccessBackgroundBrush");
    public static Brush CautionBackground => Get("SystemFillColorCautionBackgroundBrush");
    public static Brush CriticalBackground => Get("SystemFillColorCriticalBackgroundBrush");

    private static Brush Get(string key)
    {
        var theme = ThemeService.Effective;
        if (Cache.TryGetValue((theme, key), out var cached)) return cached;

        var brush = Find(Application.Current.Resources, theme == ElementTheme.Dark ? "Dark" : "Light", key)
                    ?? (Application.Current.Resources.TryGetValue(key, out var value) ? value as Brush : null)
                    ?? new SolidColorBrush(Microsoft.UI.Colors.Gray);
        Cache[(theme, key)] = brush;
        return brush;
    }

    /// <summary>Searches a dictionary and everything merged into it for <paramref name="key"/> in the given theme.</summary>
    private static Brush? Find(ResourceDictionary dictionary, string themeKey, string key, int depth = 0)
    {
        if (depth > 12) return null;

        foreach (var name in new[] { themeKey, "Default" })
        {
            if (dictionary.ThemeDictionaries.TryGetValue(name, out var themed) &&
                themed is ResourceDictionary themeDictionary &&
                themeDictionary.TryGetValue(key, out var value) && value is Brush brush)
                return brush;
        }

        foreach (var merged in dictionary.MergedDictionaries)
            if (Find(merged, themeKey, key, depth + 1) is { } found)
                return found;
        return null;
    }
}
