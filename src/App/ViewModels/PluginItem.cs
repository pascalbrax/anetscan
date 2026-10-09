using ANetworkScanner.Engine.Probes;
using CommunityToolkit.Mvvm.ComponentModel;

namespace ANetworkScanner.App.ViewModels;

/// <summary>One probe in the management list.</summary>
public sealed partial class PluginItem : ObservableObject
{
    private readonly Action<PluginItem> _enabledChanged;
    private readonly bool _loading;

    public PluginItem(ProbeDefinition definition, bool enabled, Action<PluginItem> enabledChanged)
    {
        Definition = definition;
        _enabledChanged = enabledChanged;
        _loading = true;
        IsEnabled = enabled;
        _loading = false;
    }

    public ProbeDefinition Definition { get; }

    /// <summary>Also the accessible name of the list item.</summary>
    public override string ToString() => $"{Definition.Title}, {OriginText}";

    public string Id => Definition.Id;
    public string Title => Definition.Title;
    public bool IsCustom => Definition.IsUser;
    public string PortsText => ProbeDescriber.PortsSummary(Definition);

    public string OriginText => Definition switch
    {
        { OverridesBuiltIn: true } => "Custom · replaces built-in",
        { IsUser: true } => "Custom",
        _ => "Built-in",
    };

    [ObservableProperty] public partial bool IsEnabled { get; set; }

    partial void OnIsEnabledChanged(bool value)
    {
        if (!_loading) _enabledChanged(this);
    }
}
