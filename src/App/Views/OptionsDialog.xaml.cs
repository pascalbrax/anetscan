using ANetworkScanner.App.ViewModels;
using ANetworkScanner.Engine.Settings;
using ANetworkScanner.Engine.Vendors;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace ANetworkScanner.App.Views;

public sealed partial class OptionsDialog : ContentDialog
{
    private readonly AppSettings _settings;
    private readonly MainViewModel _main;
    private bool _loading;

    public OptionsDialog(AppSettings settings, MainViewModel main)
    {
        _settings = settings;
        _main = main;
        InitializeComponent();

        _loading = true;
        var d = settings.Discovery;
        RateBox.Value = d.ProbesPerSecond;
        InFlightBox.Value = d.MaxInFlight;
        ProbesBox.Value = d.MaxConcurrentProbes;
        TimeoutBox.Value = d.TimeoutMs;
        RetriesBox.Value = d.Retries;
        ArpBox.Value = d.ArpTimeoutMs;
        ConnectRetriesBox.Value = d.ConnectRetries;
        PreciseBox.Value = d.PreciseRttMaxTargets;
        CompactBox.IsOn = settings.CompactRows;
        HideFilteredBox.IsOn = settings.HideFilteredRows;
        ThemeBox.SelectedIndex = (int)settings.Theme;
        ResolveBox.IsOn = d.ResolveNames;
        ForceBox.IsOn = d.ForceScan;
        ShowName.IsEnabled = d.ResolveNames;
        ShowName.IsChecked = !IsHidden("name");
        ShowRtt.IsChecked = !IsHidden("rtt");
        ShowMac.IsChecked = !IsHidden("mac");
        ShowVendor.IsChecked = !IsHidden("vendor");
        ShowMethod.IsChecked = !IsHidden("method");
        RemindBox.IsOn = settings.RemindAboutVendorUpdates;
        VendorStatus.Text = main.VendorStatusText;
        PresetBox.SelectedIndex = d.ProbesPerSecond switch
        {
            DiscoverySettings.GentleRate => 0,
            DiscoverySettings.NormalRate => 1,
            DiscoverySettings.AggressiveRate => 2,
            _ => 3,
        };

        _loading = false;

        PrimaryButtonClick += (_, _) => Apply();
    }

    private void PresetBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_loading) return;
        var preset = PresetBox.SelectedIndex switch
        {
            0 => RatePreset.Gentle,
            1 => RatePreset.Normal,
            2 => RatePreset.Aggressive,
            _ => RatePreset.Custom,
        };
        if (preset == RatePreset.Custom) return;

        var p = DiscoverySettings.FromPreset(preset);
        _loading = true;
        RateBox.Value = p.ProbesPerSecond;
        InFlightBox.Value = p.MaxInFlight;
        _loading = false;
    }

    private void Rate_ValueChanged(NumberBox sender, NumberBoxValueChangedEventArgs args)
    {
        if (_loading) return;
        _loading = true;
        PresetBox.SelectedIndex = sender.Value switch
        {
            DiscoverySettings.GentleRate => 0,
            DiscoverySettings.NormalRate => 1,
            DiscoverySettings.AggressiveRate => 2,
            _ => 3,
        };
        _loading = false;
    }

    private void Apply()
    {
        // NumberBox yields NaN when the field was cleared: keep the previous value then.
        static int Whole(NumberBox box, int fallback) => double.IsNaN(box.Value) ? fallback : (int)box.Value;

        var old = _settings.Discovery;
        _settings.Discovery = new DiscoverySettings
        {
            ProbesPerSecond = double.IsNaN(RateBox.Value) ? old.ProbesPerSecond : RateBox.Value,
            MaxInFlight = Whole(InFlightBox, old.MaxInFlight),
            MaxConcurrentProbes = Whole(ProbesBox, old.MaxConcurrentProbes),
            TimeoutMs = Whole(TimeoutBox, old.TimeoutMs),
            Retries = Whole(RetriesBox, old.Retries),
            ArpTimeoutMs = Whole(ArpBox, old.ArpTimeoutMs),
            ConnectRetries = Whole(ConnectRetriesBox, old.ConnectRetries),
            PreciseRttMaxTargets = Whole(PreciseBox, old.PreciseRttMaxTargets),
            ResolveNames = ResolveBox.IsOn,
            ForceScan = ForceBox.IsOn,
            ForceScanPorts = old.ForceScanPorts,
            NameTimeoutMs = old.NameTimeoutMs,
        }.Normalized();
        _settings.CompactRows = CompactBox.IsOn;
        _settings.HideFilteredRows = HideFilteredBox.IsOn;
        _settings.Theme = (AppTheme)Math.Clamp(ThemeBox.SelectedIndex, 0, 2);
        _settings.RemindAboutVendorUpdates = RemindBox.IsOn;
        _settings.HiddenColumns = [.. new[] { ("name", ShowName), ("rtt", ShowRtt), ("mac", ShowMac), ("vendor", ShowVendor), ("method", ShowMethod) }
            .Where(c => c.Item2.IsChecked != true).Select(c => c.Item1)];

    }

    /// <summary>The hostname column only exists while resolution is on, so its checkbox follows the switch.</summary>
    private void ResolveBox_Toggled(object sender, RoutedEventArgs e) => ShowName.IsEnabled = ResolveBox.IsOn;

    private bool IsHidden(string key) => _settings.HiddenColumns.Contains(key, StringComparer.OrdinalIgnoreCase);

    private async void VendorUpdate_Click(object sender, RoutedEventArgs e)
    {
        VendorUpdateButton.IsEnabled = false;
        VendorProgress.IsActive = true;
        VendorResult.Text = "Downloading from ieee.org…";
        try
        {
            var result = await _main.UpdateVendorsAsync();
            VendorResult.Text = result.Message;
            VendorStatus.Text = _main.VendorStatusText;
        }
        finally
        {
            VendorProgress.IsActive = false;
            VendorUpdateButton.IsEnabled = true;
        }
    }
}
