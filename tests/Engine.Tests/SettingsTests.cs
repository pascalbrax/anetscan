using ANetworkScanner.Engine.Settings;
using Xunit;

namespace ANetworkScanner.Engine.Tests;

public class SettingsTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "ans-tests-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true);
    }

    private SettingsStore Store() => new(Path.Combine(_dir, "settings.json"));

    [Fact]
    public void MissingFile_GivesDefaults()
    {
        var s = Store().Load();
        Assert.Empty(s.RecentTargets);
        Assert.Equal(500, s.Discovery.ProbesPerSecond);
        Assert.False(s.Discovery.ResolveNames);
    }

    [Fact]
    public void RoundTrip_KeepsEverything()
    {
        var store = Store();
        var s = new AppSettings { Discovery = new DiscoverySettings { ProbesPerSecond = 123, Retries = 2, ResolveNames = true } };
        s.AddRecentTarget("10.0.0.0/24");
        store.Save(s);

        var loaded = store.Load();
        Assert.Equal(["10.0.0.0/24"], loaded.RecentTargets);
        Assert.Equal(123, loaded.Discovery.ProbesPerSecond);
        Assert.Equal(2, loaded.Discovery.Retries);
        Assert.True(loaded.Discovery.ResolveNames);
        Assert.False(File.Exists(store.Path + ".tmp"));
    }

    [Fact]
    public void CorruptFile_FallsBackToDefaults()
    {
        var store = Store();
        Directory.CreateDirectory(_dir);
        File.WriteAllText(store.Path, "{ this is not json");
        Assert.Empty(store.Load().RecentTargets);
    }

    [Fact]
    public void OutOfRangeValues_AreClampedOnLoad()
    {
        var store = Store();
        Directory.CreateDirectory(_dir);
        File.WriteAllText(store.Path, """{ "discovery": { "maxInFlight": 999999, "timeoutMs": 1, "retries": -4 } }""");
        var d = store.Load().Discovery;
        Assert.Equal(4096, d.MaxInFlight);
        Assert.Equal(100, d.TimeoutMs);
        Assert.Equal(0, d.Retries);
    }

    [Fact]
    public void RecentTargets_AreMostRecentFirst_Unique_AndCapped()
    {
        var s = new AppSettings();
        for (int i = 0; i < 15; i++) s.AddRecentTarget($"10.0.{i}.0/24");
        s.AddRecentTarget("10.0.5.0/24");
        s.AddRecentTarget("  10.0.9.0/24  ");
        s.AddRecentTarget("   ");

        Assert.Equal(AppSettings.MaxRecentTargets, s.RecentTargets.Count);
        Assert.Equal("10.0.9.0/24", s.RecentTargets[0]);
        Assert.Equal("10.0.5.0/24", s.RecentTargets[1]);
        Assert.Equal(s.RecentTargets.Count, s.RecentTargets.Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    [Theory]
    [InlineData(RatePreset.Gentle, 100)]
    [InlineData(RatePreset.Normal, 500)]
    [InlineData(RatePreset.Aggressive, 2000)]
    public void Presets_SetTheRate(RatePreset preset, double rate) =>
        Assert.Equal(rate, DiscoverySettings.FromPreset(preset).ProbesPerSecond);
}
