using System.Net;
using ANetworkScanner.Engine.Targets;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using Microsoft.UI.Xaml.Shapes;
using Windows.UI;

namespace ANetworkScanner.App.Controls;

/// <summary>
/// One small square per target address (or per bucket of addresses when there are too many to draw), filling
/// in as the scan progresses: dim while pending, brighter once checked, accent colour and a fade-in when a
/// host answers. Hovering a square reports which address it stands for.
/// </summary>
public sealed partial class SubnetMap : UserControl
{
    private const int MaxCells = 2048;
    private const double CellSize = 11, Gap = 3;

    private TargetSet _targets = TargetSet.Empty;
    private long _bucketSize = 1;
    private Rectangle[] _cells = [];
    private int[] _count = [], _done = [], _alive = [];
    private int _columns = 1;

    public SubnetMap()
    {
        InitializeComponent();
        SizeChanged += (_, _) => Relayout();
        ActualThemeChanged += (_, _) => RecolorAll();
    }

    /// <summary>The text for the address under the pointer; empty when the pointer leaves.</summary>
    public event Action<string>? HoverTextChanged;

    public void Begin(TargetSet targets)
    {
        _targets = targets;
        long total = targets.Count;
        _bucketSize = Math.Max(1, (total + MaxCells - 1) / MaxCells);
        int cellCount = (int)((total + _bucketSize - 1) / _bucketSize);

        Surface.Children.Clear();
        _cells = new Rectangle[cellCount];
        _count = new int[cellCount];
        _done = new int[cellCount];
        _alive = new int[cellCount];

        for (long i = 0; i < total; i++) _count[(int)(i / _bucketSize)]++;

        for (int i = 0; i < cellCount; i++)
        {
            var cell = new Rectangle
            {
                Width = CellSize,
                Height = CellSize,
                RadiusX = 3,
                RadiusY = 3,
                Fill = PendingBrush,
            };
            _cells[i] = cell;
            Surface.Children.Add(cell);
        }
        Relayout();
    }

    public void Mark(uint address, bool alive)
    {
        long index = _targets.IndexOf(address);
        if (index < 0) return;
        int bucket = (int)(index / _bucketSize);

        _done[bucket]++;
        bool firstAlive = false;
        if (alive) firstAlive = ++_alive[bucket] == 1;

        Recolor(bucket);
        if (firstAlive) Pop(_cells[bucket]);
    }

    private void Relayout()
    {
        if (_cells.Length == 0) return;
        double width = Math.Max(ActualWidth, CellSize + Gap);
        _columns = Math.Max(1, (int)((width + Gap) / (CellSize + Gap)));
        int rows = (_cells.Length + _columns - 1) / _columns;

        for (int i = 0; i < _cells.Length; i++)
        {
            Canvas.SetLeft(_cells[i], i % _columns * (CellSize + Gap));
            Canvas.SetTop(_cells[i], i / _columns * (CellSize + Gap));
        }
        Height = rows * (CellSize + Gap) - Gap;
    }

    // ── Colours ──────────────────────────────────────────────────────────────

    private bool IsDark => ActualTheme == ElementTheme.Dark;

    private Brush PendingBrush => new SolidColorBrush(IsDark ? Color.FromArgb(255, 44, 50, 62) : Color.FromArgb(255, 222, 227, 236));
    private Brush CheckedBrush => new SolidColorBrush(IsDark ? Color.FromArgb(255, 78, 88, 106) : Color.FromArgb(255, 188, 197, 212));

    private Brush AliveBrush
    {
        get
        {
            var accent = Application.Current.Resources.TryGetValue("SystemAccentColor", out var c) && c is Color color
                ? color
                : Colors.DodgerBlue;
            return new SolidColorBrush(accent);
        }
    }

    private void Recolor(int bucket)
    {
        var cell = _cells[bucket];
        if (_alive[bucket] > 0)
        {
            cell.Fill = AliveBrush;
            cell.Opacity = _bucketSize == 1 ? 1.0 : 0.45 + 0.55 * _alive[bucket] / _count[bucket];
        }
        else if (_done[bucket] >= _count[bucket])
        {
            cell.Fill = CheckedBrush;
            cell.Opacity = 1;
        }
        else if (_done[bucket] > 0)
        {
            cell.Fill = CheckedBrush;
            cell.Opacity = 0.55;
        }
    }

    private void RecolorAll()
    {
        for (int i = 0; i < _cells.Length; i++)
        {
            _cells[i].Fill = PendingBrush;
            _cells[i].Opacity = 1;
            Recolor(i);
        }
    }

    /// <summary>A host answering: the square flashes bigger and settles, so new finds catch the eye.</summary>
    private static void Pop(Rectangle cell)
    {
        cell.RenderTransformOrigin = new Windows.Foundation.Point(0.5, 0.5);
        var scale = new ScaleTransform { ScaleX = 0.2, ScaleY = 0.2 };
        cell.RenderTransform = scale;

        var storyboard = new Storyboard();
        foreach (var property in new[] { "ScaleX", "ScaleY" })
        {
            var animation = new DoubleAnimation
            {
                From = 1.9,
                To = 1.0,
                Duration = TimeSpan.FromMilliseconds(420),
                EasingFunction = new BackEase { Amplitude = 0.6, EasingMode = EasingMode.EaseOut },
            };
            Storyboard.SetTarget(animation, scale);
            Storyboard.SetTargetProperty(animation, property);
            storyboard.Children.Add(animation);
        }
        storyboard.Begin();
    }

    // ── Hover ────────────────────────────────────────────────────────────────

    private void Surface_PointerMoved(object sender, PointerRoutedEventArgs e)
    {
        if (_cells.Length == 0) return;
        var point = e.GetCurrentPoint(Surface).Position;
        int column = (int)(point.X / (CellSize + Gap));
        int row = (int)(point.Y / (CellSize + Gap));
        int bucket = row * _columns + column;
        if (column >= _columns || bucket < 0 || bucket >= _cells.Length) { HoverTextChanged?.Invoke(""); return; }

        long first = bucket * _bucketSize;
        long last = Math.Min(_targets.Count - 1, first + _bucketSize - 1);
        string name = _bucketSize == 1
            ? $"{ToText(first)}"
            : $"{ToText(first)} – {ToText(last)}";
        string state = _alive[bucket] > 0
            ? (_bucketSize == 1 ? "alive" : $"{_alive[bucket]} alive")
            : _done[bucket] >= _count[bucket] ? "no answer" : "pending";
        HoverTextChanged?.Invoke($"{name}  ·  {state}");
    }

    private string ToText(long index) => new IPAddress(
        [(byte)(_targets.ValueAt(index) >> 24), (byte)(_targets.ValueAt(index) >> 16),
         (byte)(_targets.ValueAt(index) >> 8), (byte)_targets.ValueAt(index)]).ToString();

    private void Surface_PointerExited(object sender, PointerRoutedEventArgs e) => HoverTextChanged?.Invoke("");
}
