using ANetworkScanner.App.ViewModels;
using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;

namespace ANetworkScanner.App.Controls;

/// <summary>
/// The draggable edge of a column header: shows a thin divider, a left-right resize cursor, and reports the
/// drag distance. A double click asks for the column to be fitted to its content.
/// </summary>
public sealed class ResizeGrip : Grid
{
    private readonly Rectangle _line;
    private double _startX;
    private bool _dragging;

    public ResizeGrip()
    {
        Width = 12;
        Background = new SolidColorBrush(Microsoft.UI.Colors.Transparent);
        ProtectedCursor = InputSystemCursor.Create(InputSystemCursorShape.SizeWestEast);

        _line = new Rectangle
        {
            Width = 1,
            Margin = new Thickness(0, 8, 0, 8),
            HorizontalAlignment = HorizontalAlignment.Center,
            Fill = Palette.Divider,
        };
        Children.Add(_line);

        PointerEntered += (_, _) => Highlight(true);
        PointerExited += (_, _) =>
        {
            if (!_dragging) Highlight(false);
        };
        PointerPressed += OnPointerPressed;
        PointerMoved += OnPointerMoved;
        PointerReleased += (_, e) => Finish(e);
        PointerCanceled += (_, e) => Finish(e);
        PointerCaptureLost += (_, e) => Finish(e);

        DoubleTapped += (_, e) =>
        {
            e.Handled = true;
            AutoFitRequested?.Invoke();
        };
    }

    /// <summary>The user grabbed the edge.</summary>
    public event Action? DragStarted;
    /// <summary>The pointer moved: total horizontal distance since the grab, in pixels.</summary>
    public event Action<double>? DragDelta;
    public event Action? DragCompleted;
    public event Action? AutoFitRequested;

    private void OnPointerPressed(object sender, PointerRoutedEventArgs e)
    {
        if (!e.GetCurrentPoint(this).Properties.IsLeftButtonPressed) return;

        _dragging = true;
        _startX = e.GetCurrentPoint(null).Position.X;
        CapturePointer(e.Pointer);
        e.Handled = true;
        DragStarted?.Invoke();
    }

    private void OnPointerMoved(object sender, PointerRoutedEventArgs e)
    {
        if (!_dragging) return;
        DragDelta?.Invoke(e.GetCurrentPoint(null).Position.X - _startX);
        e.Handled = true;
    }

    private void Finish(PointerRoutedEventArgs e)
    {
        if (!_dragging) return;
        _dragging = false;
        ReleasePointerCaptures();
        Highlight(false);
        e.Handled = true;
        DragCompleted?.Invoke();
    }

    private void Highlight(bool on)
    {
        _line.Width = on ? 2 : 1;
        _line.Fill = on ? Palette.Accent : Palette.Divider;
    }
}
