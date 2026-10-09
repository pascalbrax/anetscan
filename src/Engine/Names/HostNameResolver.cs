using System.Net;
using System.Text;

namespace ANetworkScanner.Engine.Names;

public interface IHostNameResolver
{
    /// <returns>The best name found, or null when no source knows one.</returns>
    Task<HostName?> ResolveAsync(IPAddress address, CancellationToken cancellationToken);
}

/// <summary>
/// Asks every name source at once and returns the best answer. Sources are listed in order of preference
/// (DNS, then mDNS, then NetBIOS): a name from a more trusted source wins, but we only wait for it when it could
/// still arrive within the timeout, so a host without DNS is not held up longer than the slowest source.
/// </summary>
public sealed class HostNameResolver(IReadOnlyList<INameSource> sources, int timeoutMs) : IHostNameResolver
{
    public static HostNameResolver CreateDefault(int timeoutMs) =>
        new([new DnsPtrSource(), new MdnsSource(), new NetBiosSource()], timeoutMs);

    public async Task<HostName?> ResolveAsync(IPAddress address, CancellationToken cancellationToken)
    {
        if (sources.Count == 0) return null;

        var pending = sources.Select((source, index) => (Index: index, Task: Ask(source, address, cancellationToken))).ToList();
        var answers = new HostName?[sources.Count];
        var finished = new bool[sources.Count];

        while (pending.Count > 0)
        {
            var done = await Task.WhenAny(pending.Select(p => p.Task)).ConfigureAwait(false);
            var entry = pending.First(p => p.Task == done);
            pending.Remove(entry);

            answers[entry.Index] = await done.ConfigureAwait(false);
            finished[entry.Index] = true;

            // The best answer so far wins as soon as no more-preferred source is still outstanding.
            for (int i = 0; i < sources.Count; i++)
            {
                if (answers[i] is { } found) return found;
                if (!finished[i]) break;
            }
        }
        return null;
    }

    private async Task<HostName?> Ask(INameSource source, IPAddress address, CancellationToken ct)
    {
        try
        {
            var raw = await source.QueryAsync(address, timeoutMs, ct).ConfigureAwait(false);
            var name = Clean(raw, address);
            return name is null ? null : new HostName(name, source.Kind);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return null;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return null; // one failing source must never hide the answers of the others
        }
    }

    /// <summary>Makes a received name safe to show: no trailing dot or control characters, never just the address.</summary>
    public static string? Clean(string? raw, IPAddress address)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;

        var sb = new StringBuilder(raw.Length);
        foreach (var c in raw.Trim().TrimEnd('.'))
            if (c >= ' ' && c != '\u007F') sb.Append(c);
        var name = sb.Length > 100 ? sb.ToString(0, 100) : sb.ToString();

        if (name.Length == 0 || name.Equals("localhost", StringComparison.OrdinalIgnoreCase)) return null;
        if (name == address.ToString() || name.EndsWith(".in-addr.arpa", StringComparison.OrdinalIgnoreCase)) return null;
        return name;
    }
}
