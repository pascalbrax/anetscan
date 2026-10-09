using System.Collections.Concurrent;
using System.Net;
using System.Runtime.InteropServices;

namespace ANetworkScanner.Engine.Discovery;

/// <summary>Resolves an on-link IPv4 address to its MAC address with a real ARP request.</summary>
public interface IArpResolver
{
    /// <returns>The MAC as <c>AA:BB:CC:DD:EE:FF</c>, or null when nobody answered within the timeout.</returns>
    Task<string?> ResolveAsync(IPAddress address, int timeoutMs, CancellationToken cancellationToken);
}

/// <summary>
/// ARP through <c>SendARP</c> (iphlpapi): no admin rights, no driver. Measured behaviour on Windows 11:
/// every call puts a real request on the wire (it does not read the cache), answers arrive in
/// milliseconds, but an address nobody owns blocks the call for 3-4 s. Because the call is
/// synchronous, it runs on dedicated threads (the thread pool would starve) and the caller simply stops
/// waiting after <c>timeoutMs</c>; the thread is reused once the OS call finally returns.
/// </summary>
public sealed class SystemArpResolver : IArpResolver, IDisposable
{
    private sealed class Request(uint destination)
    {
        public uint Destination { get; } = destination;
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<string?> Result { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    private readonly BlockingCollection<Request> _queue = [];
    private readonly int _maxThreads;
    private readonly object _spawnGate = new();
    private int _threadCount;
    private int _idleThreads;

    public SystemArpResolver(int maxConcurrency = 256) => _maxThreads = Math.Clamp(maxConcurrency, 1, 1024);

    public async Task<string?> ResolveAsync(IPAddress address, int timeoutMs, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // SendARP wants the address exactly as laid out in memory (network byte order in a uint).
        var request = new Request(BitConverter.ToUInt32(address.GetAddressBytes(), 0));
        _queue.Add(request, CancellationToken.None);
        EnsureWorker();

        // The timeout only starts once a worker has actually picked the request up.
        await request.Started.Task.WaitAsync(cancellationToken).ConfigureAwait(false);

        var finished = await Task.WhenAny(request.Result.Task, Task.Delay(timeoutMs, cancellationToken)).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        return finished == request.Result.Task ? request.Result.Task.Result : null;
    }

    private void EnsureWorker()
    {
        if (Volatile.Read(ref _idleThreads) > 0) return;
        lock (_spawnGate)
        {
            if (_threadCount >= _maxThreads) return;
            _threadCount++;
            new Thread(Work, maxStackSize: 256 * 1024) { IsBackground = true, Name = "ArpResolver" }.Start();
        }
    }

    private void Work()
    {
        var mac = new byte[8];
        while (true)
        {
            Interlocked.Increment(ref _idleThreads);
            Request request;
            try { request = _queue.Take(); }
            catch (InvalidOperationException) { return; } // collection completed (disposed)
            finally { Interlocked.Decrement(ref _idleThreads); }

            request.Started.TrySetResult();
            string? result = null;
            try
            {
                int length = mac.Length;
                if (NativeMethods.SendARP(request.Destination, 0, mac, ref length) == 0 && length >= 6)
                    result = string.Join(':', mac.Take(6).Select(b => b.ToString("X2")));
            }
            catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
            {
                // Not Windows: ARP is unavailable, ICMP still works.
            }
            request.Result.TrySetResult(result);
        }
    }

    public void Dispose() => _queue.CompleteAdding();

    private static class NativeMethods
    {
        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        internal static extern int SendARP(uint destinationIp, uint sourceIp, byte[] macAddress, ref int physicalAddressLength);
    }
}
