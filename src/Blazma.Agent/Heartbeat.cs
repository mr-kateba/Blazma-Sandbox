namespace Blazma.Agent;

/// <summary>
/// Calls <c>beat</c> right away and then every interval on a thread of its own, so a busy
/// thread pool or a component that blocks or fails cannot hold heartbeats back. A failed beat
/// is logged and the next one is tried as usual.
/// </summary>
internal sealed class Heartbeat : IDisposable
{
    private readonly ManualResetEventSlim _stop = new();
    private readonly Thread _thread;

    public Heartbeat(Action beat, TimeSpan interval)
    {
        _thread = new Thread(() =>
        {
            do
            {
                try { beat(); }
                catch (Exception ex) { AgentLog.Limited("heartbeat", "Could not write the heartbeat", ex); }
            }
            while (!_stop.Wait(interval));
        })
        { IsBackground = true, Name = "heartbeat" };
        _thread.Start();
    }

    public void Dispose()
    {
        _stop.Set();
        // A beat stuck in a slow write still holds the event; leave it to the finalizer then.
        if (_thread.Join(TimeSpan.FromSeconds(5))) _stop.Dispose();
    }
}
