using Blazma.Analysis.Static;
using Blazma.Cli;
using Blazma.Storage;

// The same executable doubles as the isolated static-analysis helper.
if (StaticWorker.IsWorkerInvocation(args))
    return await StaticWorker.RunAsync(args, BlazmaJson.Options);

// Arabic output needs UTF-8 on the Windows console.
Console.OutputEncoding = System.Text.Encoding.UTF8;

using var cancel = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cancel.Cancel(); };
return await new CliApp(Console.Out, Console.Error).RunAsync(args, cancel.Token);
