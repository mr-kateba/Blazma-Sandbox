namespace Blazma.Storage;

/// <summary>
/// Where Blazma keeps its data. Everything stays under one per-user folder; nothing is
/// written next to the executable and nothing is uploaded.
/// </summary>
public sealed class BlazmaPaths
{
    public BlazmaPaths(string? root = null)
    {
        Root = root ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.Create), "Blazma", "Sandbox");
    }

    public string Root { get; }
    public string Database => Path.Combine(Root, "blazma-sandbox.db");
    public string Settings => Path.Combine(Root, "settings.json");
    public string Logs => Path.Combine(Root, "logs");
    public string Rules => Path.Combine(Root, "rules");
    public string Work => Path.Combine(Root, "work");
    public string Exports => Path.Combine(Root, "exports");
    public string Yara => Path.Combine(Root, "yara");

    /// <summary>Per-analysis artifacts (screenshots, dropped files, memory, capture). Deleted with the analysis.</summary>
    public string Artifacts => Path.Combine(Root, "artifacts");

    public string ArtifactsFor(Guid analysisId) => Path.Combine(Artifacts, analysisId.ToString("N"));

    public void EnsureCreated()
    {
        foreach (var dir in new[] { Root, Logs, Rules, Work, Exports, Yara, Artifacts }) Directory.CreateDirectory(dir);
    }
}
