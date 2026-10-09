using Blazma.App.Localization;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Settings;
using Blazma.Reporting;
using Blazma.Storage;
using Microsoft.Extensions.Logging;

namespace Blazma.App.Services;

/// <summary>Exports reports with the user's report and privacy settings, then confirms with a toast.</summary>
public sealed class ExportService(SettingsService settings, FileDialogService files, ToastService toasts, DialogService dialogs, BlazmaPaths paths, ILogger<ExportService> logger)
{
    public async Task ExportAsync(AnalysisResult result, ReportFormat format)
    {
        IReportExporter exporter = format == ReportFormat.Json ? new JsonReportExporter() : new HtmlReportExporter();
        var name = $"{Path.GetFileNameWithoutExtension(result.Sample.FileName)}-blazma-{result.StartedAt:yyyyMMdd-HHmm}{exporter.FileExtension}";
        var path = await files.PickSaveAsync(name, exporter.FileExtension, settings.Current.Reports.DefaultExportFolder ?? paths.Exports);
        if (path is null) return;
        var r = settings.Current.Reports;
        var options = new ExportOptions(Loc.Instance.Code, settings.Current.Privacy.RedactExports, r.IncludeRawEvents, r.IncludeTimeline, r.IncludeStaticDetails, r.IncludeIndicators, r.TimelineSummaryLimit);
        try
        {
            await using (var stream = File.Create(path))
                await exporter.ExportAsync(result, stream, options, CancellationToken.None);
            toasts.Exported(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            logger.LogWarning(ex, "Export failed");
            await dialogs.ErrorAsync(Loc.T("ExportFailed"), ex.Message, null, canRetry: false);
        }
    }

    private ExportOptions Options()
    {
        var r = settings.Current.Reports;
        return new ExportOptions(Loc.Instance.Code, settings.Current.Privacy.RedactExports, r.IncludeRawEvents, r.IncludeTimeline, r.IncludeStaticDetails, r.IncludeIndicators, r.TimelineSummaryLimit);
    }

    /// <summary>Formats for other security tools: STIX 2.1, MISP, draft Sigma and YARA rules, and an encrypted archive of dropped files.</summary>
    public async Task ExportInteropAsync(AnalysisResult result, string kind)
    {
        var stem = Path.GetFileNameWithoutExtension(result.Sample.FileName);
        var (suffix, extension) = kind switch
        {
            "stix" => ("-stix", ".stix.json"),
            "misp" => ("-misp", ".misp.json"),
            "sigma" => ("-sigma", ".yml"),
            "yara" => ("", ".yar"),
            "samples" => ("-dropped-files", ".zip"),
            _ => throw new ArgumentOutOfRangeException(nameof(kind)),
        };
        var options = Options();
        string? text = null;
        IReadOnlyList<Blazma.Reporting.Interop.SampleArchiveItem> archive = [];
        switch (kind)
        {
            case "sigma":
                text = new Blazma.Reporting.Interop.SigmaGenerator().Generate(result, options);
                break;
            case "yara":
                text = new Blazma.Reporting.Interop.YaraRuleGenerator().Generate(result, options);
                break;
            case "samples":
                archive = Blazma.Reporting.Interop.SampleArchiveExporter.DroppedFiles(result, paths.ArtifactsFor(result.AnalysisId));
                break;
        }
        if ((kind is "sigma" or "yara" && string.IsNullOrWhiteSpace(text)) || (kind == "samples" && archive.Count == 0))
        {
            toasts.Info(Loc.T("NothingToExport"));
            return;
        }

        var path = await files.PickSaveAsync(stem + suffix + extension, extension, settings.Current.Reports.DefaultExportFolder ?? paths.Exports);
        if (path is null) return;
        try
        {
            await using var stream = File.Create(path);
            switch (kind)
            {
                case "stix": await new Blazma.Reporting.Interop.StixExporter().ExportAsync(result, stream, options, CancellationToken.None); break;
                case "misp": await new Blazma.Reporting.Interop.MispExporter().ExportAsync(result, stream, options, CancellationToken.None); break;
                case "samples": await new Blazma.Reporting.Interop.SampleArchiveExporter().ExportAsync(archive, stream, cancellationToken: CancellationToken.None); break;
                default: await stream.WriteAsync(System.Text.Encoding.UTF8.GetBytes(text!)); break;
            }
            toasts.Exported(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            logger.LogWarning(ex, "Export failed");
            await dialogs.ErrorAsync(Loc.T("ExportFailed"), ex.Message, null, canRetry: false);
        }
    }

    public async Task ExportIndicatorsAsync(AnalysisResult result)
    {
        var name = $"{Path.GetFileNameWithoutExtension(result.Sample.FileName)}-indicators.csv";
        var path = await files.PickSaveAsync(name, ".csv", settings.Current.Reports.DefaultExportFolder ?? paths.Exports);
        if (path is null) return;
        try
        {
            var redactor = settings.Current.Privacy.RedactExports ? new Redactor() : Redactor.None;
            await File.WriteAllTextAsync(path, IndicatorExporter.ToCsv(result, redactor: redactor));
            toasts.Exported(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            await dialogs.ErrorAsync(Loc.T("ExportFailed"), ex.Message, null, canRetry: false);
        }
    }
}
