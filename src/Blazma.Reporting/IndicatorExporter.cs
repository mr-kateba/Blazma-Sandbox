using System.Text;
using Blazma.Core.Analysis;
using Blazma.Core.Indicators;

namespace Blazma.Reporting;

/// <summary>Indicator lists for blocklists and other tools. Informational-only entries are excluded by default.</summary>
public static class IndicatorExporter
{
    public static string ToCsv(AnalysisResult result, bool includeInformational = false, Redactor? redactor = null)
    {
        var r = redactor ?? Redactor.None;
        var sb = new StringBuilder("type,value,status,source\n");
        foreach (var i in Select(result, includeInformational))
            sb.Append($"{i.Type},{Csv(r.Apply(i.Value)!)},{i.Status},{Csv(i.Source)}\n");
        return sb.ToString();
    }

    public static string ToText(AnalysisResult result, IndicatorType type, bool includeInformational = false) =>
        string.Join('\n', Select(result, includeInformational).Where(i => i.Type == type).Select(i => i.Value)) + "\n";

    private static IEnumerable<Indicator> Select(AnalysisResult result, bool includeInformational) =>
        result.Indicators.Where(i => includeInformational || i.Status != IndicatorStatus.Informational || i.Type == IndicatorType.Sha256);

    private static string Csv(string value)
    {
        // Leading =,+,-,@ would be evaluated as formulas by spreadsheet apps.
        if (value.Length > 0 && value[0] is '=' or '+' or '-' or '@') value = "'" + value;
        return value.Contains(',') || value.Contains('"') || value.Contains('\n') ? "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"" : value;
    }
}
