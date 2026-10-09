using System.Text;
using Blazma.Core.Analysis;

namespace Blazma.Reporting.Tests;

public class PdfReportExporterTests
{
    private static byte[] Pdf(AnalysisResult result, string language, bool redact = false)
    {
        using var stream = new MemoryStream();
        new PdfReportExporter().ExportAsync(result, stream, TestData.Options(redact, language), CancellationToken.None).GetAwaiter().GetResult();
        return stream.ToArray();
    }

    [Theory]
    [InlineData("en")]
    [InlineData("ar")]
    public void Produces_a_pdf_in_both_languages(string language)
    {
        var bytes = Pdf(TestData.Demo(), language);
        Assert.True(bytes.Length > 10_000);
        Assert.Equal("%PDF-", Encoding.ASCII.GetString(bytes, 0, 5));
        Assert.Contains("%%EOF", Encoding.ASCII.GetString(bytes, bytes.Length - 64, 64));
    }

    [Fact]
    public void Embeds_the_blazma_fonts()
    {
        var text = Encoding.Latin1.GetString(Pdf(TestData.Demo(), "ar"));
        Assert.Contains("IBMPlexSansArabic", text.Replace(" ", "", StringComparison.Ordinal));
    }

    [Fact]
    public void Hostile_strings_do_not_break_the_document()
    {
        var result = TestData.Demo();
        var nasty = string.Concat(Enumerable.Repeat("‮\u0000￿\uD800x<script>%PDF ", 5000));
        result = new AnalysisResult
        {
            AnalysisId = result.AnalysisId,
            Sample = result.Sample with { FileName = nasty },
            Static = result.Static,
            Options = result.Options,
            ProviderId = nasty,
            IsDemo = true,
            StartedAt = result.StartedAt,
            CompletedAt = result.CompletedAt,
            Findings = result.Findings,
            Risk = result.Risk,
            Indicators = result.Indicators,
            Events = result.Events,
        };
        var bytes = Pdf(result, "en");
        Assert.Equal("%PDF-", Encoding.ASCII.GetString(bytes, 0, 5));
    }

    [Fact]
    public void Exporter_describes_itself() =>
        Assert.Equal((".pdf", "PDF"), (new PdfReportExporter().FileExtension, new PdfReportExporter().Format));
}
