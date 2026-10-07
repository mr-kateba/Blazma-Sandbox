using System.Xml.Linq;
using Blazma.Core.Analysis;
using Blazma.Sandbox.Isolation;
using Blazma.Sandbox.Providers.WindowsSandbox;

namespace Blazma.Sandbox.Tests;

public class IsolationTests
{
    private static XElement Config(NetworkPolicy network = NetworkPolicy.Disabled) =>
        XElement.Parse(new IsolationPolicy { HostInFolder = @"D:\w\in", HostOutFolder = @"D:\w\out", Network = network }.ToWsbXml());

    [Fact]
    public void Defaults_close_every_optional_channel()
    {
        var c = Config();
        Assert.Equal("Disable", c.Element("Networking")!.Value);
        Assert.Equal("Disable", c.Element("vGPU")!.Value);
        Assert.Equal("Disable", c.Element("ClipboardRedirection")!.Value);
        Assert.Equal("Disable", c.Element("PrinterRedirection")!.Value);
        Assert.Equal("Disable", c.Element("AudioInput")!.Value);
        Assert.Equal("Disable", c.Element("VideoInput")!.Value);
        Assert.Equal("Enable", c.Element("ProtectedClient")!.Value);
    }

    [Fact]
    public void Only_the_output_folder_is_writable()
    {
        var folders = Config().Element("MappedFolders")!.Elements("MappedFolder").ToList();
        Assert.Equal(2, folders.Count);
        var input = folders.Single(f => f.Element("HostFolder")!.Value.EndsWith("in", StringComparison.Ordinal));
        var output = folders.Single(f => f.Element("HostFolder")!.Value.EndsWith("out", StringComparison.Ordinal));
        Assert.Equal("true", input.Element("ReadOnly")!.Value);
        Assert.Equal("false", output.Element("ReadOnly")!.Value);
    }

    [Fact]
    public void Network_is_only_enabled_when_requested() =>
        Assert.Equal("Default", Config(NetworkPolicy.Enabled).Element("Networking")!.Value);

    [Fact]
    public void Host_paths_are_xml_escaped()
    {
        var xml = new IsolationPolicy { HostInFolder = @"D:\a&b<c>\in", HostOutFolder = @"D:\out" }.ToWsbXml();
        Assert.Equal(@"D:\a&b<c>\in", XElement.Parse(xml).Element("MappedFolders")!.Elements().First().Element("HostFolder")!.Value);
    }

    [Theory]
    [InlineData(@"..\..\evil.exe", "evil.exe")]
    [InlineData("a:b*c?.exe", "a_b_c_.exe")]
    [InlineData("   ", "sample.bin")]
    [InlineData("normal setup.exe", "normal setup.exe")]
    public void Sample_names_cannot_escape_the_sample_folder(string input, string expected) =>
        Assert.Equal(expected, WindowsSandboxSession.SafeFileName(input));
}
