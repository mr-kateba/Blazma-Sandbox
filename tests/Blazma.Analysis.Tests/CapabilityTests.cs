using System.Text;
using Blazma.Analysis.Static;
using Blazma.Core.Events;
using Blazma.Core.Samples;

namespace Blazma.Analysis.Tests;

public class CapabilityTests
{
    private static IReadOnlyList<Capability> Detect(PeImport[] imports, params string[] strings) => CapabilityDetector.Detect(imports, strings);

    [Fact]
    public void Classic_remote_thread_injection_is_found_from_imports()
    {
        var caps = Detect([new("KERNEL32.dll", ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "CloseHandle"])]);
        var inj = Assert.Single(caps, c => c.Id == "CAP-INJ-001");
        Assert.Equal(Severity.High, inj.Severity);
        Assert.StartsWith("T1055", inj.AttackTechniques[0], StringComparison.Ordinal);
        Assert.Contains(inj.Evidence, e => e == "import: kernel32!WriteProcessMemory");
    }

    [Fact]
    public void Apis_resolved_at_run_time_count_as_string_evidence()
    {
        var caps = Detect([new("KERNEL32.dll", ["GetProcAddress", "LoadLibraryA"])],
            "OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread");
        var inj = Assert.Single(caps, c => c.Id == "CAP-INJ-001");
        Assert.Contains(inj.Evidence, e => e.StartsWith("string: ", StringComparison.Ordinal));
    }

    [Fact]
    public void Half_a_technique_is_not_a_capability()
    {
        var caps = Detect([new("KERNEL32.dll", ["OpenProcess", "VirtualAllocEx"])]);
        Assert.DoesNotContain(caps, c => c.Id == "CAP-INJ-001");
    }

    [Fact]
    public void An_ordinary_program_does_not_light_up()
    {
        var caps = Detect(
        [
            new("KERNEL32.dll", ["CreateFileW", "ReadFile", "WriteFile", "CloseHandle", "GetLastError", "GetModuleHandleW", "GetProcAddress", "LoadLibraryW", "CreateThread", "Sleep", "GetTickCount", "HeapAlloc", "HeapFree", "GetCurrentProcess", "FindFirstFileW", "FindNextFileW"]),
            new("USER32.dll", ["CreateWindowExW", "ShowWindow", "GetMessageW", "DispatchMessageW", "GetForegroundWindow", "MessageBoxW"]),
            new("ADVAPI32.dll", ["RegOpenKeyExW", "RegQueryValueExW", "RegCloseKey"]),
            new("WININET.dll", ["InternetOpenW", "InternetOpenUrlW", "InternetReadFile", "InternetCloseHandle"]),
        ], "Copyright (C) Contoso", "https://contoso.example/update", "Settings saved.");
        Assert.DoesNotContain(caps, c => c.Severity >= Severity.Medium);
    }

    [Fact]
    public void Windows_sandbox_checks_are_recognised()
    {
        var caps = Detect([], @"C:\Users\WDAGUtilityAccount", "SbieDll.dll");
        Assert.Contains(caps, c => c.Id == "CAP-ANA-004");
    }

    [Fact]
    public void Ransomware_needs_encryption_file_walking_and_ransom_wording_together()
    {
        PeImport[] imports = [new("ADVAPI32.dll", ["CryptEncrypt", "CryptImportKey"]), new("KERNEL32.dll", ["FindFirstFileW", "FindNextFileW"])];
        Assert.DoesNotContain(Detect(imports, "Backup complete."), c => c.Id == "CAP-IMP-003");
        var caps = Detect(imports, "All your files have been encrypted!", "Buy bitcoin and send it to receive the decryption key.");
        Assert.Contains(caps, c => c.Id == "CAP-IMP-003");
    }

    [Fact]
    public void Detection_works_on_raw_file_content_too()
    {
        var content = Encoding.ASCII.GetBytes("junk\0\0OpenProcess\0VirtualAllocEx\0WriteProcessMemory\0CreateRemoteThread\0more");
        Assert.Contains(CapabilityDetector.Detect(null, content), c => c.Id == "CAP-INJ-001");
    }

    [Fact]
    public void Catalog_is_complete_and_bilingual()
    {
        var catalog = CapabilityDetector.Catalog;
        Assert.True(catalog.Count >= 45);
        Assert.Equal(catalog.Count, catalog.Select(c => c.Id).Distinct(StringComparer.Ordinal).Count());
        Assert.All(catalog, c =>
        {
            Assert.Matches(@"^CAP-[A-Z]{3}-\d{3}$", c.Id);
            Assert.False(string.IsNullOrWhiteSpace(c.Name.En));
            Assert.Contains(c.Name.Ar, ch => ch is >= '\u0600' and <= '\u06FF');
            Assert.Contains(c.Description.Ar, ch => ch is >= '\u0600' and <= '\u06FF');
            Assert.All(c.AttackTechniques, t => Assert.Matches(@"^T\d{4}(\.\d{3})?$", t));
        });
    }
}
