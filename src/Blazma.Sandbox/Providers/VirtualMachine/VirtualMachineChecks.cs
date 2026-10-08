using Blazma.Contracts;
using Blazma.Core.Abstractions;
using Blazma.Core.Analysis;
using Blazma.Core.Text;

namespace Blazma.Sandbox.Providers.VirtualMachine;

/// <summary>Availability checks and texts shared by the VM providers.</summary>
internal static class VirtualMachineChecks
{
    public static ProviderCheck Check(string id, LocalizedText label, bool passed, LocalizedText detail) => new(id, label, passed, detail);

    public static readonly LocalizedText VmLabel = new("Virtual machine", "الجهاز الافتراضي");
    public static readonly LocalizedText NetworkLabel = new("Network adapters disconnected", "فصل محوّلات الشبكة");
    public static readonly LocalizedText InstanceLabel = new("Virtual machine not running", "الجهاز الافتراضي ليس قيد التشغيل");
    public static readonly LocalizedText Found = new("Found.", "موجود.");
    public static readonly LocalizedText NotChecked = new("Cannot be checked until the checks above pass.", "يتعذّر التحقق من ذلك قبل اجتياز الفحوص السابقة.");
    public static readonly LocalizedText VmNotSet = new("Choose the analysis virtual machine in Settings.", "اختر الجهاز الافتراضي المخصّص للتحليل من الإعدادات.");
    public static readonly LocalizedText VmMissing = new("No virtual machine with this name was found.", "لم يُعثر على جهاز افتراضي بهذا الاسم.");
    public static readonly LocalizedText VmAmbiguous = new("Several virtual machines have this name. Rename one of them.", "يحمل أكثر من جهاز افتراضي هذا الاسم. غيّر اسم أحدها.");
    public static readonly LocalizedText Running = new(
        "The virtual machine is running. Close it first; Blazma restores the snapshot and starts it itself.",
        "الجهاز الافتراضي قيد التشغيل. أغلقه أولًا، فـBlazma يستعيد اللقطة ويشغّله بنفسه.");
    public static readonly LocalizedText Ready = new("Ready.", "جاهز.");

    public static ProviderCheck Credentials(VirtualMachineOptions options, ISecretProtector secrets)
    {
        var ok = !string.IsNullOrWhiteSpace(options.GuestUser) && HasPassword(options, secrets);
        return Check("credentials", new("Guest administrator account", "حساب المسؤول داخل الجهاز الافتراضي"), ok,
            ok ? new("Set.", "تم الإعداد.")
               : new("Enter the user name and password of an administrator account inside the virtual machine (not on this computer).",
                     "أدخل اسم المستخدم وكلمة المرور لحساب مسؤول داخل الجهاز الافتراضي (وليس على هذا الحاسوب)."));
    }

    public static ProviderCheck GuestFolder(VirtualMachineOptions options)
    {
        var ok = GuestPaths.IsValidWorkFolder(options.GuestWorkFolder);
        return Check("guest-folder", new("Working folder inside the VM", "مجلد العمل داخل الجهاز الافتراضي"), ok,
            ok ? new("Valid.", "صالح.")
               : new("Use a simple folder such as C:\\Blazma: a drive letter followed by letters, digits, spaces and _ - . ( ) only.",
                     "استخدم مجلدًا بسيطًا مثل C:\\Blazma: حرف محرّك أقراص يليه حروف وأرقام ومسافات والرموز _ - . ( ) فقط."));
    }

    public static ProviderCheck Agent(VirtualMachineOptions options)
    {
        var ok = File.Exists(Path.Combine(options.AgentFolder, Protocol.AgentExecutable));
        return Check("agent", new("Monitoring agent", "وكيل المراقبة"), ok,
            ok ? new("Present.", "موجود.")
               : new("Blazma.Agent.exe was not found next to Blazma. Reinstall or build the agent (see README).", "لم يُعثر على Blazma.Agent.exe بجانب Blazma. أعد التثبيت أو ابنِ الوكيل (راجع README)."));
    }

    /// <summary>The adapter rule: disconnected, unless the settings allow it or this analysis enables the network.</summary>
    public static ProviderCheck Network(VirtualMachineOptions options, NetworkPolicy network, IReadOnlyList<string>? connected, LocalizedText howToDisconnect)
    {
        if (connected is null) return Check("network", NetworkLabel, false, NotChecked);
        if (connected.Count == 0) return Check("network", NetworkLabel, true, new("No adapter is connected.", "لا يوجد أي محوّل متصل."));
        var list = string.Join(", ", connected);
        if (!options.RequireDisconnectedNetwork)
            return Check("network", NetworkLabel, true, new($"Connected ({list}); allowed by your settings.", $"متصل ({list})، وهذا مسموح وفق إعداداتك."));
        if (network == NetworkPolicy.Enabled)
            return Check("network", NetworkLabel, true, new($"Connected ({list}); allowed because this analysis enables network access.", $"متصل ({list})، وهذا مسموح لأن هذا التحليل يتيح الوصول إلى الشبكة."));
        return Check("network", NetworkLabel, false, new($"Connected: {list}. {howToDisconnect.En}", $"متصل: {list}. {howToDisconnect.Ar}"));
    }

    public static ProviderReadiness Readiness(IReadOnlyList<ProviderCheck> checks, bool supported, bool running) =>
        !supported ? ProviderReadiness.NotSupported
        : checks.All(c => c.Passed) ? ProviderReadiness.Ready
        : running ? ProviderReadiness.Unavailable
        : ProviderReadiness.NeedsSetup;

    public static bool HasPassword(VirtualMachineOptions options, ISecretProtector secrets) => !string.IsNullOrEmpty(UnprotectPassword(options, secrets));

    public static string? UnprotectPassword(VirtualMachineOptions options, ISecretProtector secrets)
    {
        if (string.IsNullOrEmpty(options.ProtectedGuestPassword)) return null;
        try { return secrets.Unprotect(options.ProtectedGuestPassword); }
        catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or FormatException or InvalidOperationException) { return null; }
    }

    public static string RequirePassword(VirtualMachineOptions options, ISecretProtector secrets) =>
        UnprotectPassword(options, secrets) is { Length: > 0 } password ? password
        : throw new InvalidOperationException("The guest account password is not set or cannot be read. Enter it again in Settings.");
}
