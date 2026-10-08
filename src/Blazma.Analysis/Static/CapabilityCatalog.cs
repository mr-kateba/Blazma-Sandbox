using Blazma.Core.Events;
using Blazma.Core.Samples;
using Blazma.Core.Text;

namespace Blazma.Analysis.Static;

internal sealed record CapabilityRule
{
    public required string Id { get; init; }
    public required string Namespace { get; init; }
    public required Severity Severity { get; init; }
    public required LocalizedText Name { get; init; }
    public required LocalizedText Description { get; init; }
    public string[] Attack { get; init; } = [];
    public string[] Mbc { get; init; } = [];
    public required CapabilityCondition When { get; init; }

    /// <summary>Weaker capabilities hidden when this one matches, so one ability is not reported twice.</summary>
    public string[] Supersedes { get; init; } = [];

    public Capability ToCapability(IReadOnlyList<string> evidence) => new()
    {
        Id = Id,
        Name = Name,
        Description = Description,
        Namespace = Namespace,
        Severity = Severity,
        AttackTechniques = Attack,
        Mbc = Mbc,
        Evidence = evidence,
    };
}

/// <summary>
/// The built-in capability rules. Ids are stable (reports and user settings refer to them).
/// Severity is deliberately conservative: a single common API never matches on its own, and
/// abilities that ordinary software also has (networking, services, process lists) stay
/// Informational or Low. ATT&amp;CK and MBC (github.com/MBCProject/mbc-markdown) ids are given
/// where a behavior maps cleanly; an empty list means no honest match exists.
/// </summary>
internal static class CapabilityCatalog
{
    // Declared before Rules: static members initialise in textual order.
    private static readonly string[] RansomPhrases =
    [
        "your files have been encrypted", "files are encrypted", "files were encrypted", "have been encrypted",
        "decrypt your files", "decryption key", "decryptor", "recover your files", "restore your files",
        "tor browser", "bitcoin", "ransom", "personal id", "do not rename", "don't rename", "do not try to decrypt",
    ];

    public static IReadOnlyList<CapabilityRule> Rules { get; } = Build();

    public static HashSet<string> ApiNames { get; } = Collect(Rules).OfType<ApiCondition>().Select(c => c.Name).ToHashSet(StringComparer.Ordinal);
    public static HashSet<string> TokenNames { get; } = Collect(Rules).OfType<TokenCondition>().Select(c => c.Token).ToHashSet(StringComparer.Ordinal);
    public static string[] TextPatterns { get; } = Collect(Rules).OfType<TextCondition>().Select(c => c.Pattern).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

    /// <summary>
    /// Whether an API name is distinctive enough to count when it appears only as a string. Short
    /// or all-lower-case names ("send", "connect", "socket") are ordinary words in text.
    /// </summary>
    public static bool StringEligible(string api) => api.Length >= 8 && api.Skip(1).Any(char.IsAsciiLetterUpper);

    private static IEnumerable<CapabilityCondition> Collect(IEnumerable<CapabilityRule> rules)
    {
        var stack = new Stack<CapabilityCondition>(rules.Select(r => r.When));
        while (stack.Count > 0)
        {
            var c = stack.Pop();
            yield return c;
            foreach (var child in c.Children) stack.Push(child);
        }
    }

    // ---- Condition helpers -------------------------------------------------------------

    /// <summary>Imported, or present as a string (resolved at run time).</summary>
    private static CapabilityCondition Api(params string[] names) => Any(names.Select(n => (CapabilityCondition)new ApiCondition(n)).ToArray());

    /// <summary>Present as a string but not imported: typical of code that hides what it calls.</summary>
    private static CapabilityCondition Dyn(params string[] names) =>
        Any(names.Select(n => (CapabilityCondition)new ApiCondition(n, allowImport: false, requireNotImported: true)).ToArray());

    private static CapabilityCondition Tok(params string[] tokens) => Any(tokens.Select(t => (CapabilityCondition)new TokenCondition(t)).ToArray());
    private static CapabilityCondition Txt(params string[] patterns) => Any(Each(patterns));
    private static CapabilityCondition[] Each(params string[] patterns) => patterns.Select(p => (CapabilityCondition)new TextCondition(p)).ToArray();
    private static CapabilityCondition All(params CapabilityCondition[] parts) => new AllCondition(parts);
    private static CapabilityCondition Any(params CapabilityCondition[] parts) => parts.Length == 1 ? parts[0] : new CountCondition(1, parts);
    private static CapabilityCondition AtLeast(int min, params CapabilityCondition[] parts) => new CountCondition(min, parts);

    private static CapabilityRule Rule(string id, string ns, Severity severity, LocalizedText name, LocalizedText description,
        string[] attack, string[] mbc, CapabilityCondition when) =>
        new() { Id = id, Namespace = ns, Severity = severity, Name = name, Description = description, Attack = attack, Mbc = mbc, When = when };

    private static List<CapabilityRule> Build() =>
    [
        // ---- Collection ------------------------------------------------------------------
        Rule("CAP-COL-001", "collection/keylogging", Severity.Medium,
            new("Keylogging with a keyboard hook", "تسجيل ضغطات المفاتيح عبر خطّاف لوحة المفاتيح"),
            new("Can watch every key pressed in any program and note which window was active. Used by keyloggers; some hotkey and accessibility tools do it too.",
                "يستطيع مراقبة كل مفتاح يُضغط في أي برنامج ومعرفة النافذة النشطة. تستخدمه برامج التجسس على لوحة المفاتيح، وبعض أدوات الاختصارات وإمكانية الوصول."),
            ["T1056.001"], ["F0002.001"],
            All(Api("SetWindowsHookEx"),
                Api("GetKeyboardState", "ToUnicode", "ToAscii", "ToUnicodeEx", "ToAsciiEx", "MapVirtualKey", "MapVirtualKeyEx", "GetKeyNameText"),
                Api("GetForegroundWindow", "GetWindowText"))),

        Rule("CAP-COL-002", "collection/keylogging", Severity.Medium,
            new("Keylogging by polling the keyboard", "تسجيل ضغطات المفاتيح بالفحص المتكرر"),
            new("Can repeatedly check which keys are down and record them with the title of the active window.",
                "يستطيع فحص المفاتيح المضغوطة بشكل متكرر وتسجيلها مع عنوان النافذة النشطة."),
            ["T1056.001"], ["F0002.002"],
            All(Api("GetAsyncKeyState"), Api("GetForegroundWindow"), Api("GetWindowText"),
                Api("MapVirtualKey", "MapVirtualKeyEx", "GetKeyNameText", "ToUnicode", "ToAscii", "GetKeyboardLayout", "GetKeyboardState"))),

        Rule("CAP-COL-003", "collection/keylogging", Severity.Low,
            new("Keyboard capture through raw input", "التقاط لوحة المفاتيح عبر الإدخال الخام"),
            new("Can receive raw keyboard input in the background and link it to the active window. Games use raw input too.",
                "يستطيع استقبال إدخال لوحة المفاتيح الخام في الخلفية وربطه بالنافذة النشطة. الألعاب تستخدم الإدخال الخام أيضًا."),
            ["T1056.001"], ["F0002"],
            All(Api("RegisterRawInputDevices"), Api("GetRawInputData"), Api("GetForegroundWindow"), Api("GetWindowText"))),

        Rule("CAP-COL-004", "collection/screen-capture", Severity.Low,
            new("Screen capture", "التقاط صورة للشاشة"),
            new("Can take pictures of the screen. Common in screenshot and remote-support tools; spyware uses it to see what you see.",
                "يستطيع التقاط صور للشاشة. شائع في أدوات لقطات الشاشة والدعم عن بُعد، وتستخدمه برامج التجسس لرؤية ما يظهر أمامك."),
            ["T1113"], ["E1113.m01"],
            Any(All(Api("BitBlt"), Api("CreateCompatibleBitmap"), Api("GetDesktopWindow"),
                    Api("GetDIBits", "GdipSaveImageToFile", "GdipSaveImageToStream", "GdipCreateBitmapFromHBITMAP")),
                Tok("CopyFromScreen"))),

        Rule("CAP-COL-005", "collection/clipboard", Severity.Low,
            new("Clipboard monitoring", "مراقبة الحافظة"),
            new("Can be notified every time something is copied and read it. Clipboard managers do this; stealers use it to grab passwords and addresses.",
                "يستطيع أن يُبلَّغ في كل مرة يُنسخ فيها شيء ثم يقرأه. تفعل ذلك برامج إدارة الحافظة، وتستغله برامج السرقة لالتقاط كلمات المرور والعناوين."),
            ["T1115"], [],
            All(Api("AddClipboardFormatListener", "SetClipboardViewer"), Api("OpenClipboard"), Api("GetClipboardData"))),

        Rule("CAP-COL-006", "collection/clipboard-hijacking", Severity.High,
            new("Swaps cryptocurrency addresses in the clipboard", "استبدال عناوين العملات الرقمية في الحافظة"),
            new("Contains patterns that recognise wallet addresses and can replace what you copied, so a payment goes to someone else.",
                "يحتوي على أنماط تتعرّف على عناوين المحافظ ويستطيع استبدال ما نسخته، فتذهب الدفعة إلى شخص آخر."),
            ["T1115", "T1565.002"], ["E1510"],
            All(Any(Api("SetClipboardData"), All(Tok("Clipboard"), Tok("SetText")), Txt("Set-Clipboard")),
                Txt("(bc1|[13])", "[13][a-km-zA-HJ-NP-Z1-9]{25,", "0x[a-fA-F0-9]{40}", "0x[0-9a-fA-F]{40}", "[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}", "T[A-Za-z1-9]{33}"))),

        Rule("CAP-COL-007", "collection/webcam", Severity.Medium,
            new("Webcam capture", "التقاط صور من كاميرا الويب"),
            new("Can open the webcam and take pictures or video. Expected in video-call software, unexpected almost anywhere else.",
                "يستطيع تشغيل كاميرا الويب والتقاط صور أو فيديو. متوقّع في برامج مكالمات الفيديو، وغير متوقّع في معظم البرامج الأخرى."),
            ["T1125"], [],
            Any(Api("capCreateCaptureWindow", "capGetDriverDescription"), Tok("VideoCaptureDevice"), Txt("{860BB310-5D01-11d0-BD3B-00A0C911CE86}"))),

        Rule("CAP-COL-008", "collection/microphone", Severity.Low,
            new("Microphone recording", "تسجيل الصوت من الميكروفون"),
            new("Can record sound from the microphone. Normal for voice and recording apps.",
                "يستطيع تسجيل الصوت من الميكروفون. أمر طبيعي في تطبيقات الصوت والتسجيل."),
            ["T1123"], [],
            Any(All(Api("waveInOpen"), Api("waveInStart"), Api("waveInAddBuffer", "waveInPrepareHeader")),
                All(Api("mciSendString"), Txt("type waveaudio")),
                Tok("WaveInEvent"))),

        Rule("CAP-COL-009", "credential-access/browser-passwords", Severity.High,
            new("Steals passwords saved in web browsers", "سرقة كلمات المرور المحفوظة في المتصفحات"),
            new("Refers to the files where browsers keep saved passwords and to the means of decrypting them.",
                "يشير إلى الملفات التي تحفظ فيها المتصفحات كلمات المرور، وإلى وسائل فك تشفيرها."),
            ["T1555.003"], [],
            All(AtLeast(2, Each("Login Data", "logins.json", "signons.sqlite", "password_value", "encrypted_key", "key4.db", "origin_url")),
                Any(Api("CryptUnprotectData", "BCryptDecrypt", "PK11SDR_Decrypt"), Txt("encrypted_key", "key4.db", "PK11SDR_Decrypt")))),

        Rule("CAP-COL-010", "credential-access/browser-cookies", Severity.High,
            new("Steals browser cookies", "سرقة ملفات تعريف الارتباط من المتصفحات"),
            new("Refers to browser cookie databases. Stolen cookies let an attacker sign in as you without a password.",
                "يشير إلى قواعد بيانات ملفات تعريف الارتباط في المتصفحات. سرقتها تتيح للمهاجم الدخول إلى حساباتك دون كلمة مرور."),
            ["T1539"], [],
            All(AtLeast(2, Each("Network\\Cookies", "cookies.sqlite", "encrypted_value", "host_key", "moz_cookies")),
                Any(Api("CryptUnprotectData", "BCryptDecrypt"), Txt("encrypted_key", "sqlite")))),

        Rule("CAP-COL-011", "collection/cryptocurrency-wallets", Severity.High,
            new("Steals cryptocurrency wallets", "سرقة محافظ العملات الرقمية"),
            new("Refers to the files or browser extensions of several cryptocurrency wallets.",
                "يشير إلى ملفات أو إضافات متصفح تخص عدة محافظ للعملات الرقمية."),
            ["T1005"], ["B0028"],
            AtLeast(2, Each("wallet.dat", "exodus.wallet", "Electrum\\wallets", "Ethereum\\keystore", "atomic\\Local Storage", "Armory\\",
                "Coinomi\\", "Guarda\\", "Jaxx\\", "com.liberty.jaxx", "Zcash\\", "Wasabi\\Client\\Wallets", "Ledger Live", "Bitcoin\\wallets",
                "nkbihfbeogaeaoehlefnkodbefgpgknn", "bfnaelmomeimhlpmgjnjophhpkkoljpa", "fhbohimaelbohpjbbldcngcnapndodjp",
                "ibnejdfjmmkpcnlpebklmnkoeoihofec", "hnfanknocfeofbddgcijnmhnfnkdnaad", "fnjhmkhhmkbjkkabndcnnogagogbneec"))),

        Rule("CAP-COL-012", "credential-access/discord-tokens", Severity.High,
            new("Steals Discord login tokens", "سرقة رموز تسجيل الدخول في Discord"),
            new("Looks inside Discord's local storage for login tokens, which give full access to the account.",
                "يبحث في التخزين المحلي لتطبيق Discord عن رموز تسجيل الدخول، وهي تمنح تحكّمًا كاملًا بالحساب."),
            ["T1528"], [],
            All(Txt("discord"), Txt("leveldb", "Local Storage"),
                Txt("dQw4w9WgXcQ:", "mfa\\.", "[\\w-]{24}", "[a-zA-Z0-9_-]{24}", "token"))),

        Rule("CAP-COL-013", "credential-access/telegram-session", Severity.High,
            new("Steals the Telegram session", "سرقة جلسة Telegram"),
            new("Refers to Telegram Desktop's session folder (tdata). Copying it opens the account on another computer.",
                "يشير إلى مجلد جلسة Telegram Desktop ‏(tdata). نسخه يفتح الحساب على جهاز آخر."),
            ["T1005", "T1528"], [],
            Any(Txt("Telegram Desktop\\tdata"), All(Txt("tdata"), Txt("D877F783D5D3EF8C", "key_datas", "Telegram Desktop")))),

        Rule("CAP-COL-014", "credential-access/application-passwords", Severity.High,
            new("Steals saved logins of other applications", "سرقة بيانات الدخول المحفوظة في تطبيقات أخرى"),
            new("Refers to where several FTP, e-mail, VPN or gaming programs keep their saved accounts.",
                "يشير إلى أماكن حفظ الحسابات في عدة برامج FTP أو بريد إلكتروني أو VPN أو ألعاب."),
            ["T1555", "T1552.001"], [],
            AtLeast(2,
                Txt("recentservers.xml", "sitemanager.xml"),
                Txt("IMAP Password", "POP3 Password", "SMTP Password"),
                Txt(".purple\\accounts.xml"),
                Txt("Martin Prikryl"),
                Txt("Foxmail", "Thunderbird\\Profiles"),
                Txt("loginusers.vdf", "ssfn"),
                Txt("NordVPN", "OpenVPN Connect\\profiles", "ProtonVPN"),
                Txt("wcx_ftp.ini"))),

        Rule("CAP-COL-015", "collection/document-search", Severity.Low,
            new("Searches the disk for documents", "البحث في القرص عن المستندات"),
            new("Walks through folders and refers to many document file types. Backup tools do this; so do stealers and ransomware.",
                "يتنقّل بين المجلدات ويشير إلى أنواع كثيرة من المستندات. تفعل ذلك أدوات النسخ الاحتياطي، وكذلك برامج السرقة وبرامج الفدية."),
            ["T1005", "T1083"], ["E1083"],
            All(Api("FindFirstFile", "FindFirstFileEx"), Api("FindNextFile"),
                AtLeast(5, Each(".docx", ".xlsx", ".pdf", ".pptx", ".kdbx", ".rdp", ".doc", ".xls", ".txt", ".jpg", ".sql", ".mdb")))),

        // ---- Credential access -----------------------------------------------------------
        Rule("CAP-CRD-001", "credential-access/lsass-dump", Severity.High,
            new("Dumps the memory of LSASS", "نسخ ذاكرة عملية LSASS"),
            new("Can save the memory of the Windows process that holds logged-in users' credentials, to extract passwords and hashes.",
                "يستطيع حفظ ذاكرة عملية Windows التي تحتفظ ببيانات اعتماد المستخدمين المسجّلين، لاستخراج كلمات المرور وقيمها المجزّأة."),
            ["T1003.001"], [],
            All(Txt("lsass"), Any(Api("MiniDumpWriteDump"), Txt("comsvcs")), Any(Api("OpenProcess", "NtOpenProcess"), Txt("comsvcs")))),

        Rule("CAP-CRD-002", "credential-access/credential-dumping-tool", Severity.High,
            new("Contains credential-dumping tool commands", "يحتوي على أوامر أداة لاستخراج بيانات الاعتماد"),
            new("Contains commands of well-known password-dumping tools such as Mimikatz.",
                "يحتوي على أوامر أدوات معروفة لاستخراج كلمات المرور مثل Mimikatz."),
            ["T1003"], [],
            Txt("sekurlsa::", "lsadump::", "privilege::debug", "kerberos::golden", "gentilkiwi")),

        Rule("CAP-CRD-003", "credential-access/registry-hives", Severity.High,
            new("Copies the SAM or SECURITY registry hive", "نسخ خلية السجل SAM أو SECURITY"),
            new("Can save the registry parts that store local account password hashes.",
                "يستطيع حفظ أجزاء السجل التي تخزّن القيم المجزّأة لكلمات مرور الحسابات المحلية."),
            ["T1003.002"], [],
            Any(All(Txt("hklm\\sam", "hklm\\security", "HKEY_LOCAL_MACHINE\\SAM"), Any(Txt("save"), Api("RegSaveKey", "RegSaveKeyEx"))),
                Txt("System32\\config\\SAM"))),

        Rule("CAP-CRD-004", "credential-access/credential-manager", Severity.Medium,
            new("Reads the Windows Credential Manager", "قراءة مدير بيانات الاعتماد في Windows"),
            new("Can list passwords stored in Windows Credential Manager or the Windows Vault. Some sync tools do this legitimately.",
                "يستطيع سرد كلمات المرور المحفوظة في مدير بيانات الاعتماد أو خزنة Windows. بعض أدوات المزامنة تفعل ذلك لأسباب مشروعة."),
            ["T1555.004"], [],
            Api("CredEnumerate", "VaultEnumerateItems", "VaultGetItem")),

        Rule("CAP-CRD-005", "credential-access/wifi-passwords", Severity.Medium,
            new("Reads saved Wi-Fi passwords", "قراءة كلمات مرور Wi-Fi المحفوظة"),
            new("Can display the passwords of saved wireless networks in clear text.",
                "يستطيع عرض كلمات مرور الشبكات اللاسلكية المحفوظة كنص واضح."),
            ["T1555"], [],
            Any(All(Txt("wlan"), Txt("key=clear")), All(Api("WlanGetProfile"), Txt("keyMaterial")))),

        // ---- Privilege ---------------------------------------------------------------------
        Rule("CAP-PRV-001", "privilege-escalation/debug-privilege", Severity.Medium,
            new("Enables the debug privilege", "تفعيل امتياز التصحيح"),
            new("Can turn on SeDebugPrivilege, which allows opening and changing almost any process. Debuggers and system tools need it too.",
                "يستطيع تفعيل الامتياز SeDebugPrivilege الذي يسمح بفتح أي عملية تقريبًا وتعديلها. تحتاجه أيضًا أدوات التصحيح وأدوات النظام."),
            ["T1134"], [],
            Any(All(Txt("SeDebugPrivilege"), Api("AdjustTokenPrivileges"), Api("LookupPrivilegeValue", "OpenProcessToken")), Dyn("RtlAdjustPrivilege"))),

        Rule("CAP-PRV-002", "privilege-escalation/token-manipulation", Severity.Medium,
            new("Impersonates other users' access tokens", "انتحال رموز الوصول لمستخدمين آخرين"),
            new("Can copy another process's security token and act or start programs as that user.",
                "يستطيع نسخ رمز الأمان من عملية أخرى والتصرف أو تشغيل البرامج باسم ذلك المستخدم."),
            ["T1134.001", "T1134.002"], [],
            All(Api("DuplicateTokenEx", "DuplicateToken"), Api("ImpersonateLoggedOnUser", "SetThreadToken", "CreateProcessWithToken", "CreateProcessAsUser"),
                Api("OpenProcessToken", "NtOpenProcessToken"))),

        Rule("CAP-PRV-003", "privilege-escalation/load-driver", Severity.Medium,
            new("Loads a kernel driver", "تحميل برنامج تشغيل في النواة"),
            new("Can load a driver that runs with the highest privileges in Windows. Hardware and security tools do this; rootkits too.",
                "يستطيع تحميل برنامج تشغيل يعمل بأعلى الصلاحيات في Windows. تفعل ذلك أدوات العتاد والحماية، وكذلك برامج الإخفاء الخبيثة (Rootkits)."),
            ["T1543.003", "T1014"], ["C0023"],
            Any(Api("NtLoadDriver", "ZwLoadDriver"), All(Txt("sc create", "sc.exe create"), Txt("type= kernel", "type=kernel")))),

        Rule("CAP-PRV-004", "defense-evasion/parent-spoofing", Severity.Low,
            new("Starts programs under a different parent process", "تشغيل برامج تحت عملية أصل مختلفة"),
            new("Can start a program so that it appears to have been launched by another process. Browsers use the same API for sandboxing.",
                "يستطيع تشغيل برنامج بحيث يبدو أن عملية أخرى هي التي شغّلته. تستخدم المتصفحات الواجهة نفسها لأغراض العزل."),
            ["T1134.004"], [],
            All(Api("InitializeProcThreadAttributeList"), Api("UpdateProcThreadAttribute"), Api("OpenProcess"), Api("CreateProcess"))),

        // ---- Anti-analysis -------------------------------------------------------------------
        Rule("CAP-ANA-001", "defense-evasion/anti-debugging", Severity.Low,
            new("Detects debuggers", "اكتشاف أدوات التصحيح"),
            new("Uses several tricks to notice when it is being examined in a debugger, often to behave differently. Copy-protection does this too.",
                "يستخدم عدة حيل ليعرف إن كان يُفحص بأداة تصحيح، غالبًا ليتصرّف بشكل مختلف. أنظمة الحماية من النسخ تفعل ذلك أيضًا."),
            ["T1622"], ["B0001"],
            AtLeast(2, Api("CheckRemoteDebuggerPresent"), Api("NtSetInformationThread", "ZwSetInformationThread"),
                Dyn("NtQueryInformationProcess", "ZwQueryInformationProcess"), Dyn("DbgUiRemoteBreakin", "DbgBreakPoint"),
                Api("WudfIsAnyDebuggerPresent"), Txt("DebugObject"), Txt("OLLYDBG", "WinDbgFrameClass", "Zeta Debugger", "Rock Debugger", "ObsidianGUI"))),

        Rule("CAP-ANA-002", "defense-evasion/analysis-tool-detection", Severity.Medium,
            new("Looks for analysis tools", "البحث عن أدوات التحليل"),
            new("Contains the names of several tools that researchers use to watch programs, so it may hide when they run.",
                "يحتوي على أسماء عدة أدوات يستخدمها الباحثون لمراقبة البرامج، فقد يخفي سلوكه عند تشغيلها."),
            ["T1057", "T1622"], ["B0013"],
            AtLeast(3, Each("ollydbg", "x64dbg", "x32dbg", "windbg", "ida64", "idaq", "immunitydebugger", "procmon", "procexp", "wireshark",
                "fiddler", "processhacker", "tcpview", "autoruns", "pestudio", "dnspy", "httpdebugger", "regmon", "filemon", "dumpcap", "ghidra"))),

        Rule("CAP-ANA-003", "defense-evasion/vm-detection", Severity.Medium,
            new("Detects virtual machines", "اكتشاف الأجهزة الافتراضية"),
            new("Looks for traces of VirtualBox, VMware, QEMU, Parallels or Hyper-V, often to stay quiet inside an analysis machine.",
                "يبحث عن آثار VirtualBox أو VMware أو QEMU أو Parallels أو Hyper-V، غالبًا ليبقى هادئًا داخل أجهزة التحليل."),
            ["T1497.001"], ["B0009"],
            AtLeast(2, Each("VBoxService", "VBoxTray", "VBoxGuest", "VBoxMouse", "VBoxSF", "VBOX__", "VirtualBox Guest Additions", "vmtoolsd",
                "vmwaretray", "vmwareuser", "VMware Tools", "vmhgfs", "vmmouse", "vm3dmp", "qemu-ga", "QEMU HARDDISK", "prl_tools", "prl_cc",
                "vmicheartbeat", "vmicvss", "xenservice", "HARDWARE\\ACPI\\DSDT\\VBOX"))),

        Rule("CAP-ANA-004", "defense-evasion/sandbox-detection", Severity.Medium,
            new("Detects analysis sandboxes", "اكتشاف بيئات التحليل المعزولة"),
            new("Checks for signs of Windows Sandbox (its WDAGUtilityAccount user), Sandboxie or automated analysis systems, to behave differently there.",
                "يتحقق من علامات Windows Sandbox (المستخدم WDAGUtilityAccount) أو Sandboxie أو أنظمة التحليل الآلي، ليتصرّف فيها بشكل مختلف."),
            ["T1497.001"], ["B0007"],
            Txt("WDAGUtilityAccount", "SbieDll", "cuckoomon", "\\\\.\\pipe\\cuckoo", "api_log.dll", "dir_watch.dll", "snxhk.dll", "cmdvrt32.dll",
                "joeboxcontrol", "joeboxserver")),

        // ---- Defense evasion -----------------------------------------------------------------
        Rule("CAP-EVA-001", "defense-evasion/disable-defender", Severity.High,
            new("Turns off or weakens Microsoft Defender", "تعطيل Microsoft Defender أو إضعافه"),
            new("Contains commands or settings that disable Defender's protection or exclude files from scanning.",
                "يحتوي على أوامر أو إعدادات تعطّل حماية Defender أو تستثني ملفات من الفحص."),
            ["T1562.001"], ["F0004"],
            Any(All(Txt("Set-MpPreference"), Txt("-DisableRealtimeMonitoring", "-DisableBehaviorMonitoring", "-DisableIOAVProtection",
                    "-DisableScriptScanning", "-DisableIntrusionPreventionSystem", "-SubmitSamplesConsent")),
                All(Txt("Add-MpPreference"), Txt("-ExclusionPath", "-ExclusionProcess", "-ExclusionExtension")),
                All(Txt("Windows Defender"), Txt("DisableAntiSpyware", "DisableRealtimeMonitoring", "DisableBehaviorMonitoring", "DisableOnAccessProtection")),
                Txt("Windows Defender\\Exclusions\\Paths"))),

        Rule("CAP-EVA-002", "defense-evasion/clear-logs", Severity.Medium,
            new("Clears Windows event logs", "مسح سجلات أحداث Windows"),
            new("Can erase the event logs that record what happened on the computer, hiding its tracks.",
                "يستطيع مسح سجلات الأحداث التي تدوّن ما جرى على الجهاز، فيخفي آثاره."),
            ["T1070.001"], [],
            Any(All(Txt("wevtutil"), Txt(" cl ", " clear-log ")), Txt("Clear-EventLog"), Api("ClearEventLog", "EvtClearLog"))),

        Rule("CAP-EVA-003", "defense-evasion/timestomp", Severity.Low,
            new("Changes file timestamps", "تغيير توقيتات الملفات"),
            new("Can copy the dates of a Windows system file onto its own files so they look old and trustworthy. Archive tools also set file dates.",
                "يستطيع نسخ تواريخ ملف من ملفات النظام إلى ملفاته ليبدو قديمًا وموثوقًا. أدوات الضغط تضبط تواريخ الملفات أيضًا."),
            ["T1070.006"], [],
            All(Api("SetFileTime"), Api("GetFileTime"),
                Txt("\\system32\\kernel32.dll", "\\system32\\ntdll.dll", "\\system32\\cmd.exe", "\\system32\\notepad.exe", "\\explorer.exe"))),

        Rule("CAP-EVA-004", "defense-evasion/uac-bypass", Severity.High,
            new("Bypasses User Account Control", "تجاوز التحكم في حساب المستخدم (UAC)"),
            new("Contains registry paths or programs used by known tricks to gain administrator rights without the UAC prompt.",
                "يحتوي على مسارات سجل أو برامج تستخدمها حيل معروفة للحصول على صلاحيات المسؤول دون ظهور نافذة UAC."),
            ["T1548.002"], [],
            Any(Txt("ms-settings\\shell\\open\\command", "mscfile\\shell\\open\\command", "exefile\\shell\\open\\command",
                    "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"),
                All(Txt("DelegateExecute"), Txt("fodhelper", "computerdefaults", "sdclt", "eventvwr", "slui", "wsreset", "Folder\\shell\\open\\command")))),

        Rule("CAP-EVA-005", "defense-evasion/amsi-bypass", Severity.High,
            new("Bypasses the Antimalware Scan Interface (AMSI)", "تجاوز واجهة فحص البرمجيات الخبيثة (AMSI)"),
            new("Can disable the Windows interface that lets antivirus inspect scripts before they run.",
                "يستطيع تعطيل واجهة Windows التي تسمح لبرامج الحماية بفحص السكربتات قبل تشغيلها."),
            ["T1562.001"], ["F0004.004"],
            Any(Txt("amsiInitFailed", "AmsiUtils"),
                All(Dyn("AmsiScanBuffer", "AmsiOpenSession"), Api("VirtualProtect", "NtProtectVirtualMemory", "WriteProcessMemory"), Api("GetProcAddress")))),

        Rule("CAP-EVA-006", "defense-evasion/etw-tampering", Severity.Medium,
            new("Blinds Windows event tracing", "تعطيل تتبّع أحداث Windows"),
            new("Resolves the event-tracing functions at run time together with memory-protection changes, a pattern used to stop security tools from seeing activity.",
                "يحدّد دوال تتبّع الأحداث أثناء التشغيل مع تغيير حماية الذاكرة، وهو نمط يُستخدم لمنع أدوات الحماية من رؤية النشاط."),
            ["T1562.006"], ["F0004"],
            Any(All(Dyn("EtwEventWrite", "NtTraceEvent", "EtwEventWriteFull"), Api("VirtualProtect", "NtProtectVirtualMemory"), Api("GetProcAddress")),
                All(Txt("PSEtwLogProvider"), Txt("m_enabled", "etwProvider")))),

        Rule("CAP-EVA-007", "defense-evasion/self-deletion", Severity.Medium,
            new("Deletes itself after running", "حذف نفسه بعد التشغيل"),
            new("Contains a command that waits briefly and then deletes the program's own file. Uninstallers sometimes do this.",
                "يحتوي على أمر ينتظر قليلًا ثم يحذف ملف البرنامج نفسه. بعض برامج إلغاء التثبيت تفعل ذلك."),
            ["T1070.004"], ["F0007"],
            Any(All(Txt("del ", "erase "), Txt("ping 127.0.0.1", "ping -n", "timeout /t", "choice /c")),
                All(Txt("Remove-Item"), Txt("$MyInvocation.MyCommand", "$PSCommandPath")))),

        Rule("CAP-EVA-008", "defense-evasion/disable-firewall", Severity.Medium,
            new("Turns off the Windows firewall", "تعطيل جدار حماية Windows"),
            new("Contains commands or settings that switch the firewall off.",
                "يحتوي على أوامر أو إعدادات توقف جدار الحماية."),
            ["T1562.004"], [],
            Any(Txt("set allprofiles state off", "firewall set opmode disable", "opmode mode=disable"),
                All(Txt("Set-NetFirewallProfile"), Txt("-Enabled False")),
                All(Txt("FirewallPolicy"), Txt("EnableFirewall")))),

        Rule("CAP-EVA-009", "defense-evasion/disable-system-tools", Severity.Medium,
            new("Blocks Task Manager or the Registry Editor", "منع فتح مدير المهام أو محرر السجل"),
            new("Refers to policies that stop you from opening Task Manager, the Registry Editor or the command prompt to remove it.",
                "يشير إلى سياسات تمنعك من فتح مدير المهام أو محرر السجل أو موجّه الأوامر لإزالته."),
            ["T1562.001", "T1112"], ["E1112"],
            Txt("DisableTaskMgr", "DisableRegistryTools", "DisableCMD")),

        Rule("CAP-EVA-010", "defense-evasion/hide-files", Severity.Low,
            new("Hides files", "إخفاء الملفات"),
            new("Can mark files as hidden system files so they do not show in File Explorer.",
                "يستطيع وسم الملفات كملفات نظام مخفية فلا تظهر في مستكشف الملفات."),
            ["T1564.001"], ["F0005"],
            Txt("attrib +h", "attrib +s +h", "attrib.exe +h", "attrib +r +s +h")),

        Rule("CAP-EVA-011", "defense-evasion/hidden-desktop", Severity.Medium,
            new("Runs programs on a hidden desktop", "تشغيل برامج على سطح مكتب مخفي"),
            new("Can create an invisible desktop, start programs on it and capture their windows: how hidden remote-control tools (hVNC) work.",
                "يستطيع إنشاء سطح مكتب غير مرئي وتشغيل برامج عليه والتقاط نوافذها، وهي طريقة عمل أدوات التحكم عن بُعد المخفية (hVNC)."),
            ["T1564.003"], [],
            All(Api("CreateDesktop"), Api("CreateProcess"), Api("PrintWindow"))),

        Rule("CAP-EVA-012", "defense-evasion/unhook", Severity.Medium,
            new("Loads a clean copy of system code to avoid monitoring", "تحميل نسخة نظيفة من شيفرة النظام لتفادي المراقبة"),
            new("Reads a fresh copy of ntdll.dll, a known way to remove the hooks that security software places in programs.",
                "يقرأ نسخة جديدة من ntdll.dll، وهي طريقة معروفة لإزالة نقاط المراقبة التي تضعها برامج الحماية داخل البرامج."),
            ["T1562.001"], ["F0004.003"],
            Txt("\\KnownDlls\\ntdll.dll", "\\KnownDlls32\\ntdll.dll")),

        // ---- Execution: injection ------------------------------------------------------------
        Rule("CAP-INJ-001", "execution/process-injection", Severity.High,
            new("Injects code with a remote thread", "حقن شيفرة عبر خيط بعيد"),
            new("Can write code into another running program and start it there, hiding inside a trusted process.",
                "يستطيع كتابة شيفرة داخل برنامج آخر قيد التشغيل وتشغيلها هناك، فيختبئ داخل عملية موثوقة."),
            ["T1055", "T1055.001"], ["E1055", "E1055.001"],
            All(Api("OpenProcess", "NtOpenProcess", "CreateProcess"), Api("VirtualAllocEx", "NtAllocateVirtualMemory", "VirtualAlloc2"),
                Api("WriteProcessMemory", "NtWriteVirtualMemory"), Api("CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx", "RtlCreateUserThread"))),

        Rule("CAP-INJ-002", "execution/process-injection/apc", Severity.High,
            new("Injects code through asynchronous procedure calls", "حقن شيفرة عبر الاستدعاءات غير المتزامنة (APC)"),
            new("Can place code in another process and queue it to run on one of its threads.",
                "يستطيع وضع شيفرة في عملية أخرى وجدولتها لتعمل على أحد خيوطها."),
            ["T1055.004"], ["E1055.004"],
            All(Api("QueueUserAPC", "NtQueueApcThread", "NtQueueApcThreadEx"), Api("WriteProcessMemory", "NtWriteVirtualMemory"),
                Api("VirtualAllocEx", "NtAllocateVirtualMemory"), Api("OpenThread", "NtOpenThread", "CreateProcess"))),

        Rule("CAP-INJ-003", "execution/process-injection/hollowing", Severity.High,
            new("Process hollowing", "تفريغ العملية (Process Hollowing)"),
            new("Can start a legitimate program, remove its code and replace it with different code, so the malware runs under a trusted name.",
                "يستطيع تشغيل برنامج سليم ثم إزالة شيفرته واستبدالها بأخرى، فتعمل البرمجية الخبيثة تحت اسم موثوق."),
            ["T1055.012"], ["E1055.012"],
            All(Api("NtUnmapViewOfSection", "ZwUnmapViewOfSection"), Api("WriteProcessMemory", "NtWriteVirtualMemory"),
                Api("SetThreadContext", "Wow64SetThreadContext", "NtSetContextThread"), Api("ResumeThread", "NtResumeThread"))),

        Rule("CAP-INJ-004", "execution/process-injection/thread-hijacking", Severity.Medium,
            new("Hijacks threads of other processes", "اختطاف خيوط عمليات أخرى"),
            new("Can pause a thread in another program, point it at new code and resume it. Debuggers use the same functions.",
                "يستطيع إيقاف خيط في برنامج آخر وتوجيهه إلى شيفرة جديدة ثم استئنافه. أدوات التصحيح تستخدم الدوال نفسها."),
            ["T1055.003"], ["E1055.003"],
            All(Api("OpenThread", "NtOpenThread"), Api("SuspendThread", "NtSuspendThread"), Api("GetThreadContext", "Wow64GetThreadContext", "NtGetContextThread"),
                Api("SetThreadContext", "Wow64SetThreadContext", "NtSetContextThread"), Api("WriteProcessMemory", "NtWriteVirtualMemory"),
                Api("VirtualAllocEx", "NtAllocateVirtualMemory"))),

        Rule("CAP-INJ-005", "execution/process-injection/section-mapping", Severity.High,
            new("Injects code through shared memory sections", "حقن شيفرة عبر أقسام ذاكرة مشتركة"),
            new("Can map memory shared with another process and start code from it, an injection method that avoids the usual write functions.",
                "يستطيع ربط ذاكرة مشتركة مع عملية أخرى وتشغيل شيفرة منها، وهي طريقة حقن تتفادى دوال الكتابة المعتادة."),
            ["T1055"], ["E1055"],
            All(Api("NtCreateSection", "ZwCreateSection"), Api("NtMapViewOfSection", "ZwMapViewOfSection"),
                Api("NtCreateThreadEx", "RtlCreateUserThread", "CreateRemoteThread", "QueueUserAPC", "NtQueueApcThread"))),

        Rule("CAP-INJ-006", "execution/process-injection/doppelganging", Severity.High,
            new("Process doppelgänging", "انتحال العملية عبر المعاملات (Doppelgänging)"),
            new("Can use file-system transactions to run code from a file that never really exists on disk.",
                "يستطيع استخدام معاملات نظام الملفات لتشغيل شيفرة من ملف لا يوجد فعليًا على القرص."),
            ["T1055.013"], ["E1055"],
            All(Api("CreateTransaction", "NtCreateTransaction"), Api("CreateFileTransacted"), Api("NtCreateSection", "ZwCreateSection"),
                Api("NtCreateProcessEx", "RollbackTransaction", "NtRollbackTransaction"))),

        // ---- Execution -----------------------------------------------------------------------
        Rule("CAP-EXE-001", "execution/shellcode/callback", Severity.Low,
            new("Runs code from memory through callbacks", "تشغيل شيفرة من الذاكرة عبر دوال الاستدعاء الراجع"),
            new("Combines making memory executable with functions that can be abused to jump into it, a common shellcode-loader trick.",
                "يجمع بين جعل الذاكرة قابلة للتنفيذ ودوال يمكن استغلالها للقفز إليها، وهي حيلة شائعة في محمّلات الشيفرة (Shellcode)."),
            ["T1106"], [],
            All(Api("VirtualAlloc", "NtAllocateVirtualMemory"), Api("VirtualProtect", "NtProtectVirtualMemory"),
                Api("EnumDateFormats", "CertEnumSystemStore", "EnumUILanguages", "EnumSystemGeoID", "EnumSystemLanguageGroups", "SwitchToFiber"))),

        Rule("CAP-EXE-002", "execution/shellcode/managed-loader", Severity.High,
            new("Script or .NET shellcode loader", "محمّل شيفرة (Shellcode) في سكربت أو برنامج .NET"),
            new("Declares Windows memory functions from a script or .NET code and copies raw code into memory to run it, a classic in-memory loader.",
                "يعرّف دوال الذاكرة في Windows من داخل سكربت أو شيفرة .NET وينسخ شيفرة خامًا إلى الذاكرة لتشغيلها، وهو محمّل كلاسيكي يعمل في الذاكرة."),
            ["T1620", "T1106"], [],
            All(Dyn("VirtualAlloc", "VirtualAllocEx", "NtAllocateVirtualMemory"),
                Any(Dyn("CreateThread", "CreateRemoteThread"), Tok("GetDelegateForFunctionPointer")),
                Any(Txt("Marshal.Copy", "Marshal]::Copy"), All(Tok("Marshal"), Tok("Copy")), Dyn("RtlMoveMemory")))),

        Rule("CAP-EXE-003", "execution/powershell/hidden-encoded", Severity.Medium,
            new("Runs hidden or encoded PowerShell", "تشغيل PowerShell مخفي أو مُرمَّز"),
            new("Starts PowerShell with options that hide its window or its commands. Admin scripts sometimes do this; malware very often.",
                "يشغّل PowerShell بخيارات تخفي نافذته أو أوامره. تفعل ذلك سكربتات الإدارة أحيانًا، والبرمجيات الخبيثة كثيرًا."),
            ["T1059.001", "T1027"], ["E1059", "E1027"],
            All(Txt("powershell"),
                Txt("-EncodedCommand", "-enc ", "-ec ", "-w hidden", "-WindowStyle Hidden", "-win hidden", "-windowstyle h"),
                AtLeast(2, Txt("-EncodedCommand", "-enc ", "-ec "), Txt("-w hidden", "-WindowStyle Hidden", "-win hidden", "-windowstyle h"),
                    Txt("-nop ", "-NoProfile"), Txt("-ExecutionPolicy Bypass", "-ep bypass", "-exec bypass"), Txt("FromBase64String")))),

        Rule("CAP-EXE-004", "execution/download-and-run", Severity.Medium,
            new("Downloads and runs more code", "تنزيل شيفرة إضافية وتشغيلها"),
            new("Can fetch a file or script from the internet and run it straight away. Updaters do this; so do droppers.",
                "يستطيع جلب ملف أو سكربت من الإنترنت وتشغيله فورًا. تفعل ذلك برامج التحديث، وكذلك البرمجيات التي تُنزّل برمجيات خبيثة."),
            ["T1105", "T1059"], ["E1105", "B0023"],
            Any(All(Txt("DownloadString", "DownloadData", "DownloadFile", "Invoke-WebRequest", "Invoke-RestMethod", "Net.WebClient", "Start-BitsTransfer"),
                    Txt("Invoke-Expression", "iex(", "iex (", "| iex", "|iex", "Start-Process", "Reflection.Assembly]::Load")),
                All(Api("URLDownloadToFile", "URLDownloadToCacheFile"), Api("ShellExecute", "ShellExecuteEx", "WinExec", "CreateProcess")),
                All(Txt("certutil"), Txt("-urlcache")),
                All(Txt("bitsadmin"), Txt("/transfer")))),

        Rule("CAP-EXE-005", "execution/reflective-dotnet", Severity.Medium,
            new("Loads and runs a .NET program from memory", "تحميل برنامج .NET وتشغيله من الذاكرة"),
            new("Can load another .NET program from bytes in memory and run its entry point, so the second program never touches the disk.",
                "يستطيع تحميل برنامج .NET آخر من بايتات في الذاكرة وتشغيل نقطة بدايته، فلا يُكتب البرنامج الثاني على القرص أبدًا."),
            ["T1620"], [],
            Any(Txt("Reflection.Assembly]::Load"), All(Tok("Assembly"), Tok("Load"), Tok("EntryPoint"), Tok("Invoke")))),

        Rule("CAP-EXE-006", "execution/wmi", Severity.Medium,
            new("Starts programs through WMI", "تشغيل البرامج عبر WMI"),
            new("Can start processes through Windows Management Instrumentation, which hides the usual parent-child link.",
                "يستطيع تشغيل العمليات عبر أداة إدارة Windows ‏(WMI)، مما يخفي العلاقة المعتادة بين العملية الأصل والعملية الفرعية."),
            ["T1047"], [],
            Any(Txt("process call create"), All(Txt("Win32_Process"), Txt("-Name Create", "-MethodName Create", ".Create(", "\"Create\"")))),

        Rule("CAP-EXE-007", "execution/proxy-execution", Severity.Medium,
            new("Runs code through trusted Windows programs", "تشغيل شيفرة عبر برامج Windows موثوقة"),
            new("Uses built-in programs such as mshta, rundll32 or regsvr32 to run scripts, so the activity looks like Windows itself.",
                "يستخدم برامج مدمجة مثل mshta أو rundll32 أو regsvr32 لتشغيل السكربتات، فيبدو النشاط كأنه من Windows نفسه."),
            ["T1218"], [],
            Any(All(Txt("rundll32"), Txt("javascript:")),
                All(Txt("regsvr32"), Txt("/i:http", "scrobj.dll")),
                All(Txt("mshta"), Txt("vbscript:", "javascript:", "http://", "https://")),
                All(Txt("msiexec"), Txt("/q"), Txt("http://", "https://")))),

        Rule("CAP-EXE-008", "execution/command-shell", Severity.Informational,
            new("Runs command-line commands", "تشغيل أوامر سطر الأوامر"),
            new("Can run commands through cmd.exe. Very common in installers and tools.",
                "يستطيع تشغيل أوامر عبر cmd.exe. شائع جدًا في برامج التثبيت والأدوات."),
            ["T1059.003"], ["E1059"],
            All(Txt("cmd.exe /c", "cmd /c", "cmd.exe /k", "cmd /k"), Any(Api("CreateProcess", "ShellExecute", "ShellExecuteEx", "WinExec"), Tok("ProcessStartInfo")))),

        // ---- Persistence ---------------------------------------------------------------------
        Rule("CAP-PER-001", "persistence/run-key", Severity.Medium,
            new("Starts automatically through a Run registry key", "التشغيل التلقائي عبر مفتاح Run في السجل"),
            new("Can add itself to the registry keys that Windows reads at every sign-in. Many legitimate apps do this.",
                "يستطيع إضافة نفسه إلى مفاتيح السجل التي يقرؤها Windows عند كل تسجيل دخول. كثير من البرامج السليمة تفعل ذلك."),
            ["T1547.001"], ["F0012"],
            All(Txt("CurrentVersion\\Run"),
                Any(Api("RegSetValueEx", "RegSetKeyValue", "NtSetValueKey"), Txt("reg add", "New-ItemProperty", "Set-ItemProperty", "RegWrite"), Tok("SetValue")))),

        Rule("CAP-PER-002", "persistence/logon-hijack", Severity.Medium,
            new("Hooks into Windows sign-in or program start-up", "التدخّل في تسجيل الدخول إلى Windows أو بدء البرامج"),
            new("Refers to Winlogon, Image File Execution Options or AppInit_DLLs, places that make Windows run extra code at sign-in or whenever a program starts.",
                "يشير إلى Winlogon أو Image File Execution Options أو AppInit_DLLs، وهي أماكن تجعل Windows يشغّل شيفرة إضافية عند تسجيل الدخول أو عند بدء أي برنامج."),
            ["T1547.004", "T1546.012", "T1546.010"], ["E1112"],
            Any(All(Txt("Winlogon"), Txt("Userinit", "Taskman", "Winlogon\\Notify")),
                All(Txt("Image File Execution Options"), Txt("Debugger", "GlobalFlag")),
                Txt("AppInit_DLLs"),
                All(Txt("SilentProcessExit"), Txt("MonitorProcess")))),

        Rule("CAP-PER-003", "persistence/service", Severity.Low,
            new("Installs a Windows service", "تثبيت خدمة Windows"),
            new("Can register a program as a service that starts with Windows. Normal for system software.",
                "يستطيع تسجيل برنامج كخدمة تبدأ مع Windows. أمر طبيعي في برامج النظام."),
            ["T1543.003"], [],
            Any(All(Api("OpenSCManager"), Api("CreateService")), Txt("sc create ", "sc.exe create ", "New-Service "))),

        Rule("CAP-PER-004", "persistence/scheduled-task", Severity.Medium,
            new("Creates a scheduled task", "إنشاء مهمة مجدولة"),
            new("Can create a scheduled task to run itself at sign-in or on a timer.",
                "يستطيع إنشاء مهمة مجدولة لتشغيل نفسه عند تسجيل الدخول أو في أوقات محددة."),
            ["T1053.005"], [],
            Any(Txt("schtasks /create", "schtasks.exe /create", "Register-ScheduledTask", "New-ScheduledTaskAction"),
                All(Txt("Schedule.Service"), Txt("RegisterTaskDefinition", "NewTask")),
                All(Tok("TaskService"), Tok("RegisterTaskDefinition")))),

        Rule("CAP-PER-005", "persistence/startup-folder", Severity.Medium,
            new("Places a file in the Startup folder", "وضع ملف في مجلد بدء التشغيل"),
            new("Refers to the Startup folder and can copy a file or shortcut there, so it runs at every sign-in.",
                "يشير إلى مجلد بدء التشغيل ويستطيع نسخ ملف أو اختصار إليه، فيعمل عند كل تسجيل دخول."),
            ["T1547.001"], ["F0012"],
            All(Txt("Start Menu\\Programs\\Startup", "shell:startup"),
                Any(Api("CopyFile", "CopyFileEx", "MoveFile", "MoveFileEx", "URLDownloadToFile"), Tok("CreateShortcut"), Txt("Copy-Item")))),

        Rule("CAP-PER-006", "persistence/wmi-subscription", Severity.High,
            new("Persists with a WMI event subscription", "الاستمرار عبر اشتراك في أحداث WMI"),
            new("Can register a hidden WMI rule that runs a command when an event happens, a stealthy way to survive reboots.",
                "يستطيع تسجيل قاعدة WMI مخفية تشغّل أمرًا عند وقوع حدث معيّن، وهي طريقة خفية للبقاء بعد إعادة التشغيل."),
            ["T1546.003"], [],
            AtLeast(2, Each("__EventFilter", "CommandLineEventConsumer", "ActiveScriptEventConsumer", "__FilterToConsumerBinding"))),

        Rule("CAP-PER-007", "persistence/com-hijack", Severity.Low,
            new("Registers a per-user COM object", "تسجيل كائن COM خاص بالمستخدم"),
            new("Can register a COM component for the current user, which may override a Windows component so its code loads into other programs.",
                "يستطيع تسجيل مكوّن COM للمستخدم الحالي، وقد يحلّ محل مكوّن من Windows فتُحمَّل شيفرته داخل برامج أخرى."),
            ["T1546.015"], ["F0015"],
            All(Txt("Software\\Classes\\CLSID"), Txt("InprocServer32"), Txt("HKCU", "HKEY_CURRENT_USER"))),

        Rule("CAP-PER-008", "persistence/accessibility-backdoor", Severity.High,
            new("Replaces accessibility tools at the sign-in screen", "استبدال أدوات إمكانية الوصول في شاشة تسجيل الدخول"),
            new("Refers to Sticky Keys or similar tools together with ways to replace them, which gives a command prompt at the sign-in screen without a password.",
                "يشير إلى أداة المفاتيح الدبقة أو أدوات مشابهة مع طرق لاستبدالها، مما يتيح فتح موجّه الأوامر في شاشة تسجيل الدخول دون كلمة مرور."),
            ["T1546.008"], [],
            All(Txt("sethc.exe", "utilman.exe", "osk.exe", "Magnify.exe", "DisplaySwitch.exe"), Txt("Image File Execution Options", "takeown", "icacls"))),

        // ---- Discovery -----------------------------------------------------------------------
        Rule("CAP-DIS-001", "discovery/system-information", Severity.Informational,
            new("Collects system information", "جمع معلومات عن النظام"),
            new("Reads the computer name, user name, Windows version, hardware or disks. Most programs read some of this.",
                "يقرأ اسم الجهاز واسم المستخدم وإصدار Windows والعتاد أو الأقراص. معظم البرامج تقرأ بعض هذه المعلومات."),
            ["T1082"], ["E1082"],
            AtLeast(4, Api("GetComputerName", "GetComputerNameEx"), Api("GetUserName", "GetUserNameEx"), Api("GetVersionEx", "RtlGetVersion"),
                Api("GetNativeSystemInfo", "GetSystemInfo"), Api("GlobalMemoryStatusEx"), Api("GetLogicalDriveStrings", "GetDiskFreeSpaceEx"),
                Txt("systeminfo", "Win32_OperatingSystem", "Win32_Processor", "Win32_VideoController", "HARDWARE\\DESCRIPTION\\System\\CentralProcessor"))),

        Rule("CAP-DIS-002", "discovery/process-list", Severity.Informational,
            new("Lists running programs", "سرد البرامج قيد التشغيل"),
            new("Can list the programs that are running. Task managers and many utilities do this.",
                "يستطيع سرد البرامج قيد التشغيل. تفعل ذلك برامج إدارة المهام وكثير من الأدوات."),
            ["T1057"], [],
            Any(All(Api("CreateToolhelp32Snapshot"), Api("Process32First"), Api("Process32Next")), Api("EnumProcesses"), Txt("tasklist"))),

        Rule("CAP-DIS-003", "discovery/security-software", Severity.Medium,
            new("Looks for installed antivirus", "البحث عن برامج الحماية المثبّتة"),
            new("Queries the installed security products or contains the process names of several antivirus programs.",
                "يستعلم عن منتجات الحماية المثبّتة أو يحتوي على أسماء عمليات عدة برامج مكافحة فيروسات."),
            ["T1518.001"], [],
            Any(All(Txt("SecurityCenter2"), Txt("AntiVirusProduct", "FirewallProduct", "AntiSpywareProduct")),
                AtLeast(3, Each("MsMpEng", "avp.exe", "ekrn.exe", "avgnt", "bdagent", "mcshield", "avastui", "avgui", "SavService", "egui.exe",
                    "NortonSecurity", "ccSvcHst", "MBAMService", "SophosHealth", "CylanceSvc", "CSFalconService", "SentinelAgent", "AvastSvc", "bdservicehost")))),

        Rule("CAP-DIS-004", "discovery/public-ip", Severity.Low,
            new("Looks up the computer's public IP address and location", "معرفة عنوان IP العام للجهاز وموقعه"),
            new("Contains web services that return the public IP address or country. Stealers use them to label victims; some apps for region settings.",
                "يحتوي على خدمات ويب تعيد عنوان IP العام أو الدولة. تستخدمها برامج السرقة لتصنيف الضحايا، وبعض التطبيقات لضبط المنطقة."),
            ["T1016", "T1614"], [],
            Txt("api.ipify.org", "ipinfo.io", "icanhazip.com", "checkip.dyndns.org", "checkip.amazonaws.com", "ip-api.com", "ifconfig.me",
                "myexternalip.com", "wtfismyip.com", "ipwho.is", "freegeoip.app", "api.myip.com", "geoplugin.net", "ipapi.co")),

        Rule("CAP-DIS-005", "discovery/language-check", Severity.Low,
            new("Checks the keyboard and system language", "فحص لغة لوحة المفاتيح والنظام"),
            new("Reads installed keyboard layouts and the system language. Some malware stops when it finds certain countries' languages.",
                "يقرأ تخطيطات لوحة المفاتيح المثبّتة ولغة النظام. بعض البرمجيات الخبيثة تتوقّف عند وجود لغات دول معيّنة."),
            ["T1614.001"], ["B0025"],
            All(Api("GetKeyboardLayoutList"), Api("GetUserDefaultLangID", "GetSystemDefaultLangID", "GetUserDefaultUILanguage", "GetUserDefaultLCID", "GetSystemDefaultLCID"))),

        Rule("CAP-DIS-006", "discovery/network-configuration", Severity.Informational,
            new("Examines the network configuration", "فحص إعدادات الشبكة"),
            new("Runs network commands or reads adapter and connection tables. Network tools do this routinely.",
                "يشغّل أوامر الشبكة أو يقرأ جداول المحوّلات والاتصالات. تفعل ذلك أدوات الشبكة عادةً."),
            ["T1016", "T1049"], [],
            AtLeast(2, Txt("ipconfig /all"), Txt("arp -a"), Txt("netstat -"), Txt("route print"), Api("GetAdaptersInfo", "GetAdaptersAddresses"),
                Api("GetIpNetTable"), Api("GetExtendedTcpTable", "GetTcpTable"))),

        Rule("CAP-DIS-007", "discovery/accounts-and-domain", Severity.Low,
            new("Explores user accounts and the domain", "استكشاف حسابات المستخدمين والنطاق"),
            new("Lists users, groups or domain controllers, often a first step before spreading through a company network.",
                "يسرد المستخدمين أو المجموعات أو وحدات التحكم بالنطاق، وهي غالبًا خطوة أولى قبل الانتشار في شبكة المؤسسة."),
            ["T1087", "T1069", "T1482"], [],
            AtLeast(2, Txt("net user"), Txt("net group", "net localgroup"), Txt("nltest"), Txt("domain admins"), Txt("whoami /"),
                Api("NetUserEnum"), Api("NetGroupGetUsers", "NetLocalGroupGetMembers"), Api("DsGetDcName"))),

        Rule("CAP-DIS-008", "discovery/network-shares", Severity.Low,
            new("Finds shared folders on the network", "البحث عن المجلدات المشتركة على الشبكة"),
            new("Can list shared folders on this or other computers. Ransomware uses this to reach more files.",
                "يستطيع سرد المجلدات المشتركة على هذا الجهاز أو غيره. تستخدم برامج الفدية ذلك للوصول إلى ملفات أكثر."),
            ["T1135"], [],
            Any(Api("NetShareEnum"), All(Api("WNetOpenEnum"), Api("WNetEnumResource")), Txt("net view"))),

        // ---- Command and control ---------------------------------------------------------------
        Rule("CAP-NET-001", "command-and-control/http-wininet", Severity.Informational,
            new("Communicates over HTTP (WinINet)", "الاتصال عبر HTTP ‏(WinINet)"),
            new("Can send and receive web requests. Most connected programs do.",
                "يستطيع إرسال طلبات الويب واستقبالها. معظم البرامج المتصلة بالإنترنت تفعل ذلك."),
            ["T1071.001"], ["C0002.007"],
            All(Api("InternetOpen"), Api("InternetOpenUrl", "InternetConnect", "HttpOpenRequest"), Api("InternetReadFile", "HttpSendRequest", "HttpSendRequestEx"))),

        Rule("CAP-NET-002", "command-and-control/http-winhttp", Severity.Informational,
            new("Communicates over HTTP (WinHTTP)", "الاتصال عبر HTTP ‏(WinHTTP)"),
            new("Can send and receive web requests. Most connected programs do.",
                "يستطيع إرسال طلبات الويب واستقبالها. معظم البرامج المتصلة بالإنترنت تفعل ذلك."),
            ["T1071.001"], ["C0002.008"],
            All(Api("WinHttpOpen"), Api("WinHttpConnect"), Api("WinHttpOpenRequest"), Api("WinHttpSendRequest"))),

        Rule("CAP-NET-003", "command-and-control/sockets", Severity.Informational,
            new("Uses raw network connections", "استخدام اتصالات شبكة مباشرة"),
            new("Can open its own network connections without a web library. Games, chat and server software do this.",
                "يستطيع فتح اتصالات شبكة خاصة به دون مكتبة ويب. تفعل ذلك الألعاب وبرامج الدردشة والخوادم."),
            ["T1095"], ["C0001"],
            All(Api("socket", "WSASocket"), Api("connect", "WSAConnect", "sendto"), Api("send", "recv", "WSASend", "WSARecv", "recvfrom"))),

        Rule("CAP-NET-004", "command-and-control/listen", Severity.Low,
            new("Accepts incoming network connections", "قبول اتصالات شبكة واردة"),
            new("Can wait for other computers to connect to it. Servers do this; so do backdoors.",
                "يستطيع انتظار اتصال أجهزة أخرى به. تفعل ذلك الخوادم، وكذلك الأبواب الخلفية."),
            ["T1095"], ["C0001.005"],
            All(Api("socket", "WSASocket"), Api("bind"), Api("listen"), Api("accept", "WSAAccept", "AcceptEx"))),

        Rule("CAP-NET-005", "command-and-control/reverse-shell", Severity.Medium,
            new("Remote command shell", "واجهة أوامر تُدار عن بُعد"),
            new("Can connect out and hand a command prompt to whoever is on the other end.",
                "يستطيع الاتصال بجهة خارجية وتسليمها موجّه أوامر على هذا الجهاز."),
            ["T1059.003", "T1095"], ["B0022.001"],
            Any(All(Api("WSASocket", "socket"), Api("connect", "WSAConnect"), Api("CreateProcess"), Txt("cmd.exe", "powershell"),
                    Api("CreatePipe", "PeekNamedPipe", "WSASocket")),
                All(Txt("Net.Sockets.TCPClient"), Txt("GetStream"), Txt("Invoke-Expression", "iex")))),

        Rule("CAP-NET-006", "command-and-control/tor", Severity.Medium,
            new("Uses the Tor network", "استخدام شبكة Tor"),
            new("Refers to Tor hidden services or a local Tor proxy, which hides where its server is.",
                "يشير إلى خدمات Tor المخفية أو إلى وسيط Tor محلي، مما يخفي مكان الخادم الذي يتصل به."),
            ["T1090.003"], [],
            Txt(".onion", "torrc", "SocksPort", "127.0.0.1:9050", "127.0.0.1:9150", "tor.exe")),

        Rule("CAP-NET-007", "command-and-control/dns", Severity.Low,
            new("Makes its own DNS queries", "إجراء استعلامات DNS خاصة به"),
            new("Can send DNS queries directly or over HTTPS. Data hidden in DNS can slip past filters.",
                "يستطيع إرسال استعلامات DNS مباشرة أو عبر HTTPS. البيانات المخفية في DNS قد تمر من عوامل التصفية."),
            ["T1071.004", "T1572"], ["C0011"],
            Any(Api("DnsQuery_A", "DnsQuery_W", "DnsQuery_UTF8", "DnsQueryEx"), Txt("dns.google/resolve", "cloudflare-dns.com/dns-query", "dns.quad9.net/dns-query"))),

        Rule("CAP-NET-008", "command-and-control/file-download", Severity.Low,
            new("Downloads files from the internet", "تنزيل ملفات من الإنترنت"),
            new("Can save a file from a web address to disk in one call.",
                "يستطيع حفظ ملف من عنوان ويب على القرص باستدعاء واحد."),
            ["T1105"], ["E1105"],
            Api("URLDownloadToFile", "URLDownloadToCacheFile")),

        // ---- Exfiltration ----------------------------------------------------------------------
        Rule("CAP-EXF-001", "exfiltration/messaging-api", Severity.Medium,
            new("Sends data to Telegram, Discord or Slack", "إرسال بيانات إلى Telegram أو Discord أو Slack"),
            new("Contains a bot or webhook address of a chat service. Stealers use these to deliver what they collect.",
                "يحتوي على عنوان روبوت أو Webhook لخدمة دردشة. تستخدمها برامج السرقة لإيصال ما تجمعه."),
            ["T1567", "T1102.002"], ["B0030"],
            Txt("api.telegram.org/bot", "discord.com/api/webhooks", "discordapp.com/api/webhooks", "hooks.slack.com/services")),

        Rule("CAP-EXF-002", "command-and-control/paste-and-file-sharing", Severity.Medium,
            new("Uses paste or file-sharing sites", "استخدام مواقع اللصق أو مشاركة الملفات"),
            new("Contains addresses of anonymous paste or file-sharing services, often used to fetch commands or upload stolen files.",
                "يحتوي على عناوين خدمات لصق أو مشاركة ملفات مجهولة، تُستخدم غالبًا لجلب الأوامر أو رفع الملفات المسروقة."),
            ["T1102.001", "T1567.002"], [],
            Txt("pastebin.com/raw", "paste.ee/r/", "hastebin.com/raw", "rentry.co/", "ghostbin", "transfer.sh", "anonfiles", "gofile.io",
                "files.catbox.moe", "temp.sh", "0x0.st")),

        Rule("CAP-EXF-003", "exfiltration/email-ftp", Severity.Medium,
            new("Sends data by e-mail or FTP", "إرسال بيانات عبر البريد الإلكتروني أو FTP"),
            new("Contains what is needed to log in to a mail or FTP server and send files.",
                "يحتوي على ما يلزم لتسجيل الدخول إلى خادم بريد أو FTP وإرسال الملفات."),
            ["T1048.003"], ["C0012", "C0004"],
            Any(All(Txt("smtp."), Txt("AUTH LOGIN", "MAIL FROM:", "RCPT TO:"), Txt("password", "PASS")),
                All(Tok("SmtpClient"), Tok("NetworkCredential"), Txt("smtp.")),
                Api("FtpPutFile"),
                All(Tok("FtpWebRequest"), Txt("UploadFile")))),

        // ---- Impact ----------------------------------------------------------------------------
        Rule("CAP-IMP-001", "impact/delete-shadow-copies", Severity.High,
            new("Deletes shadow copies", "حذف النسخ الاحتياطية الخفية (Shadow Copies)"),
            new("Can delete the snapshots Windows keeps for restoring files, a typical step before ransomware encrypts.",
                "يستطيع حذف اللقطات التي يحتفظ بها Windows لاستعادة الملفات، وهي خطوة معتادة قبل أن تشفّر برامج الفدية الملفات."),
            ["T1490"], ["E1485.m04"],
            Any(All(Txt("vssadmin"), Txt("delete shadows", "resize shadowstorage")),
                All(Txt("shadowcopy"), Txt("delete")),
                All(Txt("Win32_ShadowCopy"), Txt(".Delete", "Delete()", "Remove-WmiObject", "Remove-CimInstance")))),

        Rule("CAP-IMP-002", "impact/disable-recovery", Severity.High,
            new("Disables Windows recovery or deletes backups", "تعطيل الاسترداد في Windows أو حذف النسخ الاحتياطية"),
            new("Contains commands that turn off recovery at start-up or delete the backup catalog.",
                "يحتوي على أوامر توقف الاسترداد عند الإقلاع أو تحذف فهرس النسخ الاحتياطية."),
            ["T1490"], [],
            Any(All(Txt("bcdedit"), Txt("recoveryenabled no", "bootstatuspolicy ignoreallfailures")),
                All(Txt("wbadmin"), Txt("delete catalog", "delete systemstatebackup", "delete backup")))),

        Rule("CAP-IMP-003", "impact/ransomware", Severity.High,
            new("Encrypts files and demands a ransom", "تشفير الملفات وطلب فدية"),
            new("Can walk through folders, encrypt files and contains ransom-note wording. Together these are the core of ransomware.",
                "يستطيع التنقّل بين المجلدات وتشفير الملفات، ويحتوي على عبارات تشبه رسالة الفدية. اجتماعها هو جوهر برامج الفدية."),
            ["T1486"], ["E1486", "E1486.001"],
            All(Any(Api("CryptEncrypt", "BCryptEncrypt", "CryptImportKey", "BCryptImportKeyPair"), Tok("CreateEncryptor", "AesManaged", "RijndaelManaged", "AesCryptoServiceProvider")),
                Any(Api("FindFirstFile", "FindFirstFileEx", "NtQueryDirectoryFile"), Tok("GetFiles", "EnumerateFiles")),
                AtLeast(2, Each(RansomPhrases))))
        with { Supersedes = ["CAP-IMP-004"] },

        Rule("CAP-IMP-004", "impact/ransom-note", Severity.Medium,
            new("Contains ransom-note wording", "يحتوي على عبارات تشبه رسالة فدية"),
            new("Contains several phrases typical of ransom notes (encrypted files, payment, Tor, decryption key).",
                "يحتوي على عدة عبارات معتادة في رسائل الفدية (ملفات مشفّرة، دفع، Tor، مفتاح فك التشفير)."),
            ["T1486"], ["E1486.001"],
            AtLeast(3, Each(RansomPhrases))),

        Rule("CAP-IMP-005", "impact/raw-disk-write", Severity.Medium,
            new("Accesses the physical disk directly", "الوصول المباشر إلى القرص الفعلي"),
            new("Can open the whole disk below the file system, which allows overwriting the boot record. Disk utilities need this too.",
                "يستطيع فتح القرص كاملًا تحت مستوى نظام الملفات، مما يتيح الكتابة فوق سجل الإقلاع. أدوات الأقراص تحتاج ذلك أيضًا."),
            ["T1561.002", "T1542.003"], ["F0014", "F0013"],
            All(Txt("\\\\.\\PhysicalDrive", "PhysicalDrive0"), Api("WriteFile", "DeviceIoControl", "NtWriteFile"))),

        Rule("CAP-IMP-006", "impact/wipe", Severity.Medium,
            new("Securely wipes data", "مسح البيانات بشكل لا يمكن استرجاعه"),
            new("Contains commands that overwrite files or free disk space so deleted data cannot be recovered.",
                "يحتوي على أوامر تكتب فوق الملفات أو المساحة الفارغة فلا يمكن استرجاع البيانات المحذوفة."),
            ["T1485"], ["E1485"],
            Any(All(Txt("cipher"), Txt("/w:")), Txt("sdelete.exe", "sdelete64", "sdelete -"))),

        Rule("CAP-IMP-007", "impact/shutdown", Severity.Low,
            new("Shuts down or restarts the computer", "إيقاف تشغيل الجهاز أو إعادة تشغيله"),
            new("Can turn off or restart Windows. Installers often restart after an update.",
                "يستطيع إيقاف Windows أو إعادة تشغيله. برامج التثبيت تعيد التشغيل كثيرًا بعد التحديث."),
            ["T1529"], [],
            Any(Api("ExitWindowsEx", "InitiateSystemShutdown", "InitiateSystemShutdownEx", "InitiateShutdown", "NtShutdownSystem"),
                Txt("shutdown /r", "shutdown /s", "shutdown -r", "shutdown -s", "shutdown.exe /"))),

        Rule("CAP-IMP-008", "impact/crash-or-critical-process", Severity.High,
            new("Can crash Windows or make itself unkillable", "قادر على إيقاف Windows بشاشة زرقاء أو منع إنهاء نفسه"),
            new("Can mark itself as a critical process (ending it crashes Windows) or raise a fatal system error on purpose.",
                "يستطيع وسم نفسه كعملية حرجة (إنهاؤها يوقف Windows) أو إحداث خطأ نظام قاتل عمدًا."),
            ["T1529", "T1499"], ["B0033"],
            Any(Api("RtlSetProcessIsCritical"), All(Dyn("NtRaiseHardError", "ZwRaiseHardError"), Api("RtlAdjustPrivilege")))),

        Rule("CAP-IMP-009", "impact/stop-services", Severity.Medium,
            new("Stops databases and backup services", "إيقاف قواعد البيانات وخدمات النسخ الاحتياطي"),
            new("Contains commands to stop database, mail or backup programs, which ransomware does so it can encrypt their files.",
                "يحتوي على أوامر لإيقاف برامج قواعد البيانات أو البريد أو النسخ الاحتياطي، وهو ما تفعله برامج الفدية لتتمكّن من تشفير ملفاتها."),
            ["T1489"], [],
            All(Txt("net stop", "net.exe stop", "sc stop", "sc.exe stop", "taskkill", "Stop-Service"),
                AtLeast(2, Each("sqlservr", "MSSQL", "MSExchange", "Veeam", "BackupExec", "sqlwriter", "oracle.exe", "ocssd", "dbsnmp",
                    "mysqld", "postgres", "vmms", "vmcompute", "sqlagent")))),

        Rule("CAP-IMP-010", "impact/cryptomining", Severity.High,
            new("Mines cryptocurrency", "تعدين العملات الرقمية"),
            new("Contains mining-pool addresses or miner settings. Mining uses your computer's power and electricity for someone else's profit.",
                "يحتوي على عناوين مجمّعات تعدين أو إعدادات برنامج تعدين. التعدين يستهلك قدرة جهازك وكهرباءه لمصلحة شخص آخر."),
            ["T1496"], ["B0018.002"],
            Any(Txt("stratum+tcp://", "stratum+ssl://", "stratum2+tcp://"),
                AtLeast(2, Each("xmrig", "--donate-level", "cryptonight", "randomx", "nicehash", "minexmr", "supportxmr", "nanopool.org",
                    "moneroocean", "2miners.com")))),

        Rule("CAP-IMP-011", "impact/wallpaper", Severity.Low,
            new("Changes the desktop wallpaper", "تغيير خلفية سطح المكتب"),
            new("Can change the desktop background. Ransomware uses it to display its demands.",
                "يستطيع تغيير خلفية سطح المكتب. تستخدم برامج الفدية ذلك لعرض مطالبها."),
            ["T1491.001"], ["C0035"],
            All(Api("SystemParametersInfo"), Txt("Wallpaper"))),

        // ---- Lateral movement --------------------------------------------------------------------
        Rule("CAP-LAT-001", "lateral-movement/admin-shares", Severity.Medium,
            new("Spreads to other computers through admin shares", "الانتشار إلى أجهزة أخرى عبر المشاركات الإدارية"),
            new("Refers to the hidden administrative shares or PsExec, used to copy and run programs on other computers in the network.",
                "يشير إلى المشاركات الإدارية المخفية أو إلى PsExec، وتُستخدم لنسخ البرامج وتشغيلها على أجهزة أخرى في الشبكة."),
            ["T1021.002", "T1570"], [],
            All(Txt("\\ADMIN$", "\\C$\\", "PSEXESVC", "psexec"), Any(Api("WNetAddConnection2", "WNetAddConnection", "CopyFile", "OpenSCManager"), Txt("net use")))),

        Rule("CAP-LAT-002", "lateral-movement/removable-media", Severity.Medium,
            new("Spreads through USB drives", "الانتشار عبر وحدات USB"),
            new("Can find removable drives and write an autorun file to them, so it runs on other computers.",
                "يستطيع العثور على الأقراص القابلة للإزالة وكتابة ملف تشغيل تلقائي عليها، فيعمل على أجهزة أخرى."),
            ["T1091"], [],
            All(Txt("autorun.inf"), Api("GetDriveType"), Any(Api("CopyFile", "CopyFileEx"), Txt("[autorun]")))),

        Rule("CAP-LAT-003", "lateral-movement/enable-rdp", Severity.Medium,
            new("Turns on Remote Desktop", "تفعيل سطح المكتب البعيد"),
            new("Contains the settings that allow Remote Desktop connections to this computer.",
                "يحتوي على الإعدادات التي تسمح باتصالات سطح المكتب البعيد بهذا الجهاز."),
            ["T1021.001"], [],
            Txt("fDenyTSConnections", "RDPWrap")),
    ];
}
