# سطر الأوامر

**العربية** · [English](CLI.en.md)

<div dir="rtl">

تُثبَّت الأداة `blazma` بجانب `BlazmaSandbox.exe`. وهي تستخدم بيئات التحليل نفسها والقواعد
ومجلد YARA والإعدادات نفسها التي يستخدمها التطبيق، وتظهر تحليلاتها في سجل التطبيق (History).
نصوص المساعدة والرسائل بالعربية افتراضيًا؛ أضف `--lang en` لعرضها بالإنجليزية.

</div>

```
blazma static  <file> [--json] [--password <p>]
blazma analyze <file> [options]
blazma batch   <folder> [options] [--recursive] [--summary results.csv]
blazma list    [--limit 20] [--json]
blazma export  <analysis-id> --format html|pdf|json|stix|misp|sigma|yara --out <path>
blazma envs    [--json]
blazma help | version
```

<div dir="rtl">

## أمثلة

</div>

```powershell
# What is this file? Nothing is run.
blazma static .\invoice.exe

# Run it in Windows Sandbox for the standard two minutes, with the simulated internet.
blazma analyze .\invoice.exe --report invoice.html

# A sample shared as an encrypted ZIP (the password "infected" is tried automatically).
blazma static  .\sample.zip
blazma analyze .\sample.zip --entry payload/setup.exe

# A folder of samples overnight in a virtual machine, with a CSV summary.
blazma batch .\inbox --env virtualbox --profile deep --summary results.csv

# Indicators for your SIEM or threat-intelligence platform.
blazma export 31790d6c --format stix --out invoice.stix.json
```

<div dir="rtl">

ما تفعله هذه الأمثلة بالترتيب:

- `blazma static`: يعرض ما هو هذا الملف، دون تشغيل أي شيء.
- `blazma analyze ... --report`: يشغّل الملف في Windows Sandbox لمدة الدقيقتين المعتادتين، مع الإنترنت المحاكى.
- عينة مُشارَكة في ملف ZIP مشفّر: تُجرَّب كلمة المرور `infected` تلقائيًا، ويحدّد `--entry` الملف الذي يُشغَّل من داخل الأرشيف.
- `blazma batch`: يحلّل مجلدًا من العينات طوال الليل داخل جهاز افتراضي، مع ملخص بصيغة CSV.
- `blazma export --format stix`: يصدّر المؤشرات إلى نظام SIEM أو منصة استخبارات التهديدات لديك.

## خيارات التحليل

| الخيار | المعنى |
|---|---|
| `--env windows-sandbox\|virtualbox\|hyperv\|demo` | مكان التشغيل. الافتراضي: البيئة المختارة في الإعدادات (Settings). تُنتج `demo` أحداثًا اصطناعية وتُوسَم بعلامة DEMO. |
| `--profile quick\|standard\|deep\|interactive` | مدة التشغيل وما يُلتقط. الافتراضي: `standard`. |
| `--network simulated\|offline\|internet` | الافتراضي `simulated`: لا شبكة حقيقية، وإنترنت مزيّف داخل البيئة المعزولة يسجّل ما تحاول العينة فعله. |
| `--allow-internet` | مطلوب مع `--network internet`. عندها تستطيع العينة الوصول إلى خوادم حقيقية. |
| `--duration <seconds>` | يتجاوز مدة التشغيل المحددة في الملف التعريفي (من 15 إلى 1800 ثانية). |
| `--entry <path>` / `--password <p>` | للأرشيفات: الملف الذي يُشغَّل من داخل الأرشيف، وكلمة مروره. |
| `--report <path>` | يكتب أيضًا تقريرًا بصيغة `.html` أو `.pdf` أو `.json`. |
| `--lookup` | استعلام عن السمعة بالبصمة (hash) فقط، عبر الخدمات المفعّلة في الإعدادات (VirusTotal وMalwareBazaar). لا يُرفع الملف أبدًا. |
| `--pcap` | يسجّل حركة الشبكة في البيئة المعزولة (pcapng). |
| `--no-screenshots` | لا يلتقط صور شاشة البيئة المعزولة. |
| `--lang ar\|en` | لغة المخرجات: نصوص المساعدة والرسائل وعناوين النتائج. الافتراضي `ar` (العربية)؛ و`en` تعطي الإنجليزية. |
| `--json` | مخرجات قابلة للقراءة آليًا على stdout؛ ويذهب التقدّم إلى stderr. |
| `--data <folder>` | يستخدم مجلد بيانات آخر (ويمكن أيضًا عبر `BLAZMA_DATA`). |

## رموز الخروج (Exit codes)

| الرمز | المعنى |
|---|---|
| 0 | اكتمل؛ خطورة منخفضة (أو أمر غير `analyze`/`batch`) |
| 10 | مشبوه |
| 20 | سلوك عالي الخطورة |
| 30 | سلوك حرج |
| 1 | خطأ (فشل التحليل، أو تعذّرت قراءة ملف) |
| 2 | خطأ في طريقة الاستخدام |
| 3 | بيئة التحليل غير جاهزة (يوضّح `blazma envs` السبب) |
| 4 | أُلغي (Ctrl+C) |

في `batch` تُعتمد النتيجة الأشد خطورة. الدرجة دليل يراجعه شخص، وليست إثباتًا على أن الملف خبيث.

## الأمان

يتبع سطر الأوامر القواعد نفسها التي يتبعها التطبيق: يجري التحليل الثابت واستخراج الأرشيفات في
عمليات مساعدة منفصلة (`blazma --static-worker` و`--extract-worker`)، ولا تُشغَّل العينة إلا داخل
بيئة التحليل، ويتطلب الاتصال بالشبكة الحقيقية الخيار `--allow-internet`.

</div>
