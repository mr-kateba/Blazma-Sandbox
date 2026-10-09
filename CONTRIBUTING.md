# المساهمة

**العربية** · [English](CONTRIBUTING.en.md)

<div dir="rtl">

شكرًا على مساعدتك. هذه القواعد تحافظ على أمان Blazma Sandbox وصدقه.

## القواعد الأساسية

1. **ترتيب الأولويات:** الأمان > الصحة > الاستقرار > تجربة المستخدم > الأداء > الميزات الإضافية.
2. **لا تزيّف ميزة أبدًا.** إذا لم يكن شيء ما منفَّذًا، فإنه يظهر بوسم *مخطط له* ويكون معطلًا.
3. **لا حكم بناءً على مؤشر واحد.** الاكتشافات الجديدة تضيف نتائج موزونة مدعومة بالأدلة، ولا تقرر
   الحكم وحدها أبدًا.
4. **محلي أولًا.** لا اتصالات بالشبكة ما لم يوافق المستخدم على ذلك، ولا تغادر العيّنة الجهاز أبدًا.
5. **عامِل مخرجات الوكيل كمدخلات معادية.** كل ما يأتي من داخل البيئة المعزولة يُتحقق منه، ويُقيَّد
   حجمه، ولا يُنفَّذ أبدًا.

## الإعداد

- .NET SDK 10.0.100 أو أحدث (راجع `global.json`)
- Windows 10/11 Pro أو Enterprise مع تفعيل *Windows Sandbox* لاختبار التحليلات الحقيقية.
  كل ما عدا ذلك، بما فيه الوضع التجريبي وكل الاختبارات، يعمل أيضًا على Linux وmacOS.

<div dir="ltr">

```bash
dotnet build Blazma.Sandbox.slnx
dotnet test Blazma.Sandbox.slnx
dotnet run --project src/Blazma.App          # demo mode works without Windows Sandbox
```

</div>

لقطات شاشة الواجهة (دون واجهة رسومية، ولا حاجة إلى شاشة):

<div dir="ltr">

```bash
dotnet run --project tools/Blazma.Screenshots -- out en        # or: out ar · out en Report Light
```

</div>

## أين يوضع كل شيء

| التغيير | المشروع |
|---|---|
| النماذج، والإعدادات، والواجهات البرمجية (interfaces) | `src/Blazma.Core` |
| الرسائل بين الوكيل والمضيف | `src/Blazma.Contracts` (أبقِه صغيرًا ومُرقّم الإصدارات) |
| التحليل الثابت، والقواعد، وحساب الدرجة، والربط | `src/Blazma.Analysis` |
| مزوّدو البيئة المعزولة، والقناة، والوضع التجريبي | `src/Blazma.Sandbox` |
| الشيفرة التي تعمل *داخل* البيئة المعزولة | `src/Blazma.Agent` |
| قاعدة البيانات | `src/Blazma.Storage` |
| التصدير | `src/Blazma.Reporting` |
| Ask Blazma، والسمعة | `src/Blazma.Intelligence` |
| الواجهة | `src/Blazma.App` |

راجع [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## قائمة التحقق لطلب الدمج (pull request)

- [ ] لا يُظهر `dotnet build` أي تحذيرات، وينجح `dotnet test`.
- [ ] للمنطق الجديد اختبارات. تحتاج القواعد إلى اختبار إيجابي واختبار على نشاط نظيف.
- [ ] كل نص يظهر للمستخدم موجود في **كلٍّ من** `Localization/en.json` و`ar.json`. وتتحقق
      `LocalizationTests` من ذلك.
- [ ] تبدو تغييرات الواجهة صحيحة بالعربية (RTL) وفي السمة Light. أرفق لقطات شاشة.
- [ ] لا وصول جديد إلى الشبكة، ولا قياس عن بُعد (telemetry)، ولا اتصالات صادرة.
- [ ] حُدِّث `CHANGELOG.md` تحت قسم *Unreleased*.

## قواعد الكشف

أسرع طريقة للمساهمة في الكشف هي حزمة قواعد بصيغة JSON: راجع
[docs/RULE-PACKS.md](docs/RULE-PACKS.md). توجد قواعد C# المدمجة في
`src/Blazma.Analysis/Rules` وتحتاج إلى:

- معرّف (`BLZ-<category letter><number>`)
- اسم بالإنجليزية واسم بالعربية
- وزن
- معرّفات ATT&CK حيثما تنطبق

## المشكلات الأمنية

لا تفتح بلاغًا (issue) عامًا. اتبع [SECURITY.md](SECURITY.md).

</div>
