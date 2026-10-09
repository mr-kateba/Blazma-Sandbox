# التحليل في جهازك الافتراضي الخاص (VirtualBox أو Hyper-V)

**العربية** · [English](VIRTUAL-MACHINES.en.md)

<div dir="rtl">

إلى جانب Windows Sandbox، يستطيع Blazma تشغيل العينات في جهاز افتراضي بنظام Windows تجهّزه مرة
واحدة. ويتولى إدارته مزوّدان:

| المزوّد | المعرّف | يعمل على | يتواصل مع الضيف عبر |
|---|---|---|---|
| VirtualBox | `virtualbox` | أي إصدار من Windows، **بما في ذلك Home** | `VBoxManage` وGuest Additions |
| Hyper-V | `hyperv` | Windows 10/11 Pro وEnterprise وEducation | PowerShell Direct وخدمات التكامل (integration services) |

لماذا تستخدم جهازًا افتراضيًا بدلًا من Windows Sandbox:

- لا يتوفر Windows Sandbox في **Windows Home**؛ أما VirtualBox فيعمل عليه.
- الجهاز الافتراضي الكامل الذي يبدو مستخدَمًا فعلًا **أصعب على العينة في التعرّف عليه** من
  Windows Sandbox جديد (الذي يبدو دائمًا بالشكل نفسه: اسم المستخدم نفسه، بلا سجل استخدام، وقرص صغير جدًا).
- أنت من يختار إصدار Windows والبرامج المثبّتة واللغة والعتاد.

يُستخدم وكيل المراقبة نفسه وبروتوكول الملفات نفسه، لذلك تبدو التقارير متماثلة.

> **الحالة.** كلا المزوّدين مغطّى باختبارات آلية على مضيفات VirtualBox وHyper-V محاكاة، لكنهما لم
> يُجرَّبا بعد من البداية إلى النهاية على برامج المحاكاة الافتراضية (hypervisors) الحقيقية. تعامل مع
> التشغيلات الأولى على أنها تجربة، ونرجو أن تبلغنا بما تجده.

## ما يفعله Blazma في كل تحليل

1. يتحقق من أن الجهاز الافتراضي موجود، وأن اللقطة (snapshot) أو نقطة الحفظ (checkpoint) موجودة، وأن
   الجهاز الافتراضي **ليس قيد التشغيل** (لا يلمس Blazma أبدًا جهازًا افتراضيًا تستخدمه أنت).
2. **يستعيد اللقطة/نقطة الحفظ النظيفة.**
3. يتحقق من محوّلات الشبكة **في الحالة المستعادة**، ويرفض المتابعة إذا كان أحدها موصولًا، إلا إذا كان
   الوصول إلى الشبكة مفعّلًا لهذا التحليل (انظر [الشبكة](#الشبكة)).
4. يشغّل الجهاز الافتراضي وينتظر حتى تستجيب أدوات الضيف بحساب الضيف الخاص بك.
5. ينشئ `<guest working folder>\<analysis id>\in` و`\out` داخل الضيف، وينسخ الوكيل وإعداداته إليه،
   ويشغّل الوكيل **بصلاحيات مرتفعة** في الخلفية.
6. ينتظر رسالة الترحيب (hello) من الوكيل، ثم **يحذف مفتاح القناة** من نسخة الإعدادات داخل الضيف، وينسخ
   العينة إليه، ثم يرسل إشارة البدء.
7. كل ثانيتين تقريبًا ينسخ الملفات الجديدة من مجلد `out` في الضيف إلى المضيف، ويقرؤها بالقارئ الصارم
   نفسه الذي يتحقق من التواقيع والمستخدَم مع Windows Sandbox.
8. في النهاية — بعد النجاح أو الفشل **أو** الإلغاء — **يطفئ الجهاز الافتراضي ويستعيد اللقطة مرة
   أخرى**، ثم يحذف مجلد العمل على المضيف.

## تجهيز الضيف (لكلا المزوّدين)

استخدم جهازًا افتراضيًا مخصّصًا للتحليل فقط. لا ينبغي أن يكون فيه شيء يهمّك.

1. **ثبّت Windows 10 أو 11** (64 بت). اجعله يبدو مستخدَمًا إن أردت: بعض المستندات، وسجل تصفح،
   وبعض البرامج الشائعة، واسم جهاز واسم مستخدم واقعيان.
2. **ثبّت أدوات الضيف.**
   - VirtualBox: *Devices → Insert Guest Additions CD image…*، شغّل المثبّت، ثم أعد التشغيل.
   - Hyper-V: تأتي خدمات التكامل مع Windows 10/11؛ أبقِ *Heartbeat* مفعّلًا في إعدادات
     *Integration Services* للجهاز الافتراضي. ولا يحتاج PowerShell Direct إلى أي إعداد إضافي.
3. **أنشئ حساب المسؤول الذي يسجّل Blazma الدخول به.** يستخدم الوكيل تتبّع النواة (ETW)، وهو لا يعمل
   إلا برمز مسؤول كامل (full administrator token). اختر أحد الخيارين:
   - **حساب Administrator المدمج (موصى به).** لا يخضع لتصفية UAC. في موجّه أوامر بصلاحيات مرتفعة
     داخل الضيف:
</div>

     ```
     net user Administrator <password> /active:yes
     ```

<div dir="rtl">
     ثم استخدم `Administrator` (أو `.\Administrator`) بوصفه مستخدم الضيف في Blazma.
   - **حساب مسؤول محلي آخر**، مع رفع قيد UAC الخاص بهذا المسار *في جهاز التحليل الافتراضي فقط*:
     - Hyper-V: اضبط `LocalAccountTokenFilterPolicy` لكي تحصل جلسات PowerShell Direct على الرمز
       الكامل (أما الوكيل نفسه فتشغّله مهمة مجدولة بخيار *highest privileges*):
</div>

       ```
       reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
       ```

<div dir="rtl">
     - VirtualBox: البرامج التي تشغّلها Guest Additions تحصل على رمز مصفّى لمثل هذه الحسابات، لذلك
       أوقف UAC (`EnableLUA` = 0، ثم أعد التشغيل). وهذا يغيّر أيضًا سلوك العينات؛ فالأفضل استخدام
       حساب Administrator المدمج.
</div>

       ```
       reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f
       ```

<div dir="rtl">
   يحتاج الحساب إلى كلمة مرور (يرفض Windows عمليات تسجيل الدخول من النوع البعيد بكلمة مرور فارغة).
   وإذا بدأ الوكيل دون صلاحيات المسؤول، يوقف Blazma التحليل ويُعلمك بذلك.
4. **اجعل هذا الحساب يسجّل الدخول تلقائيًا** (مثلًا باستخدام أداة *Autologon* من Sysinternals)، لكي
   يكون هناك سطح مكتب: فلقطات الشاشة ومحاكاة المستخدم والعينات التي لها نافذة تحتاج إليه، وفي Hyper-V
   تعمل مهمة الوكيل في تلك الجلسة التفاعلية.
5. **اختياري لكنه مفيد:** أوقف الحماية في الوقت الحقيقي والحماية من العبث في Microsoft Defender،
   وWindows Update، وغيرها من الأعمال الخلفية الكثيرة الضجيج داخل الضيف، حتى لا تُحذف العينات قبل
   أن تعمل ويبقى الخط الزمني سهل القراءة.
6. **افصل الشبكة** (انظر أدناه).
7. **أوقف تشغيل الجهاز بشكل سليم أو اتركه يعمل على سطح المكتب، ثم التقط اللقطة/نقطة الحفظ** وسمّها
   (`clean` افتراضيًا). أفضل لقطة هي لقطة الجهاز الافتراضي *وهو يعمل والحساب مسجّل الدخول*: إذ تستأنف
   الاستعادة عند سطح المكتب خلال ثوانٍ بدلًا من الإقلاع من البداية.

ينشئ Blazma مجلد العمل الخاص به (`C:\Blazma` افتراضيًا) بنفسه؛ لا تضمّنه في اللقطة.

## الشبكة

افتراضيًا يجب ألا يكون في الجهاز الافتراضي **أي محوّل شبكة موصول**، في الحالة المخزّنة في اللقطة.
يتحقق Blazma من ذلك بعد استعادة اللقطة وقبل تشغيل الجهاز الافتراضي.

- VirtualBox: اضبط كل محوّل على **Not attached** (أو ألغِ تحديد *Enable Network Adapter*). وكلا
  الخيارين يُعدّ فصلًا.
- Hyper-V: اضبط المحوّل الافتراضي (virtual switch) لكل محوّل شبكة على **Not connected**.

التحليل الذي يبدأ مع **تفعيل الوصول إلى الشبكة** يقبل محوّلًا موصولًا. وإذا كنت تشغّل جهازك الافتراضي
عمدًا على شبكة معزولة (مثلًا شبكة داخلية فيها خدمة إنترنت مزيّفة)، فأوقف الخيار
*رفض محوّل شبكة موصول* (*Refuse a connected network adapter*) في الإعدادات؛ وعندها يقبل Blazma المحوّلات الموصولة في
كل تحليل — فتأكد من أن هذا ما تريده.

الشبكة المحاكاة (الملف التعريفي الافتراضي) لا تحتاج إلى أي محوّل: فالوكيل يجيب من داخل الضيف.

## VirtualBox

1. ثبّت VirtualBox (أي إصدار حديث من 7.x).
2. جهّز الضيف كما سبق. ودوّن اسم الجهاز الافتراضي تمامًا كما يظهر في VirtualBox Manager.
3. التقط اللقطة: *Machine → Take Snapshot…*، وسمّها `clean`.
4. في Blazma افتح **الإعدادات ← الأجهزة الافتراضية** (Settings → Virtual machines): اختر VirtualBox،
   وأدخل اسم الجهاز الافتراضي واسم اللقطة ومستخدم الضيف وكلمة المرور، واختر *Window* (لمشاهدة
   التشغيل) أو *Headless* (التشغيل بدون نافذة). التحليلات التفاعلية تفتح نافذة دائمًا. إذا لم يكن
   VirtualBox مثبّتًا في `C:\Program Files\Oracle\VirtualBox`، فاضبط المسار إلى `VBoxManage.exe`.

الأوامر التي يشغّلها Blazma (كل قيمة وسيط منفصل؛ وبعد البحث الأول يُشار إلى الجهاز الافتراضي واللقطة
بمعرّف UUID؛ وكلمة المرور موجودة في ملف لا يقرؤه أحد غيرك، ويُحذف بعد كل أمر):

</div>

```
VBoxManage list vms
VBoxManage snapshot <vm-uuid> list --machinereadable
VBoxManage showvminfo <vm-uuid> --machinereadable
VBoxManage snapshot <vm-uuid> restore <snapshot-uuid>
VBoxManage startvm <vm-uuid> --type gui|headless
VBoxManage guestproperty get <vm-uuid> /VirtualBox/GuestAdd/Version
VBoxManage guestcontrol <vm-uuid> run    --username=<user> --passwordfile=<file> --exe=<guest powershell> --timeout=60000 --wait-stdout -- <guest powershell> -NoProfile -NonInteractive -Command "exit 0"
VBoxManage guestcontrol <vm-uuid> mkdir  --username=<user> --passwordfile=<file> --parents <in\agent> <in\sample> <out>
VBoxManage guestcontrol <vm-uuid> copyto --username=<user> --passwordfile=<file> --target-directory=<guest folder> <host files…>
VBoxManage guestcontrol <vm-uuid> rm     --username=<user> --passwordfile=<file> --force <guest file>
VBoxManage guestcontrol <vm-uuid> start  --username=<user> --passwordfile=<file> --exe=<agent> -- <agent> <in> <out>
VBoxManage guestcontrol <vm-uuid> run    --username=<user> --passwordfile=<file> --exe=<guest powershell> --timeout=60000 --wait-stdout -- <guest powershell> -NoProfile -NonInteractive -EncodedCommand <list out folder>
VBoxManage guestcontrol <vm-uuid> copyfrom --username=<user> --passwordfile=<file> --target-directory=<host incoming> <guest files…>
VBoxManage controlvm <vm-uuid> poweroff
```

<div dir="rtl">

## Hyper-V

1. فعّل **Hyper-V** من ميزات Windows (Windows Features)، بما في ذلك *Hyper-V Module for Windows
   PowerShell*، ثم أعد التشغيل.
2. لا يعمل Blazma بصلاحيات المسؤول. **أضف حساب Windows الخاص بك إلى المجموعة المحلية
   "Hyper-V Administrators"**، ثم سجّل الخروج وسجّل الدخول مرة أخرى:
</div>

   ```
   net localgroup "Hyper-V Administrators" <your user> /add
   ```

<div dir="rtl">
3. جهّز الضيف كما سبق. اضبط نوع نقطة الحفظ على **Standard** (من *Settings → Checkpoints* الخاصة
   بالجهاز الافتراضي)، حتى تتضمن نقطة الحفظ الحالة التي يكون فيها الجهاز قيد التشغيل والحساب مسجّل
   الدخول؛ ثم اختر *Checkpoint* وأعد تسميتها إلى `clean`.
4. في Blazma افتح **الإعدادات ← الأجهزة الافتراضية** (Settings → Virtual machines): اختر Hyper-V،
   وأدخل اسم الجهاز الافتراضي واسم نقطة الحفظ ومستخدم الضيف وكلمة المرور. لمشاهدة التشغيل، افتح
   الجهاز الافتراضي في Hyper-V Manager (*Connect…*).

يشغّل Blazma ‏Windows PowerShell بالشكل `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass
-Command -` ويرسل كل سكربت عبر الإدخال القياسي، فلا تظهر كلمة مرور الضيف أبدًا في سطر أوامر. وكل قيمة
أدخلتها تُدرَج بوصفها قيمة PowerShell حرفية بين علامتي اقتباس مفردتين. وتستخدم السكربتات:
`Get-VM` و`Get-VMCheckpoint` و`Get-VMNetworkAdapter` و`Restore-VMCheckpoint` و`Start-VM` (ثم الانتظار
حتى تصبح حالة *Heartbeat* سليمة OK)، و`New-PSSession -VMId … -Credential …` (PowerShell Direct)،
و`Copy-Item -ToSession` / `-FromSession`، و`Register-ScheduledTask` + `Start-ScheduledTask` لتشغيل الوكيل
(تسجيل دخول تفاعلي لحساب الضيف، مع *highest privileges*: لأن العملية التي تبدأ داخل جلسة PowerShell
Direct تتوقف عند إغلاق الجلسة)، و`Stop-VM -TurnOff -Force` يليه `Restore-VMCheckpoint` في النهاية.

## ملاحظات أمنية وقيود

- **العزل هو ما ضبطته أنت.** عزل Windows Sandbox تحدده Microsoft ولا يتغير؛ أما الجهاز الافتراضي
  فعزله بقدر إعداداته فقط. أبقِ المجلدات المشتركة ومشاركة الحافظة والسحب والإفلات وتمرير USB
  معطّلة في جهاز التحليل الافتراضي. لا يحتاج Blazma إلى أي منها.
- **مجلد `in` في الضيف ليس للقراءة فقط.** في Windows Sandbox يربطه المضيف للقراءة فقط؛ أما في الجهاز
  الافتراضي فهو مجلد عادي تستطيع عينة بصلاحيات مرتفعة تغييره (مثلًا تزوير `control.json` لإنهاء
  تشغيلها مبكرًا). ومع ذلك يظل كل ما *يعود* إلى المضيف خاضعًا للتحقق: مخرجات موقّعة، وأسماء صارمة،
  وحصص، وبلا روابط، ولا يُنفَّذ شيء منه.
- **مفتاح القناة** يُحذف من ملف `session.json` في الضيف بعد رسالة الترحيب من الوكيل، كما في
  Windows Sandbox، لكن عينة بصلاحيات مرتفعة قد تستعيده من ذاكرة الوكيل أو من المساحة الحرة في القرص.
  وعندها لا يمكن اكتشاف العبث؛ لكن استعادة اللقطة تمحو كل شيء بعد ذلك على أي حال.
- **البصمة (Fingerprinting).** اكتشاف الجهاز الافتراضي أصعب من اكتشاف Windows Sandbox، لكنه ليس
  مستحيلًا: فأدوات الضيف (VirtualBox Guest Additions، وخدمات التكامل في Hyper-V)، وأسماء العتاد
  الافتراضي، وعملية الوكيل ومجلده، و(في VirtualBox) عملية PowerShell القصيرة التي تسرد مجلد المخرجات
  كل بضع ثوانٍ، كلها مرئية لعينة حذرة. والتقرير الهادئ ليس دليلًا على الأمان.
- **التأخير.** تُنسخ المخرجات كل بضع ثوانٍ (وكل عملية نسخ تفتح جلسة في الضيف)، لذلك يتأخر العرض
  المباشر قليلًا مقارنةً بـ Windows Sandbox. ويُحكم على نبضات الحياة (heartbeats) بحسب وقت *رؤية*
  المضيف لنبضة جديدة.
- **إذا فشلت الاستعادة النهائية** (مثلًا لأن VirtualBox مشغول)، يسجّل Blazma ذلك وقد يبقى الجهاز
  الافتراضي على الحال التي تركته عليها العينة. ومع ذلك يستعيد التحليل التالي اللقطة أولًا في كل الأحوال؛
  ويمكنك أيضًا استعادتها يدويًا.

## استكشاف الأخطاء وإصلاحها

| الرسالة | ما يجب فعله |
|---|---|
| *The virtual machine is already running* | أغلق الجهاز الافتراضي أو أطفئه. يستعيد Blazma اللقطة ويشغّل الجهاز بنفسه. |
| *…has a connected network adapter* | افصل المحوّلات والتقط اللقطة من جديد، أو فعّل الوصول إلى الشبكة لهذا التحليل. |
| *did not become ready in time* (VirtualBox) | ثبّت Guest Additions في اللقطة؛ وتحقق من اسم مستخدم الضيف وكلمة مروره. |
| *could not open a PowerShell Direct session* (Hyper-V) | تحقق من بيانات اعتماد الضيف؛ يجب أن يكون الضيف Windows 10/11 وأن يكون قد اكتمل تشغيله. |
| *The agent is not running as an administrator* | استخدم حساب Administrator المدمج، أو راجع الخطوة 3 من *تجهيز الضيف*. |
| *The agent task did not start* (Hyper-V) | يجب أن يكون حساب الضيف مسجّل الدخول (تسجيل دخول تلقائي، أو نقطة حفظ التُقطت عند سطح المكتب). |
| فشل *Permission to manage virtual machines* (صلاحية إدارة الأجهزة الافتراضية) | انضم إلى مجموعة *Hyper-V Administrators*، ثم سجّل الخروج وسجّل الدخول. |

</div>
