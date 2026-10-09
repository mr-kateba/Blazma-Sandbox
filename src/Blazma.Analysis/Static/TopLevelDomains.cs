namespace Blazma.Analysis.Static;

/// <summary>
/// The top-level domains Blazma accepts when it decides whether text is a host name. Without
/// this check, file names ("setup.exe") and code ("System.Net") read as domains. The list is the
/// country codes plus the generic domains seen in practice, not the full IANA root zone.
/// </summary>
internal static class TopLevelDomains
{
    private static readonly HashSet<string> CountryCodes = new(
        """
        ac ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bm bn bo br bs bt bw by bz
        ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg er es et eu fi fj fk fm
        fo fr ga gb gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu id ie il im in io iq ir is
        it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mg mh mk ml mm
        mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr
        ps pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sk sl sm sn so sr ss st su sv sx sy sz tc td tf tg th
        tj tk tl tm tn to tr tt tv tw tz ua ug uk us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw
        """.Split((char[])[' ', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries),
        StringComparer.OrdinalIgnoreCase);

    /// <summary>Generic domains that are rarely an ordinary word or file extension.</summary>
    private static readonly HashSet<string> DistinctiveGeneric = new(
        """
        com net org info biz edu gov mil int mobi asia tel travel jobs coop aero museum xxx
        xyz top online site club shop store website space icu buzz cyou cfd sbs lol monster rest quest bond
        tech cloud fun vip ltd llc inc agency digital email host press services support solutions systems
        company center studio design hair beauty autos boats homes yachts skin makeup mom pics baby cam surf
        casino poker finance capital insurance kim country gdn webcam accountant cricket racing science faith
        xin wang ink pro
        """.Split((char[])[' ', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries),
        StringComparer.OrdinalIgnoreCase);

    /// <summary>Real generic domains that are also everyday words in code ("event.date", "user.name").</summary>
    private static readonly HashSet<string> WordLikeGeneric = new(
        """
        app dev page link click download win bid loan work party review stream date trade men game games
        money zone run plus one best group media network news blog life world today live name bank bet gold
        zip mov cat
        """.Split((char[])[' ', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries),
        StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Country codes that are also common file extensions or member names ("install.sh",
    /// "Makefile.am", "user.id"). They count inside a URL or an e-mail address, not on their own.
    /// </summary>
    private static readonly HashSet<string> AmbiguousCountryCodes = new(
        """
        py sh pl pm md rs cc ps so mo ai ws gs ml mk am ac in id to is it as at be do me no us bz tf
        """.Split((char[])[' ', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries),
        StringComparer.OrdinalIgnoreCase);

    /// <summary>Whether <paramref name="tld"/> is a real top-level domain (any context).</summary>
    public static bool IsKnown(string tld) =>
        CountryCodes.Contains(tld) || DistinctiveGeneric.Contains(tld) || WordLikeGeneric.Contains(tld);

    /// <summary>
    /// Whether a bare name ending in <paramref name="tld"/>, seen without "http://" or "@" around
    /// it, is likely a host name rather than a file name or a code expression.
    /// </summary>
    public static bool IsDistinctive(string tld) =>
        (CountryCodes.Contains(tld) && !AmbiguousCountryCodes.Contains(tld)) || DistinctiveGeneric.Contains(tld);

    /// <summary>The last label of a host name, without a trailing dot.</summary>
    public static string Of(string host)
    {
        var h = host.TrimEnd('.');
        var dot = h.LastIndexOf('.');
        return dot < 0 ? h : h[(dot + 1)..];
    }
}
