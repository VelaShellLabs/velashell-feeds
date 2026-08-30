namespace VelaShell.Feeds.Domain;

/// <summary>组装 feed 时的取舍参数。</summary>
public sealed class FeedCompositionOptions
{
    /// <summary>
    /// 下发条数上限。客户端单次最多接受 100 条,超出会被它截断 ——
    /// 与其让客户端随机截掉尾巴,不如服务端按重要性主动取舍。
    /// </summary>
    public int MaxItems { get; set; } = 100;

    /// <summary>
    /// CVE 条目的最大占用条数。剩下的额度留给手工公告与广告。
    /// <para>
    /// 有配额是因为 CVE 是机器抓的、量不可控:不设限的话,某天上游批量发布,
    /// 就会把管理员精心投放的公告整个挤出 feed。
    /// </para>
    /// </summary>
    public int MaxCveItems { get; set; } = 40;

    /// <summary>
    /// CVE 条目在 feed 中的存活天数。过了就自动消失 ——
    /// 一个月前的漏洞公告已经不是"消息",留着只会占位。
    /// </summary>
    public int CveLifetimeDays { get; set; } = 30;

    /// <summary>只下发达到该 CVSS 分数的 CVE(在野被利用的不受此限)。</summary>
    public double MinCvssScore { get; set; } = 7.0;
}

/// <summary>
/// 把库里的手工条目与采集到的 CVE 组装成下发文档。
/// <para>
/// 纯函数,不碰数据库也不碰时钟(<c>utcNow</c> 由调用方传入)—— 组装规则是这个服务里
/// 最需要说清楚的部分,它必须能被直接测出来,而不是只能靠起一整套环境去观察。
/// </para>
/// </summary>
public static class FeedComposer
{
    /// <summary>按重要性与配额组装下发文档。</summary>
    public static FeedDocument Compose(
        IEnumerable<FeedEntry> entries,
        IEnumerable<CveAdvisory> advisories,
        FeedCompositionOptions options,
        DateTime utcNow)
    {
        ArgumentNullException.ThrowIfNull(entries);
        ArgumentNullException.ThrowIfNull(advisories);
        ArgumentNullException.ThrowIfNull(options);

        // 手工条目先进,且不与 CVE 抢额度:管理员明确要投的东西,不该被机器抓来的挤掉。
        List<FeedItem> manual =
        [
            .. entries.Where(entry => entry.IsLive(utcNow))
                      .OrderByDescending(entry => entry.PublishedAt)
                      .Take(options.MaxItems)
                      .Select(ToItem)
        ];
        int cveBudget = Math.Min(options.MaxCveItems, Math.Max(0, options.MaxItems - manual.Count));
        List<FeedItem> cve =
        [
            .. SelectAdvisories(advisories, options, utcNow)
               .Take(cveBudget)
               .Select(advisory => ToItem(advisory, options))
        ];
        return new()
        {
            // 客户端自己会按 publishedAt 倒序显示,但下发时也排好:
            // 人拿 curl 看这个 feed 的次数,不会比客户端少。
            Items = [.. manual.Concat(cve).OrderByDescending(item => item.PublishedAt)]
        };
    }

    /// <summary>
    /// 挑选要下发的漏洞公告:去重、过滤、排序。
    /// </summary>
    private static IEnumerable<CveAdvisory> SelectAdvisories(
        IEnumerable<CveAdvisory> advisories, FeedCompositionOptions options, DateTime utcNow)
    {
        DateTime cutoff = utcNow.AddDays(-options.CveLifetimeDays);
        return advisories
               .Where(advisory => !advisory.IsSuppressed)
               .Where(advisory => advisory.PublishedAt > cutoff)
               // 在野被利用的一律放行,不看分数:CVSS 9.8 而无人利用,远不如 7.5 但正在被打的紧急。
               .Where(advisory => advisory.KnownExploited || (advisory.CvssScore ?? 0) >= options.MinCvssScore)
               // 同一个 CVE 可能同时出现在多个来源。按编号去重,留信号最强的那条:
               // 先看是否在野被利用,再看分数 —— 否则用户会在列表里看到两条一模一样的漏洞。
               .GroupBy(advisory => advisory.CveId, StringComparer.OrdinalIgnoreCase)
               .Select(group => group.OrderByDescending(advisory => advisory.KnownExploited)
                                     .ThenByDescending(advisory => advisory.CvssScore ?? 0)
                                     .First())
               .OrderByDescending(advisory => advisory.KnownExploited)
               .ThenByDescending(advisory => advisory.PublishedAt);
    }

    private static FeedItem ToItem(FeedEntry entry) =>
        new()
        {
            Id = entry.Id,
            Kind = entry.Kind,
            Severity = entry.Severity,
            Title = entry.Title,
            Body = NullIfBlank(entry.Body),
            PublishedAt = entry.PublishedAt,
            ExpiresAt = entry.ExpiresAt,
            LinkLabel = NullIfBlank(entry.LinkLabel),
            Url = HttpsOrNull(entry.Url),
            CommandId = NullIfBlank(entry.CommandId),
            Locales = entry.Targeting.Locales.Count > 0 ? [.. entry.Targeting.Locales] : null,
            Platforms = entry.Targeting.Platforms.Count > 0 ? [.. entry.Targeting.Platforms] : null,
            MinVersion = NullIfBlank(entry.Targeting.MinVersion),
            MaxVersion = NullIfBlank(entry.Targeting.MaxVersion)
        };

    private static FeedItem ToItem(CveAdvisory advisory, FeedCompositionOptions options) =>
        new()
        {
            // id 里带来源:同一个 CVE 从 KEV 升级过来时是另一条 id,会重新亮起未读 ——
            // 「这个漏洞现在开始被利用了」确实值得再提醒一次。
            Id = advisory.Id,
            Kind = FeedKinds.Security,
            Severity = SeverityFor(advisory),
            Title = advisory.Title,
            Body = NullIfBlank(advisory.Summary),
            PublishedAt = advisory.PublishedAt,
            // 让客户端自己到点清掉,不必等下一次拉取。
            ExpiresAt = advisory.PublishedAt.AddDays(options.CveLifetimeDays),
            LinkLabel = null,
            Url = HttpsOrNull(advisory.Url)
        };

    /// <summary>
    /// 严重程度:在野被利用直接算 critical —— 它意味着"现在就有人在打这个洞",
    /// 比任何分数都更该让人立刻看见。
    /// </summary>
    public static string SeverityFor(CveAdvisory advisory) =>
        advisory.KnownExploited || advisory.CvssScore >= 9.0
            ? FeedSeverities.Critical
            : advisory.CvssScore >= 7.0
                ? FeedSeverities.Warning
                : FeedSeverities.Info;

    private static string? NullIfBlank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    /// <summary>
    /// 只放行 https。客户端那侧同样会拒非 https 的链接,这里先拦一道:
    /// 让"链接被丢掉"发生在管理台能看见的地方,而不是等用户点不动才发现。
    /// </summary>
    private static string? HttpsOrNull(string? url) =>
        NullIfBlank(url) is { } trimmed &&
        Uri.TryCreate(trimmed, UriKind.Absolute, out Uri? parsed) &&
        parsed.Scheme == Uri.UriSchemeHttps
            ? trimmed
            : null;
}
