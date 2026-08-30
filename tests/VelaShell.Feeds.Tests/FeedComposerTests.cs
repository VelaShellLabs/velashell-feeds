using VelaShell.Feeds.Domain;

namespace VelaShell.Feeds.Tests;

/// <summary>
/// 组装规则。这些用例决定了用户实际会看到什么 —— 配额、去重、阈值、过期,
/// 每一条都能单独把 feed 变得不可用,所以逐条钉住。
/// </summary>
[TestClass]
public class FeedComposerTests
{
    private static readonly DateTime Now = new(2026, 9, 1, 12, 0, 0, DateTimeKind.Utc);

    private static FeedEntry Entry(
        string id,
        EntryStatus status = EntryStatus.Published,
        DateTime? published = null,
        DateTime? expires = null,
        string kind = FeedKinds.News) =>
        new()
        {
            Id = id,
            Kind = kind,
            Title = $"条目 {id}",
            Status = status,
            PublishedAt = published ?? Now.AddHours(-1),
            ExpiresAt = expires
        };

    private static CveAdvisory Advisory(
        string cveId,
        string source = CveSources.Nvd,
        double? cvss = 8.0,
        bool exploited = false,
        DateTime? published = null,
        bool suppressed = false) =>
        new()
        {
            Id = $"{source}:{cveId}",
            CveId = cveId,
            Source = source,
            Title = $"{cveId} 标题",
            CvssScore = cvss,
            KnownExploited = exploited,
            PublishedAt = published ?? Now.AddDays(-1),
            IsSuppressed = suppressed
        };

    /// <summary>草稿与归档不进 feed —— 这是"发布"这个动作唯一的意义。</summary>
    [TestMethod]
    public void Compose_OnlyIncludesPublishedEntries()
    {
        var document = FeedComposer.Compose(
            [Entry("live"), Entry("draft", EntryStatus.Draft), Entry("archived", EntryStatus.Archived)],
            [], new(), Now);

        Assert.HasCount(1, document.Items);
        Assert.AreEqual("live", document.Items[0].Id);
    }

    /// <summary>发布时间还没到、或下线时间已过的,都不该出现。</summary>
    [TestMethod]
    public void Compose_RespectsSchedulingWindow()
    {
        var document = FeedComposer.Compose(
            [
                Entry("future", published: Now.AddHours(2)),
                Entry("expired", published: Now.AddDays(-5), expires: Now.AddDays(-1)),
                Entry("live", published: Now.AddHours(-2), expires: Now.AddDays(1))
            ],
            [], new(), Now);

        Assert.HasCount(1, document.Items);
        Assert.AreEqual("live", document.Items[0].Id);
    }

    /// <summary>
    /// **手工条目不与 CVE 抢额度。** 上游某天批量发布时,管理员精心投放的公告
    /// 不该被机器抓来的挤出 feed。
    /// </summary>
    [TestMethod]
    public void Compose_ReservesRoomForManualEntries()
    {
        List<CveAdvisory> flood = [.. Enumerable.Range(0, 200)
            .Select(i => Advisory($"CVE-2026-{i:0000}", published: Now.AddHours(-i)))];
        var options = new FeedCompositionOptions { MaxItems = 20, MaxCveItems = 40 };

        var document = FeedComposer.Compose([Entry("promo"), Entry("news")], flood, options, Now);

        Assert.HasCount(20, document.Items);
        Assert.Contains(item => item.Id == "promo", document.Items, "手工条目必须留在 feed 里。");
        Assert.Contains(item => item.Id == "news", document.Items);
    }

    /// <summary>CVE 有独立配额,不会把整个 feed 占满。</summary>
    [TestMethod]
    public void Compose_CapsCveShare()
    {
        List<CveAdvisory> flood = [.. Enumerable.Range(0, 100)
            .Select(i => Advisory($"CVE-2026-{i:0000}", published: Now.AddHours(-i)))];
        var options = new FeedCompositionOptions { MaxItems = 100, MaxCveItems = 5 };

        var document = FeedComposer.Compose([], flood, options, Now);

        Assert.HasCount(5, document.Items);
    }

    /// <summary>
    /// 在野被利用的不看分数直接放行:CVSS 9.8 而无人利用,远不如 7.5 但正在被打的紧急。
    /// </summary>
    [TestMethod]
    public void Compose_LetsExploitedAdvisoriesThroughRegardlessOfScore()
    {
        var options = new FeedCompositionOptions { MinCvssScore = 9.0 };

        var document = FeedComposer.Compose(
            [],
            [
                Advisory("CVE-2026-0001", CveSources.Kev, cvss: 5.0, exploited: true),
                Advisory("CVE-2026-0002", cvss: 8.0)
            ],
            options, Now);

        Assert.HasCount(1, document.Items);
        Assert.AreEqual($"{CveSources.Kev}:CVE-2026-0001", document.Items[0].Id);
    }

    /// <summary>低于阈值的普通 CVE 被挡掉 —— 不然一天几百条会把用户逼到关掉资讯源。</summary>
    [TestMethod]
    public void Compose_FiltersLowScoreAdvisories()
    {
        var document = FeedComposer.Compose(
            [], [Advisory("CVE-2026-0003", cvss: 4.0)], new() { MinCvssScore = 7.0 }, Now);

        Assert.IsEmpty(document.Items);
    }

    /// <summary>
    /// 同一个 CVE 出现在多个来源时只留一条,且留信号最强的那条 ——
    /// 否则用户会在列表里连着看到两条一模一样的漏洞。
    /// </summary>
    [TestMethod]
    public void Compose_DeduplicatesAcrossSources_KeepingStrongestSignal()
    {
        var document = FeedComposer.Compose(
            [],
            [
                Advisory("CVE-2026-9999", CveSources.Nvd, cvss: 9.8),
                Advisory("CVE-2026-9999", CveSources.Kev, cvss: 7.0, exploited: true)
            ],
            new(), Now);

        Assert.HasCount(1, document.Items);
        Assert.AreEqual($"{CveSources.Kev}:CVE-2026-9999", document.Items[0].Id, "在野被利用的那条信号更强。");
        Assert.AreEqual(FeedSeverities.Critical, document.Items[0].Severity);
    }

    /// <summary>被管理员屏蔽的公告不进 feed。</summary>
    [TestMethod]
    public void Compose_SkipsSuppressedAdvisories()
    {
        var document = FeedComposer.Compose(
            [], [Advisory("CVE-2026-0004", cvss: 9.0, suppressed: true)], new(), Now);

        Assert.IsEmpty(document.Items);
    }

    /// <summary>超过存活期的 CVE 自动退场 —— 一个月前的漏洞已经不是"消息"。</summary>
    [TestMethod]
    public void Compose_DropsStaleAdvisories()
    {
        var options = new FeedCompositionOptions { CveLifetimeDays = 30 };

        var document = FeedComposer.Compose(
            [],
            [
                Advisory("CVE-2026-0005", published: Now.AddDays(-40), exploited: true),
                Advisory("CVE-2026-0006", published: Now.AddDays(-2), exploited: true)
            ],
            options, Now);

        Assert.HasCount(1, document.Items);
        Assert.AreEqual($"{CveSources.Nvd}:CVE-2026-0006", document.Items[0].Id);
    }

    /// <summary>CVE 条目带上过期时间,让客户端自己到点清掉,不必等下一次拉取。</summary>
    [TestMethod]
    public void Compose_GivesAdvisoriesAnExpiry()
    {
        var options = new FeedCompositionOptions { CveLifetimeDays = 30 };
        var published = Now.AddDays(-1);

        var document = FeedComposer.Compose(
            [], [Advisory("CVE-2026-0007", published: published, exploited: true)], options, Now);

        Assert.AreEqual(published.AddDays(30), document.Items[0].ExpiresAt);
    }

    /// <summary>
    /// 非 https 的外链在服务端就被剥掉。客户端那侧同样会拒,但让它发生在管理台能看见的地方,
    /// 好过等用户点不动才发现。
    /// </summary>
    [TestMethod]
    public void Compose_StripsNonHttpsLinks()
    {
        var insecure = Entry("http-link");
        insecure.Url = "http://example.com";
        var secure = Entry("https-link");
        secure.Url = "https://example.com";

        var document = FeedComposer.Compose([insecure, secure], [], new(), Now);

        Assert.IsNull(document.Items.Single(item => item.Id == "http-link").Url);
        Assert.AreEqual("https://example.com", document.Items.Single(item => item.Id == "https-link").Url);
    }

    /// <summary>空的定向列表不下发,免得给客户端塞一堆空数组。</summary>
    [TestMethod]
    public void Compose_OmitsEmptyTargeting()
    {
        var entry = Entry("plain");
        var targeted = Entry("targeted");
        targeted.Targeting.Locales.Add("zh-Hans");

        var document = FeedComposer.Compose([entry, targeted], [], new(), Now);

        Assert.IsNull(document.Items.Single(item => item.Id == "plain").Locales);
        CollectionAssert.AreEqual(new[] { "zh-Hans" }, document.Items.Single(item => item.Id == "targeted").Locales!.ToArray());
    }

    /// <summary>输出按发布时间倒序 —— 拿 curl 直接看这个 feed 的人不会比客户端少。</summary>
    [TestMethod]
    public void Compose_SortsNewestFirst()
    {
        var document = FeedComposer.Compose(
            [
                Entry("old", published: Now.AddDays(-3)),
                Entry("new", published: Now.AddMinutes(-5)),
                Entry("mid", published: Now.AddDays(-1))
            ],
            [], new(), Now);

        CollectionAssert.AreEqual(new[] { "new", "mid", "old" }, document.Items.Select(item => item.Id).ToArray());
    }

    /// <summary>严重程度的映射:在野被利用 → critical,高分 → warning。</summary>
    [TestMethod]
    public void SeverityFor_MapsExploitationAndScore()
    {
        Assert.AreEqual(FeedSeverities.Critical, FeedComposer.SeverityFor(Advisory("a", cvss: 5.0, exploited: true)));
        Assert.AreEqual(FeedSeverities.Critical, FeedComposer.SeverityFor(Advisory("b", cvss: 9.5)));
        Assert.AreEqual(FeedSeverities.Warning, FeedComposer.SeverityFor(Advisory("c", cvss: 7.5)));
        Assert.AreEqual(FeedSeverities.Info, FeedComposer.SeverityFor(Advisory("d", cvss: 3.0)));
    }
}
