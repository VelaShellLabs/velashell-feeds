namespace VelaShell.Feeds.Domain;

/// <summary>条目的发布状态。</summary>
public enum EntryStatus
{
    /// <summary>草稿:只有管理台看得见,不进 feed。</summary>
    Draft,

    /// <summary>已发布:进 feed(仍受投放时间窗约束)。</summary>
    Published,

    /// <summary>已归档:手工下线,不进 feed,但记录留着备查。</summary>
    Archived
}

/// <summary>
/// 定向条件。三项都是「缺省 = 不限」,且**过滤发生在客户端**:
/// 服务端把全量发下去,客户端按自己的语言/平台/版本筛。
/// <para>
/// 这不是偷懒,是有意的:请求里没有版本号、没有平台、没有语言、没有任何设备标识 ——
/// 一个终端工具不该把「谁在用、什么版本、什么系统」持续汇报给服务器。
/// 代价是服务端做不了用户级个性化,只能做群体级定向。
/// </para>
/// </summary>
public sealed class Targeting
{
    /// <summary>界面语言(如 <c>zh-Hans</c>);空 = 不限。</summary>
    public List<string> Locales { get; set; } = [];

    /// <summary>运行平台 RID(如 <c>win-x64</c>);空 = 不限。</summary>
    public List<string> Platforms { get; set; } = [];

    /// <summary>最低版本(含);空 = 不限。</summary>
    public string? MinVersion { get; set; }

    /// <summary>最高版本(含);空 = 不限。</summary>
    public string? MaxVersion { get; set; }

    /// <summary>是否什么条件都没设。</summary>
    public bool IsUnrestricted =>
        Locales.Count == 0 && Platforms.Count == 0 &&
        string.IsNullOrWhiteSpace(MinVersion) && string.IsNullOrWhiteSpace(MaxVersion);
}

/// <summary>
/// 管理员手工创建的一条 feed 内容 —— 产品公告、运营推广都走它。
/// 采集来的 CVE 不在这里(见 <see cref="CveAdvisory" />):那些有自己的来源与生命周期,
/// 混在一张表里会让「哪些是人写的、哪些是机器抓的」变得说不清。
/// </summary>
public sealed class FeedEntry
{
    /// <summary>文档主键,同时就是下发给客户端的 <c>id</c>。</summary>
    public required string Id { get; set; }

    /// <summary>种类:<see cref="FeedKinds" /> 之一(这里通常是 news 或 promotion)。</summary>
    public string Kind { get; set; } = FeedKinds.News;

    /// <summary>严重程度。</summary>
    public string Severity { get; set; } = FeedSeverities.Info;

    /// <summary>标题。</summary>
    public required string Title { get; set; }

    /// <summary>正文。</summary>
    public string? Body { get; set; }

    /// <summary>动作文案。</summary>
    public string? LinkLabel { get; set; }

    /// <summary>外链(必须 https)。</summary>
    public string? Url { get; set; }

    /// <summary>站内命令 id,优先于外链。</summary>
    public string? CommandId { get; set; }

    /// <summary>发布时间(UTC),客户端按它排序。</summary>
    public DateTime PublishedAt { get; set; } = DateTime.UtcNow;

    /// <summary>下线时间(UTC);到点后客户端自动不再展示。</summary>
    public DateTime? ExpiresAt { get; set; }

    /// <summary>定向条件。</summary>
    public Targeting Targeting { get; set; } = new();

    /// <summary>发布状态。</summary>
    public EntryStatus Status { get; set; } = EntryStatus.Draft;

    /// <summary>创建者的身份主体(<c>sub</c>)。</summary>
    public string? CreatedBy { get; set; }

    /// <summary>创建时间(UTC)。</summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>最后修改时间(UTC)。</summary>
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// 此刻是否应出现在 feed 里:已发布、已到发布时间、且未过期。
    /// </summary>
    public bool IsLive(DateTime utcNow) =>
        Status == EntryStatus.Published &&
        PublishedAt <= utcNow &&
        (ExpiresAt is null || ExpiresAt > utcNow);
}

/// <summary>一条采集来的漏洞公告。</summary>
public sealed class CveAdvisory
{
    /// <summary>文档主键:<c>{来源}:{CVE 编号}</c>,天然去重。</summary>
    public required string Id { get; set; }

    /// <summary>CVE 编号(如 <c>CVE-2026-1234</c>)。</summary>
    public required string CveId { get; set; }

    /// <summary>来源标识(<see cref="CveSources" />)。</summary>
    public required string Source { get; set; }

    /// <summary>标题(通常是「组件 + 一句话」)。</summary>
    public required string Title { get; set; }

    /// <summary>摘要。</summary>
    public string? Summary { get; set; }

    /// <summary>CVSS v3 基础分;来源没给时为 null。</summary>
    public double? CvssScore { get; set; }

    /// <summary>
    /// 是否**已知在野被利用**(CISA KEV 收录)。这是最强的信号:
    /// 一个 CVSS 9.8 但无人利用的漏洞,远不如一个 7.5 但正在被打的紧急。
    /// </summary>
    public bool KnownExploited { get; set; }

    /// <summary>受影响的产品/组件关键词,用于人工检索与规则匹配。</summary>
    public List<string> Products { get; set; } = [];

    /// <summary>上游公布时间(UTC)。</summary>
    public DateTime PublishedAt { get; set; }

    /// <summary>详情链接(必须 https)。</summary>
    public string? Url { get; set; }

    /// <summary>本服务抓到它的时间(UTC)。</summary>
    public DateTime FetchedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// 管理员手工屏蔽:采集器照抓照存,但不进 feed。
    /// 用于挡掉与用户无关的噪音,而不是把它从库里删掉 —— 删了下次采集又会回来。
    /// </summary>
    public bool IsSuppressed { get; set; }

    /// <summary>屏蔽原因(留痕)。</summary>
    public string? SuppressedReason { get; set; }
}

/// <summary>CVE 来源标识。</summary>
public static class CveSources
{
    /// <summary>CISA 已知被利用漏洞目录(Known Exploited Vulnerabilities)。</summary>
    public const string Kev = "kev";

    /// <summary>NIST 国家漏洞库(National Vulnerability Database)。</summary>
    public const string Nvd = "nvd";
}
