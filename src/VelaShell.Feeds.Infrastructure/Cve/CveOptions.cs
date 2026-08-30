namespace VelaShell.Feeds.Infrastructure.Cve;

/// <summary>
/// 漏洞采集的配置。
/// <para>
/// <b>选源的原则是信号质量,不是覆盖率。</b> NVD 一天新增几百条 CVE,全量推给一个终端工具的
/// 用户,结果只有一个:他第二天就把资讯源关了。所以默认只收两类 ——
/// </para>
/// <list type="number">
///   <item>
///     <b>CISA KEV</b>:已知**在野被利用**的漏洞目录。总量千余条、每次新增个位数,
///     且每一条都意味着"现在就有人在打这个洞"。无需 API key,一个 JSON 直接下载。
///   </item>
///   <item>
///     <b>NVD</b>:按**关注的组件关键词** + CVSS 阈值过滤。运维关心的是 OpenSSH、sudo、
///     OpenSSL 这些天天在用的东西,不是某个 WordPress 插件的漏洞。
///   </item>
/// </list>
/// </summary>
public sealed class CveOptions
{
    /// <summary>配置节名。</summary>
    public const string SectionName = "Cve";

    /// <summary>是否启用采集。关掉后 feed 里只剩手工条目。</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>两次采集之间的间隔(小时)。上游更新频率以天计,拉太勤只是浪费。</summary>
    public int IntervalHours { get; set; } = 6;

    /// <summary>CISA KEV 目录的 JSON 地址。上游改版时改这里。</summary>
    public string KevUrl { get; set; } = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

    /// <summary>是否采集 CISA KEV。</summary>
    public bool KevEnabled { get; set; } = true;

    /// <summary>NVD 2.0 API 地址。</summary>
    public string NvdUrl { get; set; } = "https://services.nvd.nist.gov/rest/json/cves/2.0";

    /// <summary>是否采集 NVD。</summary>
    public bool NvdEnabled { get; set; } = true;

    /// <summary>
    /// NVD API key(可选)。不填也能用,但限流严得多(约每 30 秒 5 次,有 key 则 30 秒 50 次)。
    /// 申请:https://nvd.nist.gov/developers/request-an-api-key
    /// </summary>
    public string? NvdApiKey { get; set; }

    /// <summary>
    /// NVD 的关键词过滤:命中任一即收录。默认是终端/运维用户天天打交道的那些组件。
    /// <para>留空表示不按关键词过滤 —— 那会把整个 NVD 拉进来,几乎肯定不是你想要的。</para>
    /// </summary>
    public List<string> NvdKeywords { get; set; } =
    [
        "openssh", "openssl", "sudo", "linux kernel", "glibc",
        "bash", "curl", "git", "nginx", "docker", "kubernetes",
        "postgresql", "mysql", "redis", "mongodb"
    ];

    /// <summary>NVD 收录的 CVSS 下限。低于此分的不入库(KEV 不受此限)。</summary>
    public double NvdMinCvss { get; set; } = 7.0;

    /// <summary>每次从 NVD 回看多少天的改动。</summary>
    public int NvdLookbackDays { get; set; } = 7;
}
