namespace VelaShell.Feeds.Api.Options;

/// <summary>授权策略名。</summary>
public static class FeedsPolicies
{
    /// <summary>管理员:能进管理台、改条目、投广告、屏蔽公告。</summary>
    public const string Admin = "feeds:admin";
}

/// <summary>
/// 对接统一认证服务的配置。本服务是**依赖方**:不发令牌,只把登录交给认证服务,
/// 拿回身份后自己判断这个人是不是管理员。
/// <para>
/// <b>为什么复用那套开放注册的认证服务是安全的:</b>认证与授权是两件事。
/// 认证服务只回答"你是 <c>sub=xxx</c>";"你能不能进这个后台"由下面的
/// <see cref="AdminSubjects" /> 白名单回答。任何人都能去注册、都能拿到令牌,
/// 但拿不到这里的准入 —— 与插件市场的审核员是同一套模式。
/// </para>
/// </summary>
public sealed class FeedsAuthOptions
{
    /// <summary>配置节名。</summary>
    public const string SectionName = "Auth";

    /// <summary>
    /// 认证服务对外宣称的身份(令牌里 <c>iss</c> 的值),也是浏览器跳过去登录的地址。
    /// 必须与认证服务的 <c>Identity:Issuer</c> 一模一样,差一个斜杠就会全线 401。
    /// </summary>
    public string Issuer { get; set; } = "http://localhost:7020";

    /// <summary>
    /// 拉 discovery 与 JWKS 用的地址。留空表示与 <see cref="Issuer" /> 相同。
    /// 只有"浏览器看到的地址"与"本服务能访问到的地址"不同时才需要单独设
    /// (compose 里就是这种情况:浏览器走 localhost,容器内走服务名)。
    /// </summary>
    public string Authority { get; set; } = "";

    /// <summary>
    /// 本服务在认证服务里注册的客户端 id。
    /// <b>不要复用市场的客户端</b> —— 回跳地址必须锁死在本服务的域名上。
    /// </summary>
    public string ClientId { get; set; } = "velashell-feeds-admin";

    /// <summary>客户端密钥。管理台是有后端的机密客户端,应当配一个。</summary>
    public string ClientSecret { get; set; } = "";

    /// <summary>
    /// 申请的 API scope。<b>不要复用 <c>velashell-market</c></b>:
    /// 令牌不该跨服务通用,市场用户的令牌根本不该能打到这里来。
    /// </summary>
    public string Scope { get; set; } = "velashell-feeds";

    /// <summary>是否要求 metadata 走 HTTPS。**生产必须为 true**。</summary>
    public bool RequireHttpsMetadata { get; set; } = true;

    /// <summary>
    /// 管理员的身份主体(<c>sub</c>)白名单。
    /// <para>
    /// <b>空列表 = 谁都进不去</b>,而不是谁都能进。这个方向不能反:一个还没配置好的
    /// 服务如果默认放行,等于把广告投放和 feed 内容交给第一个找到它的人。
    /// </para>
    /// </summary>
    public string[] AdminSubjects { get; set; } = [];

    /// <summary>判断一个身份主体是不是管理员。</summary>
    public bool IsAdmin(string? subject) =>
        !string.IsNullOrWhiteSpace(subject) && AdminSubjects.Contains(subject, StringComparer.Ordinal);
}
