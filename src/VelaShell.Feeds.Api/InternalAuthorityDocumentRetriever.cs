using Microsoft.IdentityModel.Protocols;

namespace VelaShell.Feeds.Api;

/// <summary>
/// 把认证服务文档里的地址拨回**内部可达**的那个,并给内部请求补上转发头。
/// <para>
/// 只有"对外 HTTPS + 内部明文直连"这种部署才需要它,而那正是本服务的生产形态:
/// 浏览器经反代访问 <c>https://auth.easilynet.top</c>,而本服务在容器网络里直连
/// <c>http://identity:8080</c>。
/// </para>
/// <para>
/// 不装它会连撞两堵墙,而且两次的报错完全不同、很容易被当成两个问题:
/// </para>
/// <list type="number">
///   <item>
///     认证服务开着 <c>Identity:RequireHttps</c>,OpenIddict 会**拒绝一切非 HTTPS 请求**。
///     容器内直连不经反代、没有转发头,于是 discovery 直接被回 400 —— 客户端报
///     <c>IDX20807</c>(连上了但对方回了非 200,与"连不上"的 <c>IDX20804</c> 不是一回事)。
///   </item>
///   <item>
///     补上转发头之后 discovery 能拿到了,但**文档里的端点全变成了 https://identity:8080**
///     —— 协议被转发头改成了 https,主机却仍是内部的。客户端照着它去拉 JWKS,
///     等于对一个明文端口发起 TLS 握手,报 <c>The SSL connection could not be established</c>。
///   </item>
/// </list>
/// <para>
/// 所以两件事必须一起做:补头让对方放行,再把回来的地址改写回内部形态。
/// 这与插件市场的 <c>InternalAuthorityConfigurationManager</c> 是同一套处置。
/// </para>
/// <para>
/// 这不是在放松安全:这一跳根本不出宿主机的 Docker 网络,认证服务本来就无条件信任
/// 转发头(<c>KnownProxies</c> 清空),前提正是它只暴露给反代 —— 也正因如此,
/// identity 的端口绝不能直接挂到公网上。而令牌的 <c>iss</c> 校验仍然钉在对外的
/// https 地址上,那才是真正防伪造的一道。
/// </para>
/// </summary>
public sealed class InternalAuthorityDocumentRetriever : IDocumentRetriever
{
    private readonly HttpDocumentRetriever _inner;
    private readonly string _internalAuthority;

    /// <summary>
    /// 构造。
    /// </summary>
    /// <param name="issuer">对外 issuer(令牌里 <c>iss</c> 的值)。只用来判断对外是不是 HTTPS。</param>
    /// <param name="internalAuthority">本服务实际能访问到的认证服务地址。</param>
    public InternalAuthorityDocumentRetriever(string issuer, string internalAuthority)
    {
        _internalAuthority = internalAuthority.TrimEnd('/');
        var client = new HttpClient();
        if (Uri.TryCreate(issuer, UriKind.Absolute, out var issuerUri))
        {
            // 让认证服务**以为**这个请求是从对外地址进来的。两个头各管一件事:
            //
            // X-Forwarded-Proto —— 让 OpenIddict 认为传输是安全的。它在
            //   Identity:RequireHttps 下会拒绝一切非 HTTPS 请求,而容器内直连不经反代、
            //   没有这个头,discovery 会被直接回 400(客户端报 IDX20807)。
            //
            // Host —— 决定 discovery 文档里那些端点的主机名。不设的话它们会长成
            //   https://identity:8080/connect/authorize:后端拉 JWKS 尚可(会被下面
            //   ToInternal 改写回去),但 authorization_endpoint 是要**浏览器**去的,
            //   内部主机名用户根本打不开,表现是点登录后跳到一个无法访问的地址。
            //   (identity 只处理 XForwardedProto/XForwardedFor,不认 X-Forwarded-Host,
            //    所以这里直接改 Host 头 —— HTTP/1.1 的虚拟主机语义,合法且是反代的常规做法。)
            client.DefaultRequestHeaders.Add("X-Forwarded-Proto", issuerUri.Scheme);
            client.DefaultRequestHeaders.Host = issuerUri.IsDefaultPort
                                                    ? issuerUri.Host
                                                    : $"{issuerUri.Host}:{issuerUri.Port}";
        }
        _inner = new(client)
        {
            // RequireHttps 按**改写之后**的地址来定:改写后是容器内的 http 地址,
            // 硬要求 HTTPS 会让 HttpDocumentRetriever 直接抛 IDX20108。
            RequireHttps = _internalAuthority.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
        };
    }

    /// <inheritdoc />
    public Task<string> GetDocumentAsync(string address, CancellationToken cancel) =>
        _inner.GetDocumentAsync(ToInternal(address, _internalAuthority), cancel);

    /// <summary>
    /// 换掉 scheme + 主机 + 端口,路径与查询串原样保留。地址不是绝对 URI 时原样返回。
    /// </summary>
    public static string ToInternal(string address, string internalAuthority)
    {
        // 必须显式校验 scheme:漏写协议的 "identity:8080" 会被 Uri.TryCreate 当成**合法的绝对 URI**
        // (scheme=identity、path=8080),照着它重写会拼出谁也连不上的地址。
        // 宁可原样返回,把问题留给启动校验去大声报出来。
        if (!Uri.TryCreate(address, UriKind.Absolute, out var target)
            || !Uri.TryCreate(internalAuthority, UriKind.Absolute, out var authority)
            || (authority.Scheme != Uri.UriSchemeHttp && authority.Scheme != Uri.UriSchemeHttps))
        {
            return address;
        }
        return new UriBuilder(target)
        {
            Scheme = authority.Scheme,
            Host = authority.Host,
            // -1 表示"用该 scheme 的默认端口"。内部地址显式写了端口时照搬。
            Port = authority.IsDefaultPort ? -1 : authority.Port
        }.Uri.ToString();
    }
}
