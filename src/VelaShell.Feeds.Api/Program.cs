using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using VelaShell.Feeds.Api.Options;
using VelaShell.Feeds.Api.Services;
using VelaShell.Feeds.Domain;
using VelaShell.Feeds.Infrastructure;
using VelaShell.Feeds.Infrastructure.Cve;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

// ---- 配置 --------------------------------------------------------------------
builder.Services.Configure<FeedsAuthOptions>(builder.Configuration.GetSection(FeedsAuthOptions.SectionName));
builder.Services.Configure<CveOptions>(builder.Configuration.GetSection(CveOptions.SectionName));
builder.Services.Configure<FeedCompositionOptions>(builder.Configuration.GetSection("Feed"));
FeedsAuthOptions auth = builder.Configuration.GetSection(FeedsAuthOptions.SectionName).Get<FeedsAuthOptions>() ?? new();

// ---- 数据 --------------------------------------------------------------------
builder.Services.AddSingleton(_ =>
    new FeedsDbContext(builder.Configuration.GetConnectionString("Mongo")
                       ?? "mongodb://localhost:27017/velashell-feeds"));

// ---- 采集 --------------------------------------------------------------------
// 采集器各自一个具名 HttpClient:NVD 与 CISA 是两个不相干的上游,
// 一个慢下来不该把另一个的连接池拖住。
builder.Services.AddHttpClient<KevCollector>(client => client.Timeout = TimeSpan.FromSeconds(60));
builder.Services.AddHttpClient<NvdCollector>(client => client.Timeout = TimeSpan.FromSeconds(60));
builder.Services.AddHostedService<CveCollectionService>();
builder.Services.AddSingleton<CveCollectionService>();

// ---- feed 渲染与缓存 ----------------------------------------------------------
builder.Services.AddSingleton<FeedCacheService>();

// ---- 认证:把登录整个交给统一认证服务 --------------------------------------------
// 本服务不存口令、不发令牌。走授权码 + PKCE,拿回身份后由下面的策略判断是不是管理员。
builder.Services.AddAuthentication(options =>
       {
           options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
           options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
       })
       .AddCookie(options =>
       {
           options.Cookie.Name = "velashell.feeds.admin";
           options.Cookie.HttpOnly = true;
           options.Cookie.SameSite = SameSiteMode.Lax; // OIDC 回跳是顶级导航,Lax 够用且比 None 安全
           options.Cookie.SecurePolicy = auth.RequireHttpsMetadata
                                             ? CookieSecurePolicy.Always
                                             : CookieSecurePolicy.SameAsRequest;
           options.ExpireTimeSpan = TimeSpan.FromHours(8);
           options.SlidingExpiration = true;
           options.AccessDeniedPath = "/admin/denied";
       })
       .AddOpenIdConnect(options =>
       {
           options.Authority = auth.Issuer.TrimEnd('/');
           // 浏览器看到的地址与本服务能访问到的地址不同时(容器内),单独指 metadata。
           // 注意:metadata 里的 token 端点仍是对外地址,所以本服务也必须访问得到它。
           if (!string.IsNullOrWhiteSpace(auth.Authority) && auth.Authority != auth.Issuer)
           {
               options.MetadataAddress = $"{auth.Authority.TrimEnd('/')}/.well-known/openid-configuration";
           }
           options.ClientId = auth.ClientId;
           options.ClientSecret = string.IsNullOrWhiteSpace(auth.ClientSecret) ? null : auth.ClientSecret;
           options.ResponseType = "code";
           options.UsePkce = true;
           options.RequireHttpsMetadata = auth.RequireHttpsMetadata;
           options.SaveTokens = false; // 管理台不调别的 API,存着令牌只是多一份可被偷的东西
           options.GetClaimsFromUserInfoEndpoint = true;
           options.Scope.Clear();
           options.Scope.Add("openid");
           options.Scope.Add("profile");
           if (!string.IsNullOrWhiteSpace(auth.Scope))
           {
               options.Scope.Add(auth.Scope);
           }
           options.TokenValidationParameters = new TokenValidationParameters
           {
               NameClaimType = "name",
               RoleClaimType = "role",
               // OpenIddict 用 Uri 表示 issuer,令牌里的 iss 一定带结尾斜杠,而人写配置时几乎不带。
               // 只认一种写法的话,这个差别会精确地表现成"登录成功但一直跳回登录页"。
               ValidIssuers = [auth.Issuer.TrimEnd('/'), $"{auth.Issuer.TrimEnd('/')}/"]
           };
       });

builder.Services.AddAuthorizationBuilder()
       .AddPolicy(FeedsPolicies.Admin, policy =>
           policy.RequireAssertion(context =>
           {
               // 主体的取法要与别处完全一致,两处分叉的话换一次声明映射就会出现
               // "这里认得出你、那里认不出你"。
               string? subject = context.User.FindFirst("sub")?.Value
                                 ?? context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
               return context.User.Identity?.IsAuthenticated == true && auth.IsAdmin(subject);
           }));

builder.Services.AddRazorPages(options =>
{
    // 整个 /admin 目录默认要管理员,单独放行拒绝页 —— 否则被拒的人会陷入
    // "没权限 → 跳去拒绝页 → 拒绝页也没权限"的循环。
    options.Conventions.AuthorizeFolder("/Admin", FeedsPolicies.Admin);
    options.Conventions.AllowAnonymousToPage("/Admin/Denied");
});

WebApplication app = builder.Build();

// 启动即建索引;库还没起来时不该让整个服务起不来,记一条日志继续。
using (IServiceScope scope = app.Services.CreateScope())
{
    try
    {
        await scope.ServiceProvider.GetRequiredService<FeedsDbContext>().EnsureIndexesAsync();
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "建立索引失败,服务继续启动。");
    }
}
if (auth.AdminSubjects.Length == 0)
{
    app.Logger.LogWarning(
        "Auth:AdminSubjects 为空 —— 管理台现在**谁都进不去**。到统一认证服务登录一次拿到 sub,填进配置再重启。");
}

app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();

// ---- 公开端点 ----------------------------------------------------------------
// VelaShell 客户端拉的就是这个。它是匿名的:要求认证等于要求每台客户端都有账号。
app.MapGet("/feed.json", async (FeedCacheService feed, HttpContext http, CancellationToken cancel) =>
{
    CachedFeed current = await feed.GetAsync(cancel);
    http.Response.Headers.ETag = current.ETag;
    // 客户端不发条件请求,但中间的 CDN / 反代会用;5 分钟与渲染缓存对齐。
    http.Response.Headers.CacheControl = "public, max-age=300";
    if (http.Request.Headers.IfNoneMatch.Contains(current.ETag))
    {
        return Results.StatusCode(StatusCodes.Status304NotModified);
    }
    return Results.Bytes(current.Payload, "application/json; charset=utf-8");
}).AllowAnonymous();

app.MapGet("/healthz", () => Results.Ok(new { status = "ok" })).AllowAnonymous();

// 登录 / 登出。登录后回管理台首页。
app.MapGet("/signin", (string? returnUrl) =>
    Results.Challenge(new() { RedirectUri = SafeReturn(returnUrl) }, [OpenIdConnectDefaults.AuthenticationScheme]))
   .AllowAnonymous();

app.MapPost("/signout", () =>
    Results.SignOut(new() { RedirectUri = "/" },
        [CookieAuthenticationDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme]));

app.MapRazorPages();
app.MapGet("/", () => Results.Redirect("/admin")).AllowAnonymous();

app.Run();

// 只接受站内相对路径:把 returnUrl 原样交给 Challenge 等于开了个开放重定向,
// 而这个参数就在地址栏里,谁都能改。
static string SafeReturn(string? returnUrl) =>
    !string.IsNullOrWhiteSpace(returnUrl) && returnUrl.StartsWith('/') && !returnUrl.StartsWith("//", StringComparison.Ordinal)
        ? returnUrl
        : "/admin";

/// <summary>供集成测试引用的入口标记。</summary>
public partial class Program;
