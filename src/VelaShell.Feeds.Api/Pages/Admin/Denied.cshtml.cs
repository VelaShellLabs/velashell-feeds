using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace VelaShell.Feeds.Api.Pages.Admin;

/// <summary>
/// 已登录但不是管理员时落到这里。
/// <para>
/// 刻意把用户自己的 <c>sub</c> 显示出来:配置管理员白名单需要的就是这个值,
/// 不显示的话第一次部署时得去翻库或翻日志才拿得到。
/// </para>
/// </summary>
[AllowAnonymous]
public sealed class DeniedModel : PageModel
{
    /// <summary>当前登录者的身份主体。</summary>
    public string? Subject { get; private set; }

    /// <summary>载入。</summary>
    public void OnGet() =>
        Subject = User.FindFirst("sub")?.Value ?? User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
}
