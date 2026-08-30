using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text.Json;
using VelaShell.Feeds.Api.Services;

namespace VelaShell.Feeds.Api.Pages.Admin;

/// <summary>
/// feed 预览:直接看客户端会收到的那份 JSON。
/// <para>
/// 有这一页是因为投放链路上最容易出错的一步,恰恰是「我以为发出去了」——
/// 状态还是草稿、投放期没到、定向把自己筛掉了,在列表页都看不出来,在这里一目了然。
/// </para>
/// </summary>
public sealed class PreviewModel(FeedCacheService feed) : PageModel
{
    /// <summary>格式化后的 JSON。</summary>
    public string Json { get; private set; } = "";

    /// <summary>条目数。</summary>
    public int ItemCount { get; private set; }

    /// <summary>内容指纹。</summary>
    public string ETag { get; private set; } = "";

    /// <summary>渲染时刻(UTC)。</summary>
    public DateTime RenderedAt { get; private set; }

    /// <summary>载入当前 feed。</summary>
    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        var current = await feed.GetAsync(cancellationToken);
        ItemCount = current.ItemCount;
        ETag = current.ETag;
        RenderedAt = current.RenderedAt;

        // 缓存里存的是压缩过的字节(那才是真正下发的东西);这里重新缩进只为了人能读。
        using var document = JsonDocument.Parse(current.Payload);
        Json = JsonSerializer.Serialize(document, new JsonSerializerOptions { WriteIndented = true });
    }

    /// <summary>作废缓存后重新渲染 —— 改完内容想立刻看结果时用。</summary>
    public IActionResult OnPostRefresh()
    {
        feed.Invalidate();
        return RedirectToPage();
    }
}
