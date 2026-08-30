using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;
using MongoDB.Driver;
using VelaShell.Feeds.Api.Services;
using VelaShell.Feeds.Domain;
using VelaShell.Feeds.Infrastructure;
using VelaShell.Feeds.Infrastructure.Cve;

namespace VelaShell.Feeds.Api.Pages.Admin;

/// <summary>采集来的漏洞公告:查看、屏蔽噪音、手工触发一次采集。</summary>
public sealed class AdvisoriesModel(
    FeedsDbContext db,
    FeedCacheService feed,
    CveCollectionService collector,
    IOptionsMonitor<CveOptions> cveOptions) : PageModel
{
    /// <summary>列表(在野被利用的排在前面)。</summary>
    public IReadOnlyList<CveAdvisory> Items { get; private set; } = [];

    /// <summary>上一次手工采集的结果提示。</summary>
    [TempData]
    public string? Message { get; set; }

    /// <summary>载入列表。</summary>
    public async Task OnGetAsync(CancellationToken cancellationToken) =>
        Items = await db.Advisories.Find(Builders<CveAdvisory>.Filter.Empty)
                        .SortByDescending(item => item.PublishedAt)
                        .Limit(200)
                        .ToListAsync(cancellationToken);

    /// <summary>屏蔽一条:采集器照抓照存,但不进 feed。</summary>
    public async Task<IActionResult> OnPostSuppressAsync(string id, CancellationToken cancellationToken)
    {
        await db.Advisories.UpdateOneAsync(
            Builders<CveAdvisory>.Filter.Eq(item => item.Id, id),
            Builders<CveAdvisory>.Update
                .Set(item => item.IsSuppressed, true)
                .Set(item => item.SuppressedReason, "管理员手工屏蔽"),
            cancellationToken: cancellationToken);
        feed.Invalidate();
        return RedirectToPage();
    }

    /// <summary>取消屏蔽。</summary>
    public async Task<IActionResult> OnPostRestoreAsync(string id, CancellationToken cancellationToken)
    {
        await db.Advisories.UpdateOneAsync(
            Builders<CveAdvisory>.Filter.Eq(item => item.Id, id),
            Builders<CveAdvisory>.Update
                .Set(item => item.IsSuppressed, false)
                .Set(item => item.SuppressedReason, null),
            cancellationToken: cancellationToken);
        feed.Invalidate();
        return RedirectToPage();
    }

    /// <summary>
    /// 立刻跑一轮采集。NVD 那侧要按限流串行查关键词,可能要几十秒 ——
    /// 这个按钮存在的意义是"改完配置马上验证",不是日常操作。
    /// </summary>
    public async Task<IActionResult> OnPostCollectAsync(CancellationToken cancellationToken)
    {
        int written = await collector.RunOnceAsync(cveOptions.CurrentValue, cancellationToken);
        feed.Invalidate();
        Message = $"采集完成,写入 {written} 条。";
        return RedirectToPage();
    }
}
