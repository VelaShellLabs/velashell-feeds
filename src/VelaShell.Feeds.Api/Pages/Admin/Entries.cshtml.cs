using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using MongoDB.Driver;
using VelaShell.Feeds.Api.Services;
using VelaShell.Feeds.Domain;
using VelaShell.Feeds.Infrastructure;

namespace VelaShell.Feeds.Api.Pages.Admin;

/// <summary>公告与广告的列表:发布、下线、删除。</summary>
public sealed class EntriesModel(FeedsDbContext db, FeedCacheService feed) : PageModel
{
    /// <summary>全部条目,新的在前。</summary>
    public IReadOnlyList<FeedEntry> Items { get; private set; } = [];

    /// <summary>载入列表。</summary>
    public async Task OnGetAsync(CancellationToken cancellationToken) =>
        Items = await db.Entries.Find(Builders<FeedEntry>.Filter.Empty)
                        .SortByDescending(entry => entry.UpdatedAt)
                        .Limit(200)
                        .ToListAsync(cancellationToken);

    /// <summary>发布一条:立刻进 feed(仍受投放时间窗约束)。</summary>
    public Task<IActionResult> OnPostPublishAsync(string id, CancellationToken cancellationToken) =>
        SetStatusAsync(id, EntryStatus.Published, cancellationToken);

    /// <summary>下线一条:从 feed 撤出,记录留着。</summary>
    public Task<IActionResult> OnPostArchiveAsync(string id, CancellationToken cancellationToken) =>
        SetStatusAsync(id, EntryStatus.Archived, cancellationToken);

    /// <summary>删除一条。</summary>
    public async Task<IActionResult> OnPostDeleteAsync(string id, CancellationToken cancellationToken)
    {
        await db.Entries.DeleteOneAsync(Builders<FeedEntry>.Filter.Eq(entry => entry.Id, id), cancellationToken);
        feed.Invalidate();
        return RedirectToPage();
    }

    private async Task<IActionResult> SetStatusAsync(string id, EntryStatus status, CancellationToken cancellationToken)
    {
        await db.Entries.UpdateOneAsync(
            Builders<FeedEntry>.Filter.Eq(entry => entry.Id, id),
            Builders<FeedEntry>.Update
                .Set(entry => entry.Status, status)
                .Set(entry => entry.UpdatedAt, DateTime.UtcNow),
            cancellationToken: cancellationToken);

        // 状态变了就作废缓存 —— 管理员点完"发布"应该马上能在预览里看到,
        // 而不是等 5 分钟才知道自己有没有点对。
        feed.Invalidate();
        return RedirectToPage();
    }
}
