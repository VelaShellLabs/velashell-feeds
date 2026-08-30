using Microsoft.AspNetCore.Mvc.RazorPages;
using MongoDB.Driver;
using VelaShell.Feeds.Api.Services;
using VelaShell.Feeds.Domain;
using VelaShell.Feeds.Infrastructure;

namespace VelaShell.Feeds.Api.Pages.Admin;

/// <summary>管理台概览:一眼看清 feed 现在到底在发什么。</summary>
public sealed class IndexModel(FeedsDbContext db, FeedCacheService feed) : PageModel
{
    /// <summary>已发布且在投放期内的手工条目数。</summary>
    public long LiveEntries { get; private set; }

    /// <summary>草稿数。</summary>
    public long DraftEntries { get; private set; }

    /// <summary>库里的漏洞公告总数。</summary>
    public long Advisories { get; private set; }

    /// <summary>其中已知在野被利用的数量。</summary>
    public long KnownExploited { get; private set; }

    /// <summary>当前 feed 实际下发的条目数。</summary>
    public int FeedItems { get; private set; }

    /// <summary>feed 上次渲染的时刻(UTC)。</summary>
    public DateTime RenderedAt { get; private set; }

    /// <summary>载入统计。</summary>
    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        DateTime now = DateTime.UtcNow;
        LiveEntries = await db.Entries.CountDocumentsAsync(
            Builders<FeedEntry>.Filter.And(
                Builders<FeedEntry>.Filter.Eq(entry => entry.Status, EntryStatus.Published),
                Builders<FeedEntry>.Filter.Lte(entry => entry.PublishedAt, now),
                Builders<FeedEntry>.Filter.Or(
                    Builders<FeedEntry>.Filter.Eq(entry => entry.ExpiresAt, null),
                    Builders<FeedEntry>.Filter.Gt(entry => entry.ExpiresAt, now))),
            cancellationToken: cancellationToken);
        DraftEntries = await db.Entries.CountDocumentsAsync(
            Builders<FeedEntry>.Filter.Eq(entry => entry.Status, EntryStatus.Draft),
            cancellationToken: cancellationToken);
        Advisories = await db.Advisories.CountDocumentsAsync(
            Builders<CveAdvisory>.Filter.Empty, cancellationToken: cancellationToken);
        KnownExploited = await db.Advisories.CountDocumentsAsync(
            Builders<CveAdvisory>.Filter.Eq(item => item.KnownExploited, true), cancellationToken: cancellationToken);

        CachedFeed current = await feed.GetAsync(cancellationToken);
        FeedItems = current.ItemCount;
        RenderedAt = current.RenderedAt;
    }
}
