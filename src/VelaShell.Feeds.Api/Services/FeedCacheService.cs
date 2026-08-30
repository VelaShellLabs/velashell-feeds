using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;
using Microsoft.Extensions.Options;
using VelaShell.Feeds.Domain;
using VelaShell.Feeds.Infrastructure;

namespace VelaShell.Feeds.Api.Services;

/// <summary>
/// feed 的生成与缓存。
/// <para>
/// 客户端每次都是完整 GET(它不发条件请求),而 feed 内容以小时计才变一次 ——
/// 每来一个请求就查一次库、拼一次 JSON 是纯粹的浪费。这里把渲染结果连同 ETag 一起缓存,
/// 内容没变时直接吐字节。
/// </para>
/// </summary>
public sealed class FeedCacheService(
    FeedsDbContext db,
    IOptionsMonitor<FeedCompositionOptions> options,
    ILogger<FeedCacheService>? logger = null)
{
    /// <summary>缓存有效期。到点后重新查库渲染;管理台改完内容会主动作废缓存。</summary>
    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(5);

    private static readonly JsonSerializerOptions Json = new()
    {
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false
    };

    /// <summary>渲染失败后的重试间隔。库挂着的时候不该每个请求都去撞一次五秒超时。</summary>
    private static readonly TimeSpan FailureBackoff = TimeSpan.FromSeconds(30);

    private readonly SemaphoreSlim _gate = new(1, 1);
    private CachedFeed? _cached;
    private DateTime _nextAttempt = DateTime.MinValue;

    /// <summary>
    /// 取当前 feed(必要时重新渲染)。
    /// <para>
    /// <b>永远返回一份合法文档,不抛。</b> 这是个公开端点:库抖一下就给客户端 500,
    /// 换不来任何好处 —— 拿上一次的结果继续发(陈旧但有效),实在没有就发空列表,
    /// 客户端会把它当作"这次没有新消息"。
    /// </para>
    /// </summary>
    public async Task<CachedFeed> GetAsync(CancellationToken cancellationToken = default)
    {
        CachedFeed? snapshot = _cached;
        if (snapshot is not null && snapshot.RenderedAt + Ttl > DateTime.UtcNow)
        {
            return snapshot;
        }
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // 拿到锁后再看一次:并发进来的请求只该有一个真去渲染。
            snapshot = _cached;
            if (snapshot is not null && snapshot.RenderedAt + Ttl > DateTime.UtcNow)
            {
                return snapshot;
            }
            if (DateTime.UtcNow < _nextAttempt)
            {
                // 还在退避窗口里:有旧的就发旧的,没有就发空的。
                return snapshot ?? Empty();
            }
            try
            {
                CachedFeed rendered = await RenderAsync(cancellationToken).ConfigureAwait(false);
                _cached = rendered;
                _nextAttempt = DateTime.MinValue;
                return rendered;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger?.LogError(ex, "渲染 feed 失败,{Fallback}。",
                    snapshot is null ? "本次返回空列表" : "继续沿用上一次的结果");
                _nextAttempt = DateTime.UtcNow + FailureBackoff;
                return snapshot ?? Empty();
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>一份空但合法的 feed。客户端拿到它等于"这次没有新消息"。</summary>
    private static CachedFeed Empty()
    {
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(new FeedDocument { Items = [] }, Json);
        return new(payload, MakeETag(payload), DateTime.UtcNow, 0);
    }

    /// <summary>作废缓存。管理台改完内容后调用,让下一个请求立刻看到新结果。</summary>
    public void Invalidate() => _cached = null;

    private async Task<CachedFeed> RenderAsync(CancellationToken cancellationToken)
    {
        DateTime now = DateTime.UtcNow;
        FeedCompositionOptions composition = options.CurrentValue;

        // 只捞可能进 feed 的:已发布、且未过期。草稿与归档不该出现在这条路径上。
        List<FeedEntry> entries = await db.Entries
            .Find(Builders<FeedEntry>.Filter.Eq(entry => entry.Status, EntryStatus.Published))
            .SortByDescending(entry => entry.PublishedAt)
            .Limit(composition.MaxItems * 2)
            .ToListAsync(cancellationToken).ConfigureAwait(false);

        // CVE 侧同样先在库里筛掉过期与被屏蔽的,别把几千条拉进内存再过滤。
        DateTime cutoff = now.AddDays(-composition.CveLifetimeDays);
        List<CveAdvisory> advisories = await db.Advisories
            .Find(Builders<CveAdvisory>.Filter.And(
                Builders<CveAdvisory>.Filter.Eq(item => item.IsSuppressed, false),
                Builders<CveAdvisory>.Filter.Gt(item => item.PublishedAt, cutoff)))
            .SortByDescending(item => item.PublishedAt)
            .Limit(composition.MaxCveItems * 5)
            .ToListAsync(cancellationToken).ConfigureAwait(false);

        FeedDocument document = FeedComposer.Compose(entries, advisories, composition, now);
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(document, Json);
        return new(payload, MakeETag(payload), now, document.Items.Count);
    }

    /// <summary>
    /// ETag 按内容算。客户端目前不发条件请求,但中间的 CDN / 反代会用它,
    /// 而且内容没变时它能让「这次拉取到底有没有新东西」一眼可判。
    /// </summary>
    private static string MakeETag(byte[] payload) =>
        $"\"{Convert.ToHexStringLower(SHA256.HashData(payload).AsSpan(0, 16))}\"";
}

/// <summary>一份渲染好的 feed。</summary>
/// <param name="Payload">序列化后的 UTF-8 字节。</param>
/// <param name="ETag">内容指纹(带引号,可直接作为响应头)。</param>
/// <param name="RenderedAt">渲染时刻(UTC)。</param>
/// <param name="ItemCount">条目数。</param>
public sealed record CachedFeed(byte[] Payload, string ETag, DateTime RenderedAt, int ItemCount);
