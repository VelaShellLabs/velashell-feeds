using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MongoDB.Driver;
using VelaShell.Feeds.Domain;

namespace VelaShell.Feeds.Infrastructure.Cve;

/// <summary>
/// 周期性采集漏洞公告并入库的后台服务。
/// <para>
/// 入库用 upsert 且**只更新会变的字段**:<see cref="CveAdvisory.IsSuppressed" /> 与
/// <see cref="CveAdvisory.SuppressedReason" /> 是管理员的决定,不能被下一轮采集覆盖回去 ——
/// 否则屏蔽一条噪音,几小时后它自己又回来了。
/// </para>
/// </summary>
public sealed class CveCollectionService(
    FeedsDbContext db,
    KevCollector kev,
    NvdCollector nvd,
    IOptionsMonitor<CveOptions> options,
    ILogger<CveCollectionService>? logger = null) : BackgroundService
{
    /// <summary>启动后先等一会儿再采:让 Web 端点先起来,别和启动争带宽。</summary>
    private static readonly TimeSpan StartupDelay = TimeSpan.FromSeconds(20);

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await Task.Delay(StartupDelay, stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return;
        }
        while (!stoppingToken.IsCancellationRequested)
        {
            CveOptions current = options.CurrentValue;
            if (current.Enabled)
            {
                await RunOnceAsync(current, stoppingToken).ConfigureAwait(false);
            }
            try
            {
                await Task.Delay(TimeSpan.FromHours(Math.Max(1, current.IntervalHours)), stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    /// <summary>跑一轮采集。整轮吞异常:采集挂了不该把宿主进程带下去,下一轮再试。</summary>
    public async Task<int> RunOnceAsync(CveOptions current, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(current);
        List<CveAdvisory> collected = [];
        try
        {
            collected.AddRange(await kev.CollectAsync(current, cancellationToken).ConfigureAwait(false));
        }
        catch (Exception ex)
        {
            logger?.LogError(ex, "KEV 采集异常。");
        }
        try
        {
            collected.AddRange(await nvd.CollectAsync(current, cancellationToken).ConfigureAwait(false));
        }
        catch (Exception ex)
        {
            logger?.LogError(ex, "NVD 采集异常。");
        }
        if (collected.Count == 0)
        {
            logger?.LogInformation("本轮采集没有取到条目。");
            return 0;
        }
        var written = 0;
        foreach (CveAdvisory advisory in collected)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            try
            {
                await UpsertAsync(advisory, cancellationToken).ConfigureAwait(false);
                written++;
            }
            catch (MongoException ex)
            {
                logger?.LogWarning(ex, "写入公告 {Id} 失败。", advisory.Id);
            }
        }
        logger?.LogInformation("采集完成:取到 {Collected} 条,写入 {Written} 条。", collected.Count, written);
        return written;
    }

    /// <summary>
    /// 按 id upsert。**刻意逐字段更新而不是整文档替换** —— 替换会把管理员设的屏蔽标记冲掉。
    /// </summary>
    private Task UpsertAsync(CveAdvisory advisory, CancellationToken cancellationToken) =>
        db.Advisories.UpdateOneAsync(
            Builders<CveAdvisory>.Filter.Eq(item => item.Id, advisory.Id),
            Builders<CveAdvisory>.Update
                .Set(item => item.CveId, advisory.CveId)
                .Set(item => item.Source, advisory.Source)
                .Set(item => item.Title, advisory.Title)
                .Set(item => item.Summary, advisory.Summary)
                .Set(item => item.CvssScore, advisory.CvssScore)
                .Set(item => item.KnownExploited, advisory.KnownExploited)
                .Set(item => item.Products, advisory.Products)
                .Set(item => item.PublishedAt, advisory.PublishedAt)
                .Set(item => item.Url, advisory.Url)
                .Set(item => item.FetchedAt, DateTime.UtcNow)
                // 首次插入时才给屏蔽标记初值,之后再也不碰它。
                .SetOnInsert(item => item.IsSuppressed, false),
            new UpdateOptions { IsUpsert = true },
            cancellationToken);
}
