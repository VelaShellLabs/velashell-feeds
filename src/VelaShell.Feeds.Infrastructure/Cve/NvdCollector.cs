using Microsoft.Extensions.Logging;
using System.Globalization;
using System.Text.Json;
using VelaShell.Feeds.Domain;

namespace VelaShell.Feeds.Infrastructure.Cve;

/// <summary>
/// NVD 2.0 API 采集器,**按关键词逐个查**。
/// <para>
/// 不拉全量:NVD 一天新增几百条,推给终端工具的用户等于让他立刻关掉资讯源。
/// 这里对每个关注的组件关键词发一次带 <c>keywordSearch</c> 的查询,
/// 再按 CVSS 阈值过滤,留下的才是运维真会关心的那些。
/// </para>
/// <para>
/// 限流:无 API key 时约每 30 秒 5 次请求。因此关键词之间**有意串行并留间隔** ——
/// 被 429 挡住整轮都白跑,比慢几十秒糟糕得多。
/// </para>
/// </summary>
public sealed class NvdCollector(HttpClient http, ILogger<NvdCollector>? logger = null)
{
    /// <summary>两次请求之间的间隔:无 key 时的限流是 30 秒 5 次,6 秒一次正好贴着走。</summary>
    private static readonly TimeSpan ThrottleNoKey = TimeSpan.FromSeconds(6);

    /// <summary>有 key 时限流放宽到 30 秒 50 次。</summary>
    private static readonly TimeSpan ThrottleWithKey = TimeSpan.FromMilliseconds(700);

    /// <summary>单个关键词最多取回多少条,挡住某个宽泛词一次拉回上千条。</summary>
    private const int ResultsPerKeyword = 100;

    /// <summary>按配置的关键词逐个查询并汇总。任何一个关键词失败都不影响其余的。</summary>
    public async Task<IReadOnlyList<CveAdvisory>> CollectAsync(CveOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!options.NvdEnabled || string.IsNullOrWhiteSpace(options.NvdUrl) || options.NvdKeywords.Count == 0)
        {
            return [];
        }
        var throttle = string.IsNullOrWhiteSpace(options.NvdApiKey) ? ThrottleNoKey : ThrottleWithKey;
        var since = DateTime.UtcNow.AddDays(-Math.Max(1, options.NvdLookbackDays));
        Dictionary<string, CveAdvisory> collected = new(StringComparer.OrdinalIgnoreCase);
        var first = true;
        foreach (var keyword in options.NvdKeywords.Where(word => !string.IsNullOrWhiteSpace(word)))
        {
            if (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            if (!first)
            {
                await Task.Delay(throttle, cancellationToken).ConfigureAwait(false);
            }
            first = false;
            foreach (var advisory in await QueryAsync(options, keyword, since, cancellationToken).ConfigureAwait(false))
            {
                // 一个 CVE 可能同时命中多个关键词(如 openssl 与 curl),按编号收敛。
                collected.TryAdd(advisory.CveId, advisory);
            }
        }
        return [.. collected.Values];
    }

    private async Task<IReadOnlyList<CveAdvisory>> QueryAsync(
        CveOptions options, string keyword, DateTime since, CancellationToken cancellationToken)
    {
        var url = $"{options.NvdUrl.TrimEnd('/')}" +
                  $"?keywordSearch={Uri.EscapeDataString(keyword)}" +
                  $"&lastModStartDate={Iso(since)}" +
                  $"&lastModEndDate={Iso(DateTime.UtcNow)}" +
                  $"&resultsPerPage={ResultsPerKeyword}";
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            if (!string.IsNullOrWhiteSpace(options.NvdApiKey))
            {
                request.Headers.Add("apiKey", options.NvdApiKey);
            }
            using var response = await http.SendAsync(request, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                logger?.LogWarning("NVD 查询「{Keyword}」返回 {Status},跳过该关键词。", keyword, (int)response.StatusCode);
                return [];
            }
            var json = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            return Parse(json, options.NvdMinCvss);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            logger?.LogWarning(ex, "NVD 查询「{Keyword}」失败,跳过该关键词。", keyword);
            return [];
        }
    }

    /// <summary>
    /// 解析 NVD 2.0 的响应。结构为
    /// <c>{ "vulnerabilities": [ { "cve": { "id", "published", "descriptions": [...],
    /// "metrics": { "cvssMetricV31": [ { "cvssData": { "baseScore" } } ] } } } ] }</c>。
    /// </summary>
    public static IReadOnlyList<CveAdvisory> Parse(string json, double minCvss)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json);
        }
        catch (JsonException)
        {
            return [];
        }
        using (document)
        {
            if (document.RootElement.ValueKind != JsonValueKind.Object ||
                !document.RootElement.TryGetProperty("vulnerabilities", out var list) ||
                list.ValueKind != JsonValueKind.Array)
            {
                return [];
            }
            List<CveAdvisory> result = [];
            foreach (var wrapper in list.EnumerateArray())
            {
                if (wrapper.ValueKind != JsonValueKind.Object ||
                    !wrapper.TryGetProperty("cve", out var cve) ||
                    ParseOne(cve, minCvss) is not { } advisory)
                {
                    continue;
                }
                result.Add(advisory);
            }
            return result;
        }
    }

    private static CveAdvisory? ParseOne(JsonElement cve, double minCvss)
    {
        var id = ReadString(cve, "id");
        if (string.IsNullOrWhiteSpace(id))
        {
            return null;
        }
        var score = ReadCvss(cve);

        // 分数读不出来时一并跳过:没有分数就没法判断轻重,而这条路径的存在意义
        // 正是"只推够重的"。真正紧急的漏洞会从 KEV 那条路进来,不会漏。
        if (score is null || score < minCvss)
        {
            return null;
        }
        var description = ReadDescription(cve);
        return new()
        {
            Id = $"{CveSources.Nvd}:{id}",
            CveId = id,
            Source = CveSources.Nvd,
            Title = $"{id} (CVSS {score:0.0})",
            Summary = description,
            CvssScore = score,
            KnownExploited = false,
            PublishedAt = ReadDate(cve, "published") ?? DateTime.UtcNow,
            Url = $"https://nvd.nist.gov/vuln/detail/{Uri.EscapeDataString(id)}"
        };
    }

    /// <summary>取 CVSS 基础分,依次尝试 v3.1 → v3.0 → v2。</summary>
    private static double? ReadCvss(JsonElement cve)
    {
        if (!cve.TryGetProperty("metrics", out var metrics) || metrics.ValueKind != JsonValueKind.Object)
        {
            return null;
        }
        foreach (var key in (string[])["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"])
        {
            if (!metrics.TryGetProperty(key, out var entries) || entries.ValueKind != JsonValueKind.Array)
            {
                continue;
            }
            foreach (var entry in entries.EnumerateArray())
            {
                if (entry.ValueKind == JsonValueKind.Object &&
                    entry.TryGetProperty("cvssData", out var data) &&
                    data.ValueKind == JsonValueKind.Object &&
                    data.TryGetProperty("baseScore", out var score) &&
                    score.ValueKind == JsonValueKind.Number)
                {
                    return score.GetDouble();
                }
            }
        }
        return null;
    }

    /// <summary>取英文描述;没有英文时退回第一条。</summary>
    private static string? ReadDescription(JsonElement cve)
    {
        if (!cve.TryGetProperty("descriptions", out var list) || list.ValueKind != JsonValueKind.Array)
        {
            return null;
        }
        string? fallback = null;
        foreach (var entry in list.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.Object)
            {
                continue;
            }
            var value = ReadString(entry, "value");
            if (string.IsNullOrWhiteSpace(value))
            {
                continue;
            }
            fallback ??= value;
            if (ReadString(entry, "lang") is "en")
            {
                return value;
            }
        }
        return fallback;
    }

    /// <summary>NVD 的时间参数要求形如 <c>2026-08-30T00:00:00.000</c>(不带时区后缀)。</summary>
    private static string Iso(DateTime utc) => utc.ToString("yyyy-MM-ddTHH:mm:ss.fff", CultureInfo.InvariantCulture);

    private static string? ReadString(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()?.Trim()
            : null;

    private static DateTime? ReadDate(JsonElement element, string property) =>
        ReadString(element, property) is { Length: > 0 } text &&
        DateTime.TryParse(text, CultureInfo.InvariantCulture,
                          DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var parsed)
            ? parsed
            : null;
}
