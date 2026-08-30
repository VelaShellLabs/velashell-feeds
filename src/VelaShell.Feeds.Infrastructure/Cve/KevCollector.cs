using System.Globalization;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using VelaShell.Feeds.Domain;

namespace VelaShell.Feeds.Infrastructure.Cve;

/// <summary>
/// CISA「已知被利用漏洞」目录(KEV)的采集器。
/// <para>
/// 这是整个 feed 里信号最强的一路:能进这个目录,前提是**已经观察到在野利用**。
/// 它总量千余条、每次新增个位数,不需要任何过滤规则就可以整条推给用户。
/// </para>
/// <para>
/// 上游格式(节选):<c>{ "vulnerabilities": [ { "cveID", "vendorProject", "product",
/// "vulnerabilityName", "dateAdded", "shortDescription", "requiredAction" } ] }</c>
/// </para>
/// </summary>
public sealed class KevCollector(HttpClient http, ILogger<KevCollector>? logger = null)
{
    /// <summary>响应体上限:KEV 目录目前约 1–2 MB,给到 16 MB 足够它长几年。</summary>
    private const int MaxResponseBytes = 16 * 1024 * 1024;

    /// <summary>
    /// 拉取并解析。任何失败都返回空列表并记一条日志 —— 采集失败绝不能让 feed 端点跟着挂,
    /// 上一轮的数据还在库里,继续服务它就是了。
    /// </summary>
    public async Task<IReadOnlyList<CveAdvisory>> CollectAsync(CveOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!options.KevEnabled || string.IsNullOrWhiteSpace(options.KevUrl))
        {
            return [];
        }
        string json;
        try
        {
            using HttpResponseMessage response = await http.GetAsync(options.KevUrl, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                logger?.LogWarning("KEV 目录返回 {Status},本轮跳过。", (int)response.StatusCode);
                return [];
            }
            if (response.Content.Headers.ContentLength is > MaxResponseBytes)
            {
                logger?.LogWarning("KEV 目录超过 {Limit} 字节,本轮跳过。", MaxResponseBytes);
                return [];
            }
            json = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            logger?.LogWarning(ex, "拉取 KEV 目录失败,本轮跳过。");
            return [];
        }
        return Parse(json);
    }

    /// <summary>
    /// 解析 KEV 文档。单条不合法只跳过那一条 —— 上游偶尔会有字段缺失,
    /// 不该让一条坏数据把整批一千多条都废掉。
    /// </summary>
    public static IReadOnlyList<CveAdvisory> Parse(string json)
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
                !document.RootElement.TryGetProperty("vulnerabilities", out JsonElement list) ||
                list.ValueKind != JsonValueKind.Array)
            {
                return [];
            }
            List<CveAdvisory> result = [];
            foreach (JsonElement element in list.EnumerateArray())
            {
                if (ParseOne(element) is { } advisory)
                {
                    result.Add(advisory);
                }
            }
            return result;
        }
    }

    private static CveAdvisory? ParseOne(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            return null;
        }
        string? cveId = ReadString(element, "cveID");
        if (string.IsNullOrWhiteSpace(cveId))
        {
            return null;
        }
        string? vendor = ReadString(element, "vendorProject");
        string? product = ReadString(element, "product");
        string? name = ReadString(element, "vulnerabilityName");

        // 标题拼成「组件 — 一句话」:用户在 340px 宽的列表里先看到的是组件名,
        // 那才是他判断"这关不关我事"的依据,而不是 CVE 编号。
        string component = string.Join(' ', new[] { vendor, product }.Where(part => !string.IsNullOrWhiteSpace(part))).Trim();
        string title = string.IsNullOrWhiteSpace(component)
                           ? $"{cveId}: {name ?? "已知被利用的漏洞"}"
                           : $"{component} — {name ?? cveId}";
        return new()
        {
            Id = $"{CveSources.Kev}:{cveId}",
            CveId = cveId,
            Source = CveSources.Kev,
            Title = title,
            Summary = ReadString(element, "shortDescription"),
            KnownExploited = true,
            Products = [.. new[] { vendor, product }.OfType<string>().Where(part => part.Length > 0)],
            PublishedAt = ReadDate(element, "dateAdded") ?? DateTime.UtcNow,
            Url = $"https://nvd.nist.gov/vuln/detail/{Uri.EscapeDataString(cveId)}"
        };
    }

    private static string? ReadString(JsonElement element, string property) =>
        element.TryGetProperty(property, out JsonElement value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()?.Trim()
            : null;

    /// <summary>KEV 的 <c>dateAdded</c> 是 <c>yyyy-MM-dd</c>,按 UTC 当天零点算。</summary>
    private static DateTime? ReadDate(JsonElement element, string property) =>
        ReadString(element, property) is { Length: > 0 } text &&
        DateTime.TryParse(text, CultureInfo.InvariantCulture,
                          DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out DateTime parsed)
            ? parsed
            : null;
}
