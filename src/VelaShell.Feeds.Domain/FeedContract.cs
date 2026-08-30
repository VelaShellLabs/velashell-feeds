using System.Text.Json.Serialization;

namespace VelaShell.Feeds.Domain;

/// <summary>
/// 下发给 VelaShell 客户端的资讯源文档。
/// <para>
/// <b>这是对外契约,字段名一经发布就不能改。</b> 客户端那侧的解析器是
/// <c>VelaShell.Core/Notifications/AnnouncementFeedDocument</c>,它按名字取值、
/// 认不得的字段一律忽略 —— 所以加能力只能加可选字段,改名等于让所有老客户端瞎掉。
/// </para>
/// </summary>
public sealed class FeedDocument
{
    /// <summary>契约版本,当前恒为 1。</summary>
    [JsonPropertyName("schema")]
    public int Schema { get; init; } = 1;

    /// <summary>条目列表。客户端**单次最多接受 100 条**,超出会被它截断。</summary>
    [JsonPropertyName("items")]
    public required IReadOnlyList<FeedItem> Items { get; init; }
}

/// <summary>资讯源里的一条。空字段一律省略,别给客户端塞一堆 null。</summary>
[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
public sealed class FeedItem
{
    /// <summary>
    /// 稳定标识,**去重与已读状态的键**。
    /// <para>
    /// 客户端见过同一个 id 就跳过,并保住用户的已读状态。因此:同一条内容改了标题也要沿用旧 id
    /// (否则会重新亮起未读打扰用户);确实是新事件才换新 id。
    /// </para>
    /// </summary>
    [JsonPropertyName("id")]
    public required string Id { get; init; }

    /// <summary>种类:<c>news</c> / <c>update</c> / <c>security</c> / <c>promotion</c>。</summary>
    [JsonPropertyName("kind")]
    public required string Kind { get; init; }

    /// <summary>轻重:<c>info</c> / <c>warning</c> / <c>critical</c>。</summary>
    [JsonPropertyName("severity")]
    public string Severity { get; init; } = "info";

    /// <summary>标题。客户端超过 200 字符会截断。</summary>
    [JsonPropertyName("title")]
    public required string Title { get; init; }

    /// <summary>正文。客户端超过 1000 字符会截断,列表里只显示两行。</summary>
    [JsonPropertyName("body")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Body { get; init; }

    /// <summary>发布时间(UTC)。客户端按它倒序,不是按收到的时间。</summary>
    [JsonPropertyName("publishedAt")]
    public required DateTime PublishedAt { get; init; }

    /// <summary>过期时间(UTC);到点后客户端不再展示,并在下次载入时清掉。</summary>
    [JsonPropertyName("expiresAt")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DateTime? ExpiresAt { get; init; }

    /// <summary>动作文案。不给则客户端按去处兜底为「查看」/「阅读全文」。</summary>
    [JsonPropertyName("linkLabel")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? LinkLabel { get; init; }

    /// <summary>外链,**必须 https**。客户端会丢弃其它协议的链接。</summary>
    [JsonPropertyName("url")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Url { get; init; }

    /// <summary>站内命令 id,优先于 <see cref="Url" />。</summary>
    [JsonPropertyName("commandId")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? CommandId { get; init; }

    /// <summary>定向:界面语言。空/省略 = 不限。</summary>
    [JsonPropertyName("locales")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? Locales { get; init; }

    /// <summary>定向:运行平台 RID。空/省略 = 不限。</summary>
    [JsonPropertyName("platforms")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? Platforms { get; init; }

    /// <summary>定向:最低版本(含)。</summary>
    [JsonPropertyName("minVersion")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? MinVersion { get; init; }

    /// <summary>定向:最高版本(含)。</summary>
    [JsonPropertyName("maxVersion")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? MaxVersion { get; init; }
}

/// <summary>客户端契约里的常量,避免各处散落字符串字面量。</summary>
public static class FeedKinds
{
    /// <summary>产品资讯、公告。</summary>
    public const string News = "news";

    /// <summary>版本更新。</summary>
    public const string Update = "update";

    /// <summary>安全资讯(漏洞公告一类)。</summary>
    public const string Security = "security";

    /// <summary>运营/推广。**用户可以在客户端关掉这一类**,到达率不是 100%。</summary>
    public const string Promotion = "promotion";
}

/// <summary>严重程度常量。</summary>
public static class FeedSeverities
{
    /// <summary>一般信息。</summary>
    public const string Info = "info";

    /// <summary>需要留意,客户端用警示色徽标。</summary>
    public const string Warning = "warning";

    /// <summary>需要尽快处理,客户端用警示色徽标。</summary>
    public const string Critical = "critical";
}
