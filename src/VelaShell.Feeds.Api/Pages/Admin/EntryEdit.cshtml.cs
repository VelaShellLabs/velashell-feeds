using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using MongoDB.Driver;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using VelaShell.Feeds.Api.Services;
using VelaShell.Feeds.Domain;
using VelaShell.Feeds.Infrastructure;

namespace VelaShell.Feeds.Api.Pages.Admin;

/// <summary>新建 / 编辑一条公告或广告。</summary>
public sealed class EntryEditModel(FeedsDbContext db, FeedCacheService feed) : PageModel
{
    /// <summary>表单数据。</summary>
    [BindProperty]
    public EntryForm Form { get; set; } = new();

    /// <summary>是否为编辑既有条目(决定标题与是否允许改 id)。</summary>
    public bool IsEdit { get; private set; }

    /// <summary>载入表单;<paramref name="id" /> 为空表示新建。</summary>
    public async Task<IActionResult> OnGetAsync(string? id, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(id))
        {
            // 新建时给一个带日期前缀的 id 建议:它是去重键,可读的 id 便于日后对账。
            Form.Id = $"{DateTime.UtcNow:yyyy-MM-dd}-";
            Form.PublishedAt = DateTime.UtcNow;
            return Page();
        }
        var entry = await db.Entries
            .Find(Builders<FeedEntry>.Filter.Eq(item => item.Id, id))
            .FirstOrDefaultAsync(cancellationToken);
        if (entry is null)
        {
            return NotFound();
        }
        IsEdit = true;
        Form = EntryForm.From(entry);
        return Page();
    }

    /// <summary>保存。</summary>
    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        IsEdit = await db.Entries
            .Find(Builders<FeedEntry>.Filter.Eq(item => item.Id, Form.Id))
            .AnyAsync(cancellationToken);
        Validate();
        if (!ModelState.IsValid)
        {
            return Page();
        }
        var now = DateTime.UtcNow;
        var subject = User.FindFirst("sub")?.Value ?? User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "unknown";
        var entry = Form.ToEntry();
        entry.UpdatedAt = now;

        // upsert 但保住创建信息:编辑一条广告不该把"谁在什么时候建的"改掉。
        await db.Entries.UpdateOneAsync(
            Builders<FeedEntry>.Filter.Eq(item => item.Id, entry.Id),
            Builders<FeedEntry>.Update
                .Set(item => item.Kind, entry.Kind)
                .Set(item => item.Severity, entry.Severity)
                .Set(item => item.Title, entry.Title)
                .Set(item => item.Body, entry.Body)
                .Set(item => item.LinkLabel, entry.LinkLabel)
                .Set(item => item.Url, entry.Url)
                .Set(item => item.CommandId, entry.CommandId)
                .Set(item => item.PublishedAt, entry.PublishedAt)
                .Set(item => item.ExpiresAt, entry.ExpiresAt)
                .Set(item => item.Targeting, entry.Targeting)
                .Set(item => item.Status, entry.Status)
                .Set(item => item.UpdatedAt, now)
                .SetOnInsert(item => item.CreatedAt, now)
                .SetOnInsert(item => item.CreatedBy, subject),
            new UpdateOptions { IsUpsert = true },
            cancellationToken);
        feed.Invalidate();
        return RedirectToPage("Entries");
    }

    /// <summary>
    /// 表单校验。这里挡住的都是**客户端会静默丢弃**的东西 ——
    /// 与其让管理员发完才发现链接点不动,不如在保存时就说清楚。
    /// </summary>
    private void Validate()
    {
        if (!string.IsNullOrWhiteSpace(Form.Url) &&
            !(Uri.TryCreate(Form.Url, UriKind.Absolute, out var parsed) && parsed.Scheme == Uri.UriSchemeHttps))
        {
            ModelState.AddModelError("Form.Url", "外链必须是 https —— 客户端会丢弃其它协议的链接，条目会变得点不动。");
        }
        if (Form.ExpiresAt is { } expires && expires <= Form.PublishedAt)
        {
            ModelState.AddModelError("Form.ExpiresAt", "下线时间要晚于发布时间，否则这条永远不会出现。");
        }
        if (Form.Kind == FeedKinds.Promotion && Form.Severity == FeedSeverities.Critical)
        {
            ModelState.AddModelError("Form.Severity",
                "运营消息不该用 critical：那个警示徽标是留给安全公告的，用它发促销会让用户不再相信这个信号。");
        }
        foreach (var version in new[] { Form.MinVersion, Form.MaxVersion })
        {
            if (!string.IsNullOrWhiteSpace(version) && !Version.TryParse(version.Trim(), out _))
            {
                ModelState.AddModelError("Form.MinVersion", $"版本号「{version}」解析不了，应形如 1.4.0。");
            }
        }
    }
}

/// <summary>投放表单。逗号分隔的定向字段在这里拆合,实体里存的是列表。</summary>
public sealed class EntryForm
{
    /// <summary>稳定标识,也是客户端的去重键。</summary>
    [Required(ErrorMessage = "id 不能为空 —— 它是客户端的去重与已读状态的键。")]
    [RegularExpression("^[A-Za-z0-9._:-]{3,120}$", ErrorMessage = "id 只能用字母、数字与 . _ : - ,长度 3–120。")]
    public string Id { get; set; } = "";

    /// <summary>种类。</summary>
    public string Kind { get; set; } = FeedKinds.News;

    /// <summary>严重程度。</summary>
    public string Severity { get; set; } = FeedSeverities.Info;

    /// <summary>标题。</summary>
    [Required(ErrorMessage = "标题不能为空。")]
    [StringLength(200, ErrorMessage = "标题超过 200 字符会被客户端截断。")]
    public string Title { get; set; } = "";

    /// <summary>正文。</summary>
    [StringLength(1000, ErrorMessage = "正文超过 1000 字符会被客户端截断。")]
    public string? Body { get; set; }

    /// <summary>动作文案。</summary>
    [StringLength(60)]
    public string? LinkLabel { get; set; }

    /// <summary>外链(必须 https)。</summary>
    public string? Url { get; set; }

    /// <summary>站内命令 id(优先于外链)。</summary>
    public string? CommandId { get; set; }

    /// <summary>发布时间(UTC)。</summary>
    public DateTime PublishedAt { get; set; } = DateTime.UtcNow;

    /// <summary>下线时间(UTC),留空表示不过期。</summary>
    public DateTime? ExpiresAt { get; set; }

    /// <summary>定向语言,逗号分隔。</summary>
    public string? Locales { get; set; }

    /// <summary>定向平台 RID,逗号分隔。</summary>
    public string? Platforms { get; set; }

    /// <summary>最低版本。</summary>
    public string? MinVersion { get; set; }

    /// <summary>最高版本。</summary>
    public string? MaxVersion { get; set; }

    /// <summary>发布状态。</summary>
    public EntryStatus Status { get; set; } = EntryStatus.Draft;

    /// <summary>从实体填表单。</summary>
    public static EntryForm From(FeedEntry entry) =>
        new()
        {
            Id = entry.Id,
            Kind = entry.Kind,
            Severity = entry.Severity,
            Title = entry.Title,
            Body = entry.Body,
            LinkLabel = entry.LinkLabel,
            Url = entry.Url,
            CommandId = entry.CommandId,
            PublishedAt = entry.PublishedAt,
            ExpiresAt = entry.ExpiresAt,
            Locales = string.Join(", ", entry.Targeting.Locales),
            Platforms = string.Join(", ", entry.Targeting.Platforms),
            MinVersion = entry.Targeting.MinVersion,
            MaxVersion = entry.Targeting.MaxVersion,
            Status = entry.Status
        };

    /// <summary>把表单变成实体。</summary>
    public FeedEntry ToEntry() =>
        new()
        {
            Id = Id.Trim(),
            Kind = Kind,
            Severity = Severity,
            Title = Title.Trim(),
            Body = Trim(Body),
            LinkLabel = Trim(LinkLabel),
            Url = Trim(Url),
            CommandId = Trim(CommandId),
            PublishedAt = PublishedAt,
            ExpiresAt = ExpiresAt,
            Status = Status,
            Targeting = new()
            {
                Locales = Split(Locales),
                Platforms = Split(Platforms),
                MinVersion = Trim(MinVersion),
                MaxVersion = Trim(MaxVersion)
            }
        };

    private static string? Trim(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static List<string> Split(string? value) =>
        string.IsNullOrWhiteSpace(value)
            ? []
            : [.. value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)];
}
