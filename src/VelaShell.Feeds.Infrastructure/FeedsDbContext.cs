using MongoDB.Bson;
using MongoDB.Bson.Serialization;
using MongoDB.Bson.Serialization.Conventions;
using MongoDB.Driver;
using VelaShell.Feeds.Domain;

namespace VelaShell.Feeds.Infrastructure;

/// <summary>
/// MongoDB 访问入口。与插件市场共用同一个副本集,但**用自己的数据库**
/// (默认 <c>velashell-feeds</c>)—— 两套业务的集合混在一个库里,
/// 迁移、备份和权限收敛都会立刻变麻烦。
/// </summary>
public sealed class FeedsDbContext
{
    /// <summary>手工条目集合(公告与广告)。</summary>
    public const string EntriesCollection = "entries";

    /// <summary>漏洞公告集合(采集所得)。</summary>
    public const string AdvisoriesCollection = "advisories";

    private static int _conventionsRegistered;

    /// <summary>按连接串建立上下文,并确保索引与序列化约定就位。</summary>
    public FeedsDbContext(string connectionString)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        RegisterConventions();
        var url = new MongoUrl(connectionString);
        MongoClientSettings settings = MongoClientSettings.FromUrl(url);

        // 驱动默认要等 30 秒才认定"选不出服务器"。而 /feed.json 是**公开端点**:
        // 库一抖,每个客户端请求都挂满半分钟,连接就堆起来了。5 秒足够区分
        // "库慢一下"和"库没了",剩下的交给上层的降级逻辑。
        settings.ServerSelectionTimeout = TimeSpan.FromSeconds(5);
        settings.ConnectTimeout = TimeSpan.FromSeconds(5);
        var client = new MongoClient(settings);
        Database = client.GetDatabase(string.IsNullOrWhiteSpace(url.DatabaseName) ? "velashell-feeds" : url.DatabaseName);
        Entries = Database.GetCollection<FeedEntry>(EntriesCollection);
        Advisories = Database.GetCollection<CveAdvisory>(AdvisoriesCollection);
    }

    /// <summary>底层数据库句柄。</summary>
    public IMongoDatabase Database { get; }

    /// <summary>手工条目。</summary>
    public IMongoCollection<FeedEntry> Entries { get; }

    /// <summary>漏洞公告。</summary>
    public IMongoCollection<CveAdvisory> Advisories { get; }

    /// <summary>
    /// 建立查询要用的索引。启动时调用一次,幂等。
    /// </summary>
    public async Task EnsureIndexesAsync(CancellationToken cancellationToken = default)
    {
        // feed 端点每次都按「状态 + 发布时间」筛,这是唯一的热查询。
        await Entries.Indexes.CreateOneAsync(
            new CreateIndexModel<FeedEntry>(
                Builders<FeedEntry>.IndexKeys.Ascending(entry => entry.Status).Descending(entry => entry.PublishedAt)),
            cancellationToken: cancellationToken).ConfigureAwait(false);

        // 采集侧按 CveId 收敛,管理台按发布时间翻页。
        await Advisories.Indexes.CreateOneAsync(
            new CreateIndexModel<CveAdvisory>(Builders<CveAdvisory>.IndexKeys.Ascending(item => item.CveId)),
            cancellationToken: cancellationToken).ConfigureAwait(false);
        await Advisories.Indexes.CreateOneAsync(
            new CreateIndexModel<CveAdvisory>(Builders<CveAdvisory>.IndexKeys.Descending(item => item.PublishedAt)),
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// 注册全局序列化约定。
    /// <para>
    /// 驱动的约定注册表是**进程级**的,重复注册同名约定会抛;这里用 Interlocked 挡住
    /// 多次构造(测试里很容易发生)。
    /// </para>
    /// </summary>
    private static void RegisterConventions()
    {
        if (Interlocked.Exchange(ref _conventionsRegistered, 1) != 0)
        {
            return;
        }
        ConventionRegistry.Register("velashell-feeds", new ConventionPack
        {
            // 枚举按名字存:数字在库里没法读,加一个成员就可能把顺序改错。
            new EnumRepresentationConvention(BsonType.String),
            // 忽略文档里多出来的字段:老版本写入的字段被删掉后,新版本仍要能读回旧文档。
            new IgnoreExtraElementsConvention(true)
        }, _ => true);

        // 主键映射:两个实体的 Id 都是自定义字符串(不是 ObjectId)。
        BsonClassMap.TryRegisterClassMap<FeedEntry>(map =>
        {
            map.AutoMap();
            map.MapIdMember(entry => entry.Id);
        });
        BsonClassMap.TryRegisterClassMap<CveAdvisory>(map =>
        {
            map.AutoMap();
            map.MapIdMember(advisory => advisory.Id);
        });
    }
}
