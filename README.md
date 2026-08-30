# VelaShell 资讯服务(velashell-feeds)

给 [VelaShell](../VelaShell) 客户端消息中心供稿的服务:**聚合漏洞情报 + 投放公告与广告**,
汇成一份 JSON 挂在 <https://feeds.easilynet.top/feed.json>。

```
CISA KEV ──┐
           ├──▶ 采集(每 6h) ──▶ MongoDB ──┐
NVD(按关键词)─┘                            ├──▶ /feed.json ──▶ VelaShell 消息中心
                                          │
管理台(公告 / 广告)────────────────────────┘
```

客户端那侧的契约与行为见 velashell-docs 的
[`zh/host/消息中心与资讯源.md`](https://github.com/VelaShellLabs/velashell-docs/blob/main/zh/host/消息中心与资讯源.md)。

## 跑起来

前置:[velashell-identity](https://github.com/joesdu/velashell-identity) 的认证服务、
以及 velashell-markets 的 MongoDB 已经在跑(本服务复用它们)。

```powershell
cp .env.example .env      # 至少填 IDENTITY_ISSUER 与 MONGO_ROOT_PASSWORD
dotnet run --project src/VelaShell.Feeds.Api
```

```bash
dotnet build VelaShell.Feeds.slnx
dotnet test  VelaShell.Feeds.slnx
```

| 地址 | 说明 |
| --- | --- |
| `/feed.json` | **公开**。客户端拉的就是它,带 ETag 与 5 分钟缓存 |
| `/admin` | 管理台,仅白名单内的管理员可进 |
| `/healthz` | 存活探测 |

## 选源:为什么只收这两路

**信号质量比覆盖率重要。** NVD 一天新增几百条 CVE,全量推给终端工具的用户,
结果只有一个 —— 他第二天就把资讯源关了。所以默认只收:

| 源 | 收什么 | 为什么 |
| --- | --- | --- |
| **CISA KEV** | 整条放行 | 能进这个目录的前提是**已观察到在野利用**。总量千余条、每次新增个位数,每一条都意味着"现在就有人在打这个洞" |
| **NVD** | 关键词 + CVSS ≥ 7.0 | 运维关心的是 OpenSSH、sudo、OpenSSL 这些天天在用的东西,不是某个 CMS 插件的漏洞。关键词表在 `Cve:NvdKeywords`,默认十五个常用组件 |

在野被利用的**不看分数直接放行**:CVSS 9.8 而无人利用,远不如 7.5 但正在被打的紧急。

噪音在管理台「漏洞公告」里屏蔽。屏蔽只是不进 feed,采集器照抓照存 ——
否则下一轮采集会把它原样带回来。

## 接入统一认证

本服务是**依赖方**:不存口令、不发令牌,登录整个交给
[velashell-identity](https://github.com/joesdu/velashell-identity) 的认证服务,
走授权码 + PKCE,拿回身份后自己判断是不是管理员。

### 为什么复用那套开放注册的认证服务是安全的

认证与授权是两件事,市场那边早就把它们分开了:

> 审核员的身份主体(`sub`)列表。**市场的管理员是市场自己的概念,不要求认证服务为我们维护一套角色声明。**
> —— `MarketAuthOptions`

认证服务只回答"你是 `sub=xxx`";"你能不能进这个后台"由本服务的 `Auth:AdminSubjects` 白名单回答。
任何人都能去注册、都能拿到令牌,但**拿不到这里的准入**。

三处加固:

| 加固 | 为什么 |
| --- | --- |
| 独立 scope `velashell-feeds` | 不复用 `velashell-market`。令牌不该跨服务通用 —— 市场用户的令牌根本不该能打到这里 |
| 独立客户端 `velashell-feeds-admin` | 回跳地址锁死在本服务域名,防止拿市场的客户端换码 |
| 白名单 **fail-closed** | `AdminSubjects` 为空时谁都进不去。一个还没配置好的服务如果默认放行,等于把广告投放交给第一个找到它的人 |

也**不需要**在认证服务里加 role claim:为几个管理员建一套角色管理是过度设计。
将来真要细分权限(比如"广告运营"不能碰 CVE),在本服务加张角色表即可,仍然不用动认证服务。

### 要在认证服务那边加的两行

在 **velashell-identity** 的 `docker-compose.yml` 里,给 identity 服务补上
(那份 compose 里已经预置了这一组,通常只需确认 `FEEDS_ORIGIN` 与密钥):

```yaml
# 新的 API 资源(scope)。索引接着已有的往后排。
- Identity__Scopes__1__Name=velashell-feeds
- Identity__Scopes__1__Resources__0=velashell-feeds
# 资讯服务的管理台客户端。
- Identity__Clients__1__ClientId=velashell-feeds-admin
- Identity__Clients__1__DisplayName=VelaShell 资讯服务
- Identity__Clients__1__ClientSecret=${FEEDS_CLIENT_SECRET}
- Identity__Clients__1__RedirectUris__0=https://feeds.easilynet.top/signin-oidc
- Identity__Clients__1__PostLogoutRedirectUris__0=https://feeds.easilynet.top/
- Identity__Clients__1__Scopes__0=velashell-feeds
```

客户端与 scope 不需要手工写库:认证服务每次启动都按配置覆盖进 MongoDB,
所以"改配置 → 重启"是唯一的管理方式。

### 拿到自己的 sub

用管理员账号登录一次 `/admin`。因为白名单还是空的,你会被挡在
「没有权限」页 —— **那一页会把你的 `sub` 显示出来**,复制进 `.env` 的
`ADMIN_SUBJECT_0` 再重启即可。

## 部署到 feeds.easilynet.top

```powershell
cp .env.example .env
# 填 IDENTITY_ISSUER / MONGO_ROOT_PASSWORD / FEEDS_CLIENT_SECRET / ADMIN_SUBJECT_0
docker compose up -d --build
```

反代(Nginx / Caddy)把 `https://feeds.easilynet.top` 指到容器的 `7030`,并透传
`X-Forwarded-Proto` —— 容器里已开 `ASPNETCORE_FORWARDEDHEADERS_ENABLED`,
不透传的话 OIDC 回跳会拼出 `http://` 的地址,登录会失败。

生产上 `REQUIRE_HTTPS=true` 必须保持开启。

## 投放前值得知道的

- **广告用户可以关掉。** 客户端有「接收运营消息」开关,关掉后 `promotion` 类条目在客户端被丢弃。
  到达率不是 100%,这是有意留的开关。
- **定向在客户端算。** 语言 / 平台 / 版本区间随条目下发,由客户端自己筛。请求里没有版本号、
  平台、语言或任何设备标识 —— 服务端做不了用户级个性化,也拿不到曝光与点击数据。
  要统计转化,给落地页链接带 UTM 参数。
- **`id` 决定要不要重新打扰用户。** 客户端见过同一个 id 就跳过并保住已读状态。
  改标题请沿用旧 id;确实是新事件才换新 id。
- **别拿 `critical` 发广告。** 那个警示徽标是留给安全公告的,用它发促销会让用户不再相信这个信号。
  管理台在保存时会直接拦下这种组合。

## 结构

```
src/
  VelaShell.Feeds.Domain/          契约模型、实体、组装规则(纯逻辑,无依赖)
  VelaShell.Feeds.Infrastructure/  MongoDB、KEV/NVD 采集器、后台采集任务
  VelaShell.Feeds.Api/             /feed.json、OIDC 登录、Razor Pages 管理台
tests/
  VelaShell.Feeds.Tests/           组装规则与上游解析
```

管理台用 Razor Pages 而不是再起一个 SPA:它只有管理员会看到,
服务端渲染 + cookie 会话比"前端拿令牌调 API"少一整套令牌保管的问题。
