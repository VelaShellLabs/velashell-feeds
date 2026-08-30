# AGENTS.md

> 给 AI 代理与新加入者的操作约定。**动手之前先读完本文件,以及它指向的文档。**

## 一、开工前必读:velashell-docs

VelaShell 生态的**全部文档**集中在一个仓库:
**[VelaShellLabs/velashell-docs](https://github.com/VelaShellLabs/velashell-docs)**。
本仓库**不放** `docs/`、`docs-en/` —— 设计手册、开发规范与开发文档都在那边。

**在动任何代码之前**,先把下表中与你要改的部分相关的几篇读掉。跳过这一步直接改,
结果通常是两种:与既有设计冲突,或者重复实现一个已经存在的能力。

| 位置 | 内容 |
| --- | --- |
| [`zh/host/`](https://github.com/VelaShellLabs/velashell-docs/tree/main/zh/host) | 宿主分层架构与依赖方向、工程化重构蓝图、交互与界面规格、快捷键参考、设置项审计,以及 SFTP / FTP / Telnet / 串口 / Redis / S3 / 系统密钥链等可行性调研 |
| [`zh/plugins/`](https://github.com/VelaShellLabs/velashell-docs/tree/main/zh/plugins) | 插件系统设计蓝图 01–15(进程模型、IPC 协议、权限系统、UI 扩展、威胁模型、路线图)与[进度总览 STATUS](https://github.com/VelaShellLabs/velashell-docs/blob/main/zh/plugins/STATUS.md) |
| [`zh/sdk/`](https://github.com/VelaShellLabs/velashell-docs/tree/main/zh/sdk) | 插件契约 SDK 参考、SDK 仓库的发版流程 |
| [`zh/cli/`](https://github.com/VelaShellLabs/velashell-docs/tree/main/zh/cli) | `vela-plugin` 命令行手册、CLI 仓库的发版流程 |
| [`zh/templates/`](https://github.com/VelaShellLabs/velashell-docs/tree/main/zh/templates) | 插件开发指南、打包与发布、模板仓库的发版流程 |

英文镜像在 [`en/`](https://github.com/VelaShellLabs/velashell-docs/tree/main/en),与 `zh/` 同构。
[仓库首页](https://github.com/VelaShellLabs/velashell-docs)有按「我想做什么」组织的快速入口表。

## 二、涉及文档的改动一律同步到 velashell-docs

**这是本文件最重要的一条。**

- 本仓库里**不新建** `docs/`、`docs-en/` 或任何成体系的文档目录。要写文档,去 velashell-docs 开 PR。
- 改了代码,而**行为、接口、配置项、命令行、构建流程或版本纪律**与现有文档对不上时,
  必须**同时**在 velashell-docs 提一个 PR 把文档改过来。两个 PR 在正文里互相引用,一起合。
  只改代码不改文档,等于让文档开始骗人 —— 而文档是别人照抄的。
- velashell-docs 的 `zh/` 与 `en/` 是**互为镜像**的两棵树,文件一一对应。改了中文就要改英文,
  反之亦然。漏一边,两棵树就开始漂。
- velashell-docs 内部的互相引用**一律走相对路径**(如 `../templates/dev-guide.md`),
  不要写回 GitHub 绝对 URL —— 文档集中到一个仓库,消掉的正是那种一改路径就断的跨仓库链接。
- **例外**:留在代码仓库里的少数几份文件不适用上述规则,因为它们服务的是「在这个仓库里写代码」
  这件事,搬走只会离使用场景更远。各仓库的例外清单见下面第三节。


## 三、本仓库:velashell-feeds(资讯服务)

给 VelaShell 客户端消息中心供稿:聚合漏洞情报(CISA KEV + NVD)、投放公告与广告,
汇成一份 JSON 挂在 <https://feeds.easilynet.top/feed.json>。

### 跑起来

```bash
dotnet build VelaShell.Feeds.slnx
dotnet test  VelaShell.Feeds.slnx
```

前置:velashell-identity 的认证服务与 velashell-markets 的 MongoDB 已经在跑 —— 本服务复用它们,
自己不起数据库也不发令牌。完整说明见 [README.md](README.md)。

### 几条会让你踩坑的硬约束

- **`/feed.json` 的字段是对外契约**,客户端(`VelaShell.Core/Notifications/AnnouncementFeedDocument`)
  按名字取值。字段一经发布不能改名,加能力只能加**可选**字段 —— 改名等于让所有老客户端瞎掉。
  `FeedContract.cs` 顶上写着这条,改之前先读。
- **管理员白名单 fail-closed**:`Auth:AdminSubjects` 为空时管理台谁都进不去。
  任何"为了方便先默认放行"的改动都是在把广告投放交给第一个找到这个域名的人。
- **不复用市场的 scope 与客户端**:feeds 有自己的 `velashell-feeds` scope 与
  `velashell-feeds-admin` 客户端。令牌不该跨服务通用。
- **屏蔽 CVE 不等于删除**:采集是 upsert 且**只更新会变的字段**,
  `IsSuppressed` / `SuppressedReason` 是管理员的决定,不能被下一轮采集覆盖回去。
  改 `CveCollectionService.UpsertAsync` 时别图省事换成整文档替换。
- **手工条目不与 CVE 抢额度**:`FeedComposer` 给 CVE 单独设了配额,
  否则上游某天批量发布就会把管理员精心投放的公告整个挤出 feed。
- **选源看信号质量,不是覆盖率**:NVD 一天几百条,全推给用户等于让他关掉资讯源。
  在野被利用的(KEV)不看分数直接放行;普通 CVE 按关键词 + CVSS 阈值收。

### 留在本仓库的文档

`README.md`、`AGENTS.md`。面向用户的行为说明在 velashell-docs 的
`zh|en/host/消息中心与资讯源.md`(客户端侧)—— 本服务的字段契约与它是同一份东西,
改了要一起改。
