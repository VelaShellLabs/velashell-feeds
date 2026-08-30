using VelaShell.Feeds.Domain;
using VelaShell.Feeds.Infrastructure.Cve;

namespace VelaShell.Feeds.Tests;

/// <summary>
/// 上游解析。用例里的 JSON 按 CISA / NVD 的真实响应结构裁剪而来 ——
/// 拿自己造的简化结构去测,只能证明"我的解析器认得我自己写的格式"。
/// </summary>
[TestClass]
public class CollectorTests
{
    /// <summary>KEV 的条目整条放行,并标记为在野被利用。</summary>
    [TestMethod]
    public void Kev_ParsesEntries()
    {
        const string json = """
        {
          "title": "CISA Catalog of Known Exploited Vulnerabilities",
          "vulnerabilities": [
            {
              "cveID": "CVE-2026-1234",
              "vendorProject": "OpenSSH",
              "product": "OpenSSH Server",
              "vulnerabilityName": "OpenSSH Remote Code Execution Vulnerability",
              "dateAdded": "2026-08-20",
              "shortDescription": "OpenSSH contains a flaw that allows remote code execution.",
              "requiredAction": "Apply mitigations per vendor instructions."
            }
          ]
        }
        """;

        IReadOnlyList<CveAdvisory> items = KevCollector.Parse(json);

        Assert.HasCount(1, items);
        CveAdvisory item = items[0];
        Assert.AreEqual("CVE-2026-1234", item.CveId);
        Assert.AreEqual($"{CveSources.Kev}:CVE-2026-1234", item.Id);
        Assert.IsTrue(item.KnownExploited, "进了 KEV 目录就意味着已观察到在野利用。");
        Assert.AreEqual(new DateTime(2026, 8, 20, 0, 0, 0, DateTimeKind.Utc), item.PublishedAt);
        Assert.Contains("OpenSSH", item.Title, StringComparison.Ordinal);
    }

    /// <summary>
    /// 标题以组件打头。用户在 340px 宽的列表里先看到的是组件名,
    /// 那才是他判断"这关不关我事"的依据,而不是 CVE 编号。
    /// </summary>
    [TestMethod]
    public void Kev_TitleLeadsWithComponent()
    {
        const string json = """
        { "vulnerabilities": [ {
            "cveID": "CVE-2026-5678",
            "vendorProject": "Linux",
            "product": "Kernel",
            "vulnerabilityName": "Use-After-Free",
            "dateAdded": "2026-08-01" } ] }
        """;

        Assert.StartsWith("Linux Kernel", KevCollector.Parse(json)[0].Title, StringComparison.Ordinal);
    }

    /// <summary>缺 cveID 的条目单独跳过,不影响同批其余条目。</summary>
    [TestMethod]
    public void Kev_SkipsBadEntriesOnly()
    {
        const string json = """
        { "vulnerabilities": [
            { "vendorProject": "X", "dateAdded": "2026-08-01" },
            "这一条不是对象",
            { "cveID": "CVE-2026-0001", "vendorProject": "Y", "product": "Z", "dateAdded": "2026-08-02" } ] }
        """;

        IReadOnlyList<CveAdvisory> items = KevCollector.Parse(json);

        Assert.HasCount(1, items);
        Assert.AreEqual("CVE-2026-0001", items[0].CveId);
    }

    /// <summary>结构不对时返回空,不抛 —— 上游改版不该让采集进程崩掉。</summary>
    [TestMethod]
    public void Kev_ReturnsEmptyForMalformed()
    {
        Assert.IsEmpty(KevCollector.Parse("不是 JSON"));
        Assert.IsEmpty(KevCollector.Parse("{}"));
        Assert.IsEmpty(KevCollector.Parse("""{"vulnerabilities":"不是数组"}"""));
    }

    /// <summary>NVD 取 CVSS v3.1 基础分与英文描述。</summary>
    [TestMethod]
    public void Nvd_ParsesScoreAndEnglishDescription()
    {
        const string json = """
        {
          "vulnerabilities": [
            {
              "cve": {
                "id": "CVE-2026-2222",
                "published": "2026-08-25T10:00:00.000",
                "descriptions": [
                  { "lang": "es", "value": "Descripcion en espanol" },
                  { "lang": "en", "value": "A heap overflow in the TLS handshake." }
                ],
                "metrics": {
                  "cvssMetricV31": [ { "cvssData": { "baseScore": 9.1 } } ]
                }
              }
            }
          ]
        }
        """;

        IReadOnlyList<CveAdvisory> items = NvdCollector.Parse(json, minCvss: 7.0);

        Assert.HasCount(1, items);
        Assert.AreEqual(9.1, items[0].CvssScore);
        Assert.AreEqual("A heap overflow in the TLS handshake.", items[0].Summary);
        Assert.IsFalse(items[0].KnownExploited, "NVD 不代表在野被利用。");
    }

    /// <summary>低于阈值的直接不入库,别让噪音先进来再想办法过滤。</summary>
    [TestMethod]
    public void Nvd_FiltersByScore()
    {
        const string json = """
        { "vulnerabilities": [
            { "cve": { "id": "CVE-2026-3333", "published": "2026-08-25T10:00:00.000",
                       "metrics": { "cvssMetricV31": [ { "cvssData": { "baseScore": 4.2 } } ] } } } ] }
        """;

        Assert.IsEmpty(NvdCollector.Parse(json, minCvss: 7.0));
    }

    /// <summary>没有 v3.1 时退到 v3.0,再退到 v2。</summary>
    [TestMethod]
    public void Nvd_FallsBackAcrossCvssVersions()
    {
        const string json = """
        { "vulnerabilities": [
            { "cve": { "id": "CVE-2026-4444", "published": "2026-08-25T10:00:00.000",
                       "metrics": { "cvssMetricV2": [ { "cvssData": { "baseScore": 8.3 } } ] } } } ] }
        """;

        Assert.AreEqual(8.3, NvdCollector.Parse(json, minCvss: 7.0)[0].CvssScore);
    }

    /// <summary>
    /// 读不出分数的一并跳过:没有分数就没法判断轻重,而这条路径存在的意义正是"只推够重的"。
    /// 真正紧急的会从 KEV 那条路进来,不会漏。
    /// </summary>
    [TestMethod]
    public void Nvd_SkipsEntriesWithoutScore()
    {
        const string json = """
        { "vulnerabilities": [
            { "cve": { "id": "CVE-2026-5555", "published": "2026-08-25T10:00:00.000", "metrics": {} } } ] }
        """;

        Assert.IsEmpty(NvdCollector.Parse(json, minCvss: 0));
    }

    /// <summary>结构不对时返回空。</summary>
    [TestMethod]
    public void Nvd_ReturnsEmptyForMalformed()
    {
        Assert.IsEmpty(NvdCollector.Parse("不是 JSON", 7.0));
        Assert.IsEmpty(NvdCollector.Parse("{}", 7.0));
    }
}
