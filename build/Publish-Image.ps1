#!/usr/bin/env pwsh
<#
.SYNOPSIS
    产出资讯服务的容器镜像,按需导出成 tar.gz 或推到镜像仓库。

.DESCRIPTION
    本仓库**没有 Dockerfile** —— 镜像由 .NET SDK 的容器发布直接产出
    (`dotnet publish -t:PublishContainer`)。镜像的基础镜像、非 root 用户与暴露端口
    全部写在 src/VelaShell.Feeds.Api/VelaShell.Feeds.Api.csproj 的「容器」段里,
    这个脚本只负责调用它,不重复定义任何一项。

    三种去向,可以任意组合:

      (默认)      推本机 Docker → `docker compose up -d` 直接可用
      -Archive     写成 <OutputDir>/velashell-feeds.tar.gz → 目标机 `docker load -i`
      -Push        推到 -Registry(默认 harbor.easilynet.top),推之前自己先 `docker login`

    三者在 SDK 那边是互斥的(给了归档路径就只写归档、给了仓库就只推远端),所以要几个
    去向就跑几趟发布 —— 编译只发生在第一趟,后面是增量命中,只多花打层/传输的时间。

    ⚠️ 别用 `docker save` 去导这个镜像 —— 能导,但 SDK 已经会直接写 tar.gz,
    多绕一层还得先有个跑着的 Docker 守护进程。-Archive 连守护进程都不需要。

.PARAMETER Tag
    镜像标签,默认 latest。想并存多个版本时才传,例如 -Tag 2026-09-11。

.PARAMETER Repository
    镜像名,默认 velashell/feeds —— 与 csproj 的 ContainerRepository、
    docker-compose.yml 的 image: 三处一致,改一处就要三处一起改。
    第一段 velashell 是 **Harbor 上的项目名**:Harbor 只认已经建好的项目,
    单段名字或者项目不存在都会在推送时被拒,且它不会自动建项目。

.PARAMETER OutputDir
    -Archive 的产物目录。默认是本脚本所在的 build/ —— 不写死任何盘符,换台机器照样跑。

.PARAMETER Registry
    镜像仓库地址,默认 harbor.easilynet.top。它只是个默认值 —— **不给 -Push 就不会推**。
    推之前先 `docker login harbor.easilynet.top` —— SDK 读的是同一份 ~/.docker/config.json。

.PARAMETER Push
    推到 -Registry。最终地址是 <Registry>/<Repository>:<Tag>,即默认
    harbor.easilynet.top/velashell/feeds:latest。

.PARAMETER Archive
    导出 tar.gz。这条路不需要 Docker 守护进程。

.PARAMETER SkipLocal
    不推本机镜像库。与 -Archive 或 -Push 搭配,用在没装 Docker、只负责出包的机器上。

.PARAMETER Configuration
    编译配置,默认 Release。

.EXAMPLE
    pwsh ./build/Publish-Image.ps1
    出一个 velashell/feeds:latest 进 Docker,接着 docker compose up -d 就行。

.EXAMPLE
    pwsh ./build/Publish-Image.ps1 -Push
    构建并推到 harbor.easilynet.top/velashell/feeds:latest,同时在本机留一份。
    先 `docker login harbor.easilynet.top`。

.EXAMPLE
    pwsh ./build/Publish-Image.ps1 -Push -Tag 2026-09-12 -SkipLocal
    只往 Harbor 推一个带日期的版本,本机不留。

.EXAMPLE
    pwsh ./build/Publish-Image.ps1 -Archive
    本机镜像照出,另外在 build/ 下留一个 velashell-feeds.tar.gz。

.EXAMPLE
    pwsh ./build/Publish-Image.ps1 -Archive -SkipLocal -OutputDir Z:\velashell-feeds
    只出包,直接落到已挂载的共享目录。目标机上:
        docker load -i velashell-feeds.tar.gz
        docker compose up -d

.EXAMPLE
    pwsh ./build/Publish-Image.ps1 -Push -Registry harbor.other.example.com
    推到另一个仓库。项目名(Repository 的第一段)在那边也得先建好。
#>
[CmdletBinding()]
param(
    [string]$Tag = 'latest',

    [string]$Repository = 'velashell/feeds',

    [string]$OutputDir = $PSScriptRoot,

    [string]$Registry = 'harbor.easilynet.top',

    [switch]$Push,

    [switch]$Archive,

    [switch]$SkipLocal,

    [string]$Configuration = 'Release'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# 各版本 pwsh 对"原生命令写了 stderr 算不算错"的默认值不一样,统一关掉,
# 下面一律以退出码为准 —— dotnet 的还原进度本来就走 stderr,不关会假报错。
$PSNativeCommandUseErrorActionPreference = $false

$RepoRoot = Split-Path -Parent $PSScriptRoot
$Project = Join-Path $RepoRoot 'src/VelaShell.Feeds.Api/VelaShell.Feeds.Api.csproj'

if ($SkipLocal -and -not ($Archive -or $Push)) {
    throw '-SkipLocal 又不 -Archive、也不 -Push,那就什么都不会产出。'
}

# Registry 有默认值,所以"推不推"只看 -Push —— 否则每次本机发布都会顺手推一趟 Harbor。
if ($Push -and -not $Registry) { throw '-Push 了但 -Registry 是空的。' }

function Invoke-Native {
    <# 跑外部命令,退出码非 0 就抛。输出直接透到当前控制台,不做缓冲。 #>
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Arguments
    )
    Push-Location $RepoRoot
    try {
        Write-Verbose "> $FilePath $($Arguments -join ' ')"
        & $FilePath @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "$FilePath $($Arguments -join ' ') 失败(退出码 $LASTEXITCODE)"
        }
    }
    finally {
        Pop-Location
    }
}

function Format-Size {
    param([long]$Bytes)
    if ($Bytes -ge 1GB) { return '{0:N2} GB' -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return '{0:N1} MB' -f ($Bytes / 1MB) }
    return '{0:N0} KB' -f ($Bytes / 1KB)
}

function Write-Step {
    param([string]$Message)
    Write-Host ''
    Write-Host "==> $Message" -ForegroundColor Cyan
}

# ---------------------------------------------------------------- 前置检查

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw '找不到 dotnet。镜像是 SDK 直接出的,没有 Dockerfile 可以退而求其次。'
}
if (-not (Test-Path $Project)) { throw "找不到工程:$Project" }

if (-not $SkipLocal) {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw '找不到 docker。只想出包的话加 -Archive -SkipLocal,那条路不需要守护进程。'
    }
    docker info --format '{{.ServerVersion}}' *> $null
    if ($LASTEXITCODE -ne 0) {
        throw 'docker 守护进程没响应,先把 Docker Desktop 起起来(或者用 -Archive -SkipLocal)。'
    }
}

# 镜像里留个来路标记,目标机上 `docker inspect` 能查到是哪次构建的。
# created 那条标签 SDK 自动会打;source / revision 两条要 PublishRepositoryUrl=true
# 才放行 —— SDK 把它当作"作者同意把仓库信息写进产物"的显式开关,不给就静默不打。
$commit = ''
if (Get-Command git -ErrorAction SilentlyContinue) {
    $commit = (git -C $RepoRoot rev-parse --short HEAD 2>$null)
    if ($LASTEXITCODE -ne 0) { $commit = '' }
    elseif ((git -C $RepoRoot status --porcelain 2>$null)) { $commit = "$commit-dirty" }
}

function Publish-Image {
    param([string]$ExtraProperty)
    $publishArgs = @(
        'publish', $Project,
        '-c', $Configuration,
        '-t:PublishContainer',
        '--nologo',
        "-p:ContainerRepository=$Repository",
        "-p:ContainerImageTag=$Tag"
    )
    if ($commit) { $publishArgs += @('-p:PublishRepositoryUrl=true', "-p:SourceRevisionId=$commit") }
    if ($ExtraProperty) { $publishArgs += $ExtraProperty }
    Invoke-Native -FilePath 'dotnet' -Arguments $publishArgs
}

$destinations = @()
if (-not $SkipLocal) { $destinations += '本机 Docker' }
if ($Archive) { $destinations += "tar.gz -> $OutputDir" }
if ($Push) { $destinations += "仓库 -> $Registry" }

Write-Host ''
Write-Host 'VelaShell 资讯服务 · 镜像发布' -ForegroundColor Green
Write-Host "  仓库    $RepoRoot$(if ($commit) { "  ($commit)" })"
Write-Host "  镜像    ${Repository}:$Tag"
Write-Host "  去向    $($destinations -join ' / ')"

# ---------------------------------------------------------------- 一、本机镜像库

if (-not $SkipLocal) {
    Write-Step "发布到本机 Docker(${Repository}:$Tag)"
    # LocalRegistry=Docker 钉在 csproj 里:这台机器上除了 Docker Desktop 还有 WSL 的
    # 容器存储,让 SDK 自己探测会挑中后者,镜像就进了 `docker images` 看不见的地方。
    Publish-Image
}

# ---------------------------------------------------------------- 二、导出

$archivePath = $null
if ($Archive) {
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }
    $OutputDir = (Resolve-Path $OutputDir).Path
    Write-Step "导出 tar.gz -> $OutputDir"

    # SDK 按镜像名建目录:两段式的 velashell/feeds 会落成 <dir>/velashell/feeds.tar.gz。
    # 目标机上要的是扁平文件名,所以先导到临时目录再搬平。
    $staging = Join-Path ([System.IO.Path]::GetTempPath()) ('vela-img-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $staging -Force | Out-Null
    try {
        Publish-Image -ExtraProperty "-p:ContainerArchiveOutputPath=$staging"
        $produced = Get-ChildItem -Path $staging -Recurse -File -Filter '*.tar.gz' | Select-Object -First 1
        if (-not $produced) { throw "SDK 说导出成功,但 $staging 下没有 .tar.gz。" }
        $archivePath = Join-Path $OutputDir 'velashell-feeds.tar.gz'
        Move-Item -LiteralPath $produced.FullName -Destination $archivePath -Force
    }
    finally {
        Remove-Item -Recurse -Force $staging -ErrorAction SilentlyContinue
    }

    # -Force 不能省:SMB 共享会给新建的文件打上隐藏属性,不加就是 "Could not find item",
    # 而文件其实好好地在那儿。
    Write-Host "   $(Format-Size (Get-Item -LiteralPath $archivePath -Force).Length)" -ForegroundColor DarkGray
}

# ---------------------------------------------------------------- 三、推仓库

$pushed = $null
if ($Push) {
    $registryHost = $Registry.TrimEnd('/')
    $pushed = "$registryHost/${Repository}:$Tag"
    Write-Step "推送 -> $pushed"
    if ($Repository -notmatch '/') {
        Write-Host '   注意:镜像名是单段的。Harbor 要求第一段是已建好的项目名,会拒收 —— 见 -Repository 的说明。' -ForegroundColor Yellow
    }
    Publish-Image -ExtraProperty "-p:ContainerRegistry=$registryHost"
}

# ---------------------------------------------------------------- 收尾

Write-Host ''
Write-Host '完成' -ForegroundColor Green

if (-not $SkipLocal) {
    Write-Host '本机起服务:'
    Write-Host '  docker compose up -d'
}
if ($archivePath) {
    Write-Host "产物:$archivePath" -ForegroundColor Yellow
    Write-Host '复制到目标机之后:'
    Write-Host '  docker load -i velashell-feeds.tar.gz'
    Write-Host '  docker compose up -d'
}
if ($pushed) {
    Write-Host "已推送:$pushed" -ForegroundColor Yellow
    Write-Host '目标机上(.env 里写 FEEDS_IMAGE,compose 默认值是本机镜像名):'
    Write-Host "  FEEDS_IMAGE=$pushed"
    Write-Host '  docker compose pull && docker compose up -d'
}
