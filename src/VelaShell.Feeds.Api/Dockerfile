# VelaShell 资讯服务的镜像。构建上下文是**仓库根目录**（要用到根上的
# Directory.Build.props / Directory.Packages.props / global.json）：
#     docker build -f src/VelaShell.Feeds.Api/Dockerfile -t velashell-feeds/api:latest .
#
# ⚠️ 运行时基础镜像走 nightly 仓库。.NET 11 仍是 preview，正式仓库下**没有**
#    mcr.microsoft.com/dotnet/aspnet:11.0-preview 这个标签（VS 自动生成的 Dockerfile
#    默认填的就是它，构建会在最后一步 pull 失败）。等 .NET 11 GA 后可以换回正式仓库。

# 运行期。单独成一个 base 阶段是 VS 容器工具的约定：Fast 模式（F5 调试）只构建到这里。
FROM mcr.microsoft.com/dotnet/nightly/aspnet:11.0-preview AS base
WORKDIR /app
EXPOSE 8080
# 不用 root 跑：这个服务对外暴露一个公开端点，没有任何理由让它有写系统的能力。
USER $APP_UID

FROM mcr.microsoft.com/dotnet/nightly/sdk:11.0-preview AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
# 先只拷 csproj 与构建属性，让 restore 这一层能被缓存 —— 改代码不改依赖时不必重新 restore。
# global.json 锁定 SDK 版本，跟着一起拷，保证容器里用的与本地是同一个。
COPY ["global.json", "Directory.Packages.props", "Directory.Build.props", "./"]
COPY ["src/VelaShell.Feeds.Api/VelaShell.Feeds.Api.csproj", "src/VelaShell.Feeds.Api/"]
COPY ["src/VelaShell.Feeds.Domain/VelaShell.Feeds.Domain.csproj", "src/VelaShell.Feeds.Domain/"]
COPY ["src/VelaShell.Feeds.Infrastructure/VelaShell.Feeds.Infrastructure.csproj", "src/VelaShell.Feeds.Infrastructure/"]
RUN dotnet restore "src/VelaShell.Feeds.Api/VelaShell.Feeds.Api.csproj"

COPY . .
RUN dotnet publish "src/VelaShell.Feeds.Api/VelaShell.Feeds.Api.csproj" \
    -c $BUILD_CONFIGURATION -o /app/publish --no-restore /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "VelaShell.Feeds.Api.dll"]
