FROM openclaw/openclaw:latest AS base

# 安装 Python 依赖
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        python3 \
        python3-pip \
        python3-yaml \
        curl \
        && rm -rf /var/lib/apt/lists/*

# 安装 arsguard 插件
COPY --chown=openclaw:openclaw ../../src /arsguard/plugins
COPY --chown=openclaw:openclaw ../../config /arsguard/config

# 安装 Python 依赖
RUN pip3 install --no-cache-dir \
        pyyaml \
        jsonschema \
        aiohttp \
        rate-limiter

# 配置 OpenClaw 加载 arsguard 插件
ENV OPENCLAW_PLUGINS="/arsguard/plugins"
ENV ARSGUARD_CONFIG="/arsguard/config/arsguard.yaml"
ENV ARSGUARD_ENABLED="true"

# 健康检查
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

EXPOSE 8080

CMD ["openclaw", "--plugins-dir", "/arsguard/plugins"]
