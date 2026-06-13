FROM alpine/openclaw:latest

USER root

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        python3-pip \
        python3-yaml \
        python3-jsonschema \
        curl \
        && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir --break-system-packages --default-timeout=120 \
        aiohttp \
        rate-limiter

# Create OpenClaw config for node user (uid 1000, matches mounted plugin ownership)
RUN mkdir -p /home/node/.openclaw && \
    echo '{"plugins":{"load":{"paths":["/arsguard/plugins"]}}}' > /home/node/.openclaw/openclaw.json && \
    chown -R node:node /home/node/.openclaw

USER node

ENV ARSGUARD_CONFIG="/arsguard/config/arsguard.yaml"

# 健康检查
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

EXPOSE 8080

CMD ["openclaw", "gateway", "run", "--allow-unconfigured", "--port", "8080"]
