# syntax=docker/dockerfile:1.7

FROM node:22.16.0-alpine AS web-builder
WORKDIR /build/apps/web

COPY apps/web/package.json ./
RUN npm install --no-audit --no-fund

COPY apps/web/ ./
RUN npm run build

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    TOXICJOIN_HOST=0.0.0.0 \
    TOXICJOIN_PORT=8000 \
    TOXICJOIN_RUNTIME_DIR=/var/lib/toxicjoin \
    TOXICJOIN_WEB_DIST=/app/apps/web/dist

WORKDIR /app

RUN useradd \
      --uid 10001 \
      --create-home \
      --home-dir /home/toxicjoin \
      --shell /usr/sbin/nologin \
      toxicjoin \
    && mkdir -p /var/lib/toxicjoin /app/apps/web/dist \
    && chown -R toxicjoin:toxicjoin /var/lib/toxicjoin /app

COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
COPY config/ ./config/
COPY demo/ ./demo/

RUN python -m pip install --no-cache-dir .

COPY --from=web-builder /build/apps/web/dist/ /app/apps/web/dist/

RUN chown -R toxicjoin:toxicjoin /app/apps/web/dist

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=20s --timeout=4s --start-period=25s --retries=3 \
  CMD ["python", "-c", "import json, urllib.request; data=json.load(urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3)); assert data['status'] == 'ok'"]

CMD ["toxicjoin-api"]
