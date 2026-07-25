# syntax=docker/dockerfile:1.7

FROM node@sha256:0473e7dc433a1310f436edee02aa79737ec78a4b345433ab0963d4a256f9ad85 AS web-builder
WORKDIR /build/apps/web
COPY apps/web/package.json apps/web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY apps/web/ ./
RUN npm run build

FROM python@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de AS python-deps
WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN python -m pip install --no-cache-dir 'uv==0.8.4' \
    && uv sync --frozen --no-dev --no-install-project

FROM python@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH=/app/.venv/bin:$PATH \
    PYTHONPATH=/app/src \
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
COPY --from=python-deps /app/.venv /app/.venv
COPY src/ ./src/
COPY config/ ./config/
COPY demo/ ./demo/
COPY --from=web-builder /build/apps/web/dist/ /app/apps/web/dist/
RUN chown -R toxicjoin:toxicjoin /app/apps/web/dist
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=20s --timeout=4s --start-period=25s --retries=3 \
  CMD ["python", "-c", "import json, urllib.request; data=json.load(urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3)); assert data['status'] == 'ok'"]
CMD ["python", "-c", "from toxicjoin.cli import run_api; run_api()"]
