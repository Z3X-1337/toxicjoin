#!/usr/bin/env bash
set -Eeuo pipefail

mkdir -p .toxicjoin artifacts/video-captures
LOG_FILE="artifacts/video-captures/capture-harness.log"
STAGE_FILE="artifacts/video-captures/capture-stage.txt"

# Preserve stdout/stderr from the very first setup command so an early quickstart
# failure still produces a useful artifact.
exec > >(tee -a "$LOG_FILE") 2>&1

stage="bootstrap"
printf '%s\n' "$stage" > "$STAGE_FILE"

on_error() {
  local exit_code=$?
  {
    echo "status=failed"
    echo "stage=$stage"
    echo "exit_code=$exit_code"
    echo "timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } > artifacts/video-captures/capture-failure-stage.txt
  docker ps -a > artifacts/video-captures/docker-ps.txt 2>&1 || true
  docker compose ls > artifacts/video-captures/docker-compose-ls.txt 2>&1 || true
  df -h > artifacts/video-captures/disk-usage.txt 2>&1 || true
  exit "$exit_code"
}
trap on_error ERR

set_stage() {
  stage="$1"
  printf '%s\n' "$stage" > "$STAGE_FILE"
  echo "=== ToxicJoin capture stage: $stage ==="
}

export DATAHUB_GMS_URL="http://127.0.0.1:8080"
export DATAHUB_GMS_TOKEN="local-quickstart-no-auth"
export DATAHUB_UI_URL="http://127.0.0.1:9002"

set_stage "free-runner-space"
sudo rm -rf /usr/local/lib/android /usr/share/dotnet /opt/ghc || true
docker system prune --all --force || true
df -h | tee artifacts/video-captures/disk-before.txt

set_stage "install-python-dependencies"
python -m pip install --quiet --upgrade pip wheel setuptools uv
python -m pip install --quiet -e '.[datahub]'
python - <<'PY'
from importlib.metadata import version
assert version('acryl-datahub') == '1.6.0.15'
print('acryl-datahub', version('acryl-datahub'))
PY
uvx --version

set_stage "start-datahub-quickstart"
datahub docker quickstart 2>&1 | tee artifacts/video-captures/datahub-quickstart.log

set_stage "verify-datahub-services"
ready_gms=false
for attempt in $(seq 1 90); do
  if curl --fail --silent --show-error "$DATAHUB_GMS_URL/health" > artifacts/video-captures/gms-health.txt; then
    ready_gms=true
    break
  fi
  echo "DataHub GMS attempt $attempt is not healthy yet."
  sleep 3
done
test "$ready_gms" = "true"

ready_ui=false
for attempt in $(seq 1 90); do
  status=$(curl --silent --output artifacts/video-captures/ui-probe.html --write-out '%{http_code}' "$DATAHUB_UI_URL" || true)
  if [[ "$status" == "200" || "$status" == "302" ]]; then
    ready_ui=true
    break
  fi
  echo "DataHub frontend attempt $attempt returned HTTP ${status:-unavailable}."
  sleep 3
done
test "$ready_ui" = "true"

docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' \
  | tee artifacts/video-captures/docker-running.txt

set_stage "seed-governed-metadata"
toxicjoin-datahub-seed \
  --yes \
  --output .toxicjoin/datahub-video-seed.json \
  2>&1 | tee artifacts/video-captures/datahub-seed.log
cp .toxicjoin/datahub-video-seed.json artifacts/video-captures/

set_stage "write-decision-through-mcp"
python - <<'PY' 2>&1 | tee artifacts/video-captures/datahub-decision.log
import asyncio
import json
from pathlib import Path

from pydantic import SecretStr
from toxicjoin.demo import default_fixture_catalog
from toxicjoin.integrations.datahub_mcp import (
    DataHubMcpClient,
    DataHubMcpSettings,
    StdioDataHubMcpTransport,
)

async def main() -> None:
    catalog = default_fixture_catalog()
    dataset_urns = tuple(sorted(dataset.urn for dataset in catalog.datasets.values()))
    retention_urn = catalog.datasets['retention_scores'].urn
    settings = DataHubMcpSettings(
        gms_url='http://127.0.0.1:8080',
        gms_token=SecretStr('local-quickstart-no-auth'),
        command='uvx',
        args=(
            '--from',
            'mcp-server-datahub==0.6.0',
            'mcp-server-datahub',
        ),
        timeout_seconds=90.0,
        mutation_enabled=True,
    )
    content = '''# ToxicJoin Decision — Flagship Rewrite Verified

## Decision

Initial policy: **REWRITE** (`SMALL_GROUP_RISK`).

ToxicJoin strengthened the supported grouped query with:

```sql
HAVING COUNT(DISTINCT c.customer_id) >= 20
```

The rewritten SQL was reparsed, grounded again in governed metadata, and reevaluated to **ALLOW** before execution.

## Independent verification

- three result groups;
- forty distinct subjects in every group;
- no forbidden raw identifier projected;
- persisted ToxicJoin receipt contains hashes and governed evidence, not returned result rows.

## Enforcement boundary

A rewrite is never trusted merely because ToxicJoin produced it. Unsupported or ambiguous transformations fail closed.
'''
    async with StdioDataHubMcpTransport(settings) as transport:
        client = DataHubMcpClient(transport)
        await client.discover_and_validate(require_mutations=True)
        urn = await client.save_decision(
            title='ToxicJoin Decision — Flagship Rewrite Verified',
            content=content,
            related_assets=dataset_urns,
        )

    manifest = {
        'schema_version': '1.0',
        'flagship_dataset_urn': retention_urn,
        'decision_document_urn': urn,
        'related_asset_urns': dataset_urns,
        'decision_created_through': 'DataHub MCP save_document',
        'mcp_package': 'mcp-server-datahub==0.6.0',
    }
    Path('.toxicjoin/video-capture-manifest.json').write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + '\n',
        encoding='utf-8',
    )
    print(json.dumps(manifest, indent=2))

asyncio.run(main())
PY
cp .toxicjoin/video-capture-manifest.json artifacts/video-captures/

set_stage "install-browser-client"
npm install --no-save --no-audit --no-fund playwright-core@1.54.1
# Recording video with Playwright uses its pinned FFmpeg helper even when the
# browser executable is supplied by the runner. Install only that small helper;
# keep using the preinstalled Chrome binary rather than downloading a browser.
npx playwright-core install ffmpeg

browser_path=""
for command_name in google-chrome google-chrome-stable chromium chromium-browser; do
  candidate=$(command -v "$command_name" || true)
  if [[ -n "$candidate" && -x "$candidate" ]]; then
    browser_path="$candidate"
    break
  fi
done
if [[ -z "$browser_path" ]]; then
  echo "No Chrome/Chromium executable found." >&2
  exit 1
fi
"$browser_path" --version

export BROWSER_EXECUTABLE="$browser_path"
export TOXICJOIN_CAPTURE_MANIFEST=".toxicjoin/video-capture-manifest.json"
export TOXICJOIN_CAPTURE_DIR="artifacts/video-captures"

set_stage "capture-datahub-ui"
node scripts/capture_datahub_video_evidence.mjs

set_stage "hash-capture-package"
# Hash only files that exist. Diagnostics are intentionally included so every
# retained capture package has an integrity manifest.
find artifacts/video-captures -maxdepth 1 -type f ! -name SHA256SUMS -print0 \
  | sort -z \
  | xargs -0 sha256sum > artifacts/video-captures/SHA256SUMS

cat artifacts/video-captures/capture-report.json
cat artifacts/video-captures/SHA256SUMS

set_stage "complete"
rm -f artifacts/video-captures/capture-failure-stage.txt
