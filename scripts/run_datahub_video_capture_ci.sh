#!/usr/bin/env bash
set -euo pipefail

export DATAHUB_GMS_URL="http://127.0.0.1:8080"
export DATAHUB_GMS_TOKEN="local-quickstart-no-auth"
export DATAHUB_UI_URL="http://127.0.0.1:9002"

python -m pip install --quiet --upgrade pip wheel setuptools uv
python -m pip install --quiet -e '.[datahub]'
python - <<'PY'
from importlib.metadata import version
assert version('acryl-datahub') == '1.6.0.15'
print('acryl-datahub', version('acryl-datahub'))
PY
uvx --version

datahub docker quickstart
curl --fail --silent --show-error "$DATAHUB_GMS_URL/health"

ready=false
for attempt in $(seq 1 90); do
  status=$(curl --silent --output /dev/null --write-out '%{http_code}' "$DATAHUB_UI_URL" || true)
  if [[ "$status" == "200" || "$status" == "302" ]]; then
    ready=true
    break
  fi
  echo "DataHub frontend attempt $attempt returned HTTP ${status:-unavailable}."
  sleep 3
done
test "$ready" = "true"

mkdir -p .toxicjoin artifacts/video-captures

toxicjoin-datahub-seed \
  --yes \
  --output .toxicjoin/datahub-video-seed.json

python - <<'PY'
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
            external_url='https://github.com/Z3X-1337/toxicjoin',
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

npm install --no-save --no-audit --no-fund playwright-core@1.54.1

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
node scripts/capture_datahub_video_evidence.mjs

cp .toxicjoin/video-capture-manifest.json artifacts/video-captures/
cp .toxicjoin/datahub-video-seed.json artifacts/video-captures/
sha256sum \
  artifacts/video-captures/*.json \
  artifacts/video-captures/*.png \
  artifacts/video-captures/*.webm \
  | sort > artifacts/video-captures/SHA256SUMS

cat artifacts/video-captures/capture-report.json
cat artifacts/video-captures/SHA256SUMS
