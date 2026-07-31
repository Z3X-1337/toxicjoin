#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python3}"
DIAGNOSTICS_DIR="${TOXICJOIN_BOOTSTRAP_DIAGNOSTICS_DIR:-.toxicjoin/bootstrap}"
export UV_PROJECT_ENVIRONMENT="${TOXICJOIN_VENV:-.venv}"
mkdir -p "$DIAGNOSTICS_DIR"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "bootstrap error: Python 3.11.15 or 3.12.13 is required." >&2
  exit 2
fi

"$PYTHON_BIN" scripts/bootstrap.py verify \
  --components python,locks,contract \
  --output "$DIAGNOSTICS_DIR/pre-uv.json"

UV_VERSION="$("$PYTHON_BIN" -c 'import json; print(json.load(open("config/toolchain.json", encoding="utf-8"))["uv"]["version"])')"
UV_CANDIDATE="${TOXICJOIN_UV_BIN:-uv}"

if [[ "$UV_CANDIDATE" == */* ]]; then
  UV_BIN="$UV_CANDIDATE"
elif command -v "$UV_CANDIDATE" >/dev/null 2>&1; then
  UV_BIN="$(command -v "$UV_CANDIDATE")"
else
  "$PYTHON_BIN" -m pip install --disable-pip-version-check "uv==$UV_VERSION"
  UV_BIN="$("$PYTHON_BIN" -c 'import os, sysconfig; print(os.path.join(sysconfig.get_path("scripts"), "uv"))')"
fi

if [[ ! -x "$UV_BIN" ]]; then
  echo "bootstrap error: exact uv executable was not found at $UV_BIN" >&2
  exit 2
fi

export TOXICJOIN_UV_BIN="$UV_BIN"
"$PYTHON_BIN" scripts/bootstrap.py verify \
  --components python,uv,locks,contract \
  --output "$DIAGNOSTICS_DIR/toolchain.json"
"$PYTHON_BIN" scripts/bootstrap.py sync \
  --output "$DIAGNOSTICS_DIR/sync.json"

exec "$UV_BIN" run --frozen toxicjoin-api
