# Reproducible Locked Bootstrap

This document defines the Phase 3 installation and startup boundary. It is subordinate to the normative product architecture in [`architecture.md`](architecture.md).

## Authority

`config/toolchain.json` is the machine-readable authority for exact bootstrap tool versions, supported clean-machine runners, lock surfaces, container identities, and DataHub tool versions recorded for later phases.

The executable enforcement authority is `scripts/bootstrap.py`. It uses only the Python standard library so it can validate the environment before project dependencies are installed.

## Exact toolchain

The Phase 3 contract currently requires:

- Python `3.11.15` or `3.12.13`;
- uv `0.8.4`;
- Node.js `22.16.0`;
- npm `10.9.2`;
- Docker Client/Server `28.0.4`, Buildx `0.35.0`, and Compose `2.38.2` for the Linux container proof;
- DataHub SDK `1.6.0.15` and MCP Server `0.6.0`, recorded only for later Live DataHub work.

A different patch version is not silently accepted. Update the contract and regenerate exact-platform evidence through a reviewed pull request before changing the supported toolchain.

## Lock authority

The committed dependency authorities are:

| Surface | Lock | Required consumer |
|---|---|---|
| Python runtime and profiles | `uv.lock` | `uv sync --frozen` and `uv run --frozen` |
| Hosted replay verification tooling | `package-lock.json` | `npm ci` |
| Judge interface | `apps/web/package-lock.json` | `npm ci` |

The only bootstrap exception is installing the package manager itself as exact `uv==0.8.4` before `uv.lock` can be consumed. That exception may not install ToxicJoin or any project dependency.

## Native fixture startup

Linux and supported macOS Intel hosts:

```bash
bash run.sh
```

Windows PowerShell:

```powershell
.\run.ps1
```

Both launchers:

1. resolve the repository root;
2. reject unsupported Python patches;
3. verify the committed locks and manifest authorities;
4. install uv only when absent and only at the exact contracted version;
5. execute a frozen sync;
6. record sanitized diagnostics under `.toxicjoin/bootstrap/`;
7. launch `toxicjoin-api` through `uv run --frozen`.

They do not upgrade pip, perform editable pip installation, resolve dependencies outside the lock, start DataHub, or select the PostgreSQL work from PR #118.

## Manual diagnostics

Verify Python, uv, and locks:

```bash
python scripts/bootstrap.py verify --components python,uv,locks,contract
```

Verify Node and npm as well:

```bash
python scripts/bootstrap.py verify --components python,uv,node,npm,locks,contract
```

Perform an idempotent frozen sync:

```bash
python scripts/bootstrap.py sync
```

Run the fixture readiness smoke test:

```bash
python scripts/bootstrap.py smoke
```

Audit canonical bootstrap surfaces for lock bypasses and exact-toolchain drift, while retaining non-Phase-3 workflows as inventory-only observations:

```bash
python scripts/bootstrap.py audit
```

Generate a machine-readable census and content-addressed evidence package:

```bash
python scripts/bootstrap.py evidence --output-dir artifacts/phase3-bootstrap
```

## Clean-machine support boundary

The Phase 3 workflow verifies native bootstrap on fixed GitHub runner families:

- `ubuntu-24.04` on x64;
- `windows-2025` on x64;
- `macos-15-intel` on x64.

Each runner is exercised with both exact supported Python patches. The gate performs two frozen syncs, compares package-set identity, installs both npm graphs through `npm ci`, builds the frontend, starts the fixture API, checks health/readiness, and verifies that the tracked worktree remains unchanged.

The initial `macos-15` ARM64 probe failed before repository bootstrap because `actions/setup-python` did not publish exact `3.11.15` or `3.12.13` toolcache builds for that runner. Phase 3 therefore does not claim macOS ARM64 support. Adding it later requires a separate exact-toolchain proof rather than a moving or source-built Python fallback.

This is bootstrap portability only. The complete Windows/Linux test parity defect `TJ-P1-TEST-PORT-001`, traceback-frame portability, and full cross-platform test comparison remain Phase 4 work.

## Phase boundary

Phase 3 does not:

- run or claim exact-head Live DataHub evidence;
- change DataHub credentials or role separation;
- modify or merge PR #118;
- change the canonical runtime architecture;
- create a release tag or GitHub Release;
- change the release-manifest completeness gate;
- deploy Vercel or relabel the historical replay;
- submit Devpost.
