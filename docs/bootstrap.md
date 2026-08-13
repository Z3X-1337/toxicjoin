# Reproducible Locked Bootstrap

This document defines the Phase 3 installation and startup boundary. It is subordinate to the normative product architecture in [`architecture.md`](architecture.md).

## Authority

`config/toolchain.json` is the machine-readable authority for exact bootstrap tool versions, supported clean-machine runners, lock surfaces, container identities, and DataHub tool versions recorded for later phases.

The executable enforcement authority is `scripts/bootstrap.py`. It uses only the Python standard library so it can validate the environment before project dependencies are installed.

## Exact toolchain

Python is exact per supported platform because CPython patch binaries are published differently across operating systems:

| Platform | Exact Python patches |
|---|---|
| Linux x64 | `3.11.15`, `3.12.13` |
| Windows x64 | `3.11.9`, `3.12.10` |
| macOS Intel x64 | `3.11.9`, `3.12.10` |

The remaining exact tools are:

- uv `0.8.4`;
- Node.js `22.16.0`;
- npm `10.9.2`;
- Docker Client/Server `28.0.4`, Buildx `0.35.0`, and Compose `2.38.2` for the Linux container proof;
- DataHub SDK `1.6.0.15` and MCP Server `0.6.0`, recorded only for later Live DataHub work.

A different patch version is not silently accepted. Update the contract and regenerate exact-platform evidence through a reviewed pull request before changing the supported toolchain.

## Lock authority

| Surface | Lock | Required consumer |
|---|---|---|
| Python runtime and profiles | `uv.lock` | `uv sync --frozen` and `uv run --frozen` |
| Production browser E2E tooling | `package-lock.json` | `npm ci` |
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
2. reject Python patches outside the exact current-platform contract;
3. verify the committed locks and manifest authorities;
4. install uv only when absent and only at the exact contracted version;
5. execute a frozen sync;
6. record sanitized diagnostics under `.toxicjoin/bootstrap/`;
7. launch `toxicjoin-api` through `uv run --frozen`.

They do not upgrade pip, perform editable pip installation, resolve dependencies outside the lock, start DataHub, or select the PostgreSQL work from PR #118.

## Manual diagnostics

```bash
python scripts/bootstrap.py verify --components python,uv,locks,contract
python scripts/bootstrap.py verify --components python,uv,node,npm,locks,contract
python scripts/bootstrap.py sync
python scripts/bootstrap.py smoke
python scripts/bootstrap.py audit
python scripts/bootstrap.py evidence --output-dir artifacts/phase3-bootstrap
```

The audit fails closed on lock bypasses and exact-toolchain drift in canonical Phase 3 surfaces. Non-Phase-3 workflows are retained as inventory-only observations so this phase does not start Live DataHub or unrelated remediation.

## Clean-machine support boundary

The Phase 3 workflow verifies six exact runner/Python pairs:

- `ubuntu-24.04`: Python `3.11.15` and `3.12.13`;
- `windows-2025`: Python `3.11.9` and `3.12.10`;
- `macos-15-intel`: Python `3.11.9` and `3.12.10`.

Each job performs two frozen syncs, compares package-set identity, installs both npm graphs through `npm ci`, builds the frontend, starts the fixture API, checks health/readiness, verifies tracked-worktree cleanliness, and creates content-addressed evidence.

The exploratory `macos-15` ARM64 run failed before repository bootstrap because the exact Phase 3 Python patches were unavailable to `actions/setup-python` on that runner. Phase 3 therefore does not claim macOS ARM64 support. Adding it later requires a separate exact-toolchain proof rather than a moving or source-built fallback.

The Windows and macOS patch difference is deliberate: those platforms use the last official binary CPython patches available for the supported minors, while Linux can consume later source-built security patches. It does not weaken lock enforcement; each supported platform is checked against its own exact list.

This is bootstrap portability only. The complete Windows/Linux test parity defect `TJ-P1-TEST-PORT-001`, traceback-frame portability, and full cross-platform test comparison remain Phase 4 work.

## Phase boundary

Phase 3 does not:

- run or claim exact-head Live DataHub evidence;
- change DataHub credentials or role separation;
- modify or merge PR #118;
- change the canonical runtime architecture;
- create a release tag or GitHub Release;
- change the release-manifest completeness gate;
- change public hosting or deployment identity;
- submit Devpost.
