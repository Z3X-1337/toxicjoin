# ToxicJoin v0.1.0 reproducibility

Release identity:

- tag: `{{TAG}}`
- exact commit: `{{SOURCE_SHA}}`
- Release Manifest SHA-256: `{{MANIFEST_SHA256}}`

## Checkout

```bash
git clone https://github.com/Z3X-1337/toxicjoin.git
cd toxicjoin
git checkout --detach {{SOURCE_SHA}}
test "$(git rev-parse HEAD)" = "{{SOURCE_SHA}}"
```

## Locked Python environment

```bash
python -m pip install --disable-pip-version-check "uv==0.8.4"
python scripts/bootstrap.py verify --components python,uv,locks,contract
python scripts/bootstrap.py sync --extra dev
uv run --frozen pytest -q
```

Use the exact supported Python versions recorded in `config/toolchain.json`. The committed `uv.lock`, root `package-lock.json`, and `apps/web/package-lock.json` are release authority.

## Frontend

```bash
npm ci
npm --prefix apps/web ci
npm --prefix apps/web run typecheck
npm --prefix apps/web test -- --run
npm --prefix apps/web run build
```

## Release assets

```bash
sha256sum --check SHA256SUMS
```

The Release Manifest and final evidence index must both name commit `{{SOURCE_SHA}}`. SBOM files must declare CycloneDX format. Replay evidence must not be interpreted as live execution.
