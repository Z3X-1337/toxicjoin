# toxicjoin — project standard

Overrides `~/.claude/CLAUDE.md` on conflict. That file's rules (verify, label confidence,
root-cause, no filler) still apply.

## What this is
Compositional privacy firewall for AI data agents. An agent proposes SQL; the deterministic
kernel in `src/toxicjoin/policy/engine.py` (rules in `policy.yaml`) evaluates it against
governed DataHub lineage and returns **ALLOW / REWRITE / BLOCK**. REWRITE output is never
trusted as-is — it is reparsed, re-evaluated, executed read-only, then independently
re-verified (`src/toxicjoin/verify/`) before release. README.md documents two real
privacy bypasses found by adversarial review and closed; treat any change near
policy/rewrite/verify as capable of reintroducing that class of bug.

## Environment [verified 2026-08-04]
- Python 3.11–3.12 via `uv`. Venv at `.venv\Scripts\python.exe`. **Never `pip install`
  into it** — use `uv add` / `uv sync`, or it desyncs `uv.lock`.
- Frontend at `apps/web/` — separate Node/TS project (Vite + vitest + tsc), own
  `package-lock.json`.
- Dev server: `uv run --frozen toxicjoin-api` → `http://127.0.0.1:8000` (also
  `.claude/launch.json`, use the `run` skill / Browser preview to launch it).

## Commands — run this session, exact output noted
```powershell
uv run --frozen ruff check src tests scripts   # CI's actual lint gate. Passed, 0 issues.
uv run --frozen pytest -q                       # 962 passed, 1 skipped, ~97s.
python -m bandit -q -ll -r src                  # 2 medium, 27 low, 0 high, 26998 lines.
```
```bash
cd apps/web && npm ci && npm run check          # CI's frontend gate: tsc -b + vitest + build.
```

**Known, NOT CI gates — don't treat a failure here as a regression you introduced:**
- `mypy src` → 252 pre-existing errors across 37 files. `mypy` is in the `dev` extra but
  `ci.yml` never calls it. Don't "fix" these opportunistically inside an unrelated change;
  it's a real backlog, out of scope unless the user asks for it directly.
- `ruff format --check .` → 176 files would reformat. Not run in CI either. Don't
  reformat the whole tree as a drive-by; it'd blow up every diff.
- `python scripts/bootstrap.py verify --components ...,node,...` → fails locally:
  `Node mismatch: expected 22.16.0, got 24.18.1` (this machine has 24.18.1 global).
  This is a real environment gap, not something to silently patch — don't downgrade
  Node globally to satisfy one project. Use `nvm`/a local Node version manager if asked
  to fix it, or just skip `node` from `--components` for a local check.

## Critical areas — extra scrutiny, always
- `policy/engine.py` + `policy.yaml` — the decision kernel. Any change here is
  security-relevant by definition, not just a logic change.
- `rewrite/` — generates SQL that is *not yet trusted*. A rewrite that isn't re-verified
  downstream is the exact shape of both closed historical bypasses.
- `proofs/` (`agent_provenance.py`, `agent_handoff.py`) — PPMC authority handoff.
  `tests/security/test_agent_ppmc_authority_handoff_authenticity.py` exists specifically
  because this was worth a dedicated regression suite; keep it that way.
- `receipts/` / `evidence/` — HMAC-signed, sanitized (no raw rows: see `"rows" not in
  result["receipt"]` assertion in `ci.yml`). A receipt leaking preview rows is a
  disclosure bug, not a formatting bug.
- `verify/` — must stay independent of `rewrite/`/`policy/` reasoning. If verify starts
  trusting policy's decision instead of re-checking the executed result, it stops meaning
  anything.
- `api/app.py:_unauthenticated_principal` + `cli.py:_uvicorn_proxy_kwargs` — the pre-auth
  failure limiter's identity comes entirely from `request.client.host`, which is only as
  trustworthy as the proxy-trust boundary configured in `cli.py` (`TOXICJOIN_TRUSTED_PROXY_IPS`,
  documented in `docs/deploy-public.md`). Fixed 2026-08-04: this was previously an
  uvicorn-default, unexamined trust boundary — CWE-346/CWE-290, not exploitable on the
  two shipped fixture-mode deployments (fly.toml/render.yaml bypass auth entirely) but real
  for any live/credentialed deployment behind a proxy. Don't reintroduce an implicit default.

## Before claiming a change is safe
Run the three verified commands above for the language you touched. For anything under
Critical areas, also apply the `secure-code-audit` or `threat-model` skill, or hand off
to the `security-auditor` subagent — don't eyeball it.
