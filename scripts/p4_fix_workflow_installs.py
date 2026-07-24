from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
UV_VERSION = "0.8.4"

_INLINE_EDITABLE = re.compile(
    r"^(?P<indent>\s*)run:\s*(?:python(?:3)?\s+-m\s+pip|pip)\s+install\s+-e\s+"
    r"['\"]?\.\[(?P<extras>[^\]]+)\]['\"]?\s*$"
)
_INLINE_CHAINED = re.compile(
    r"^(?P<indent>\s*)run:\s*(?:python(?:3)?\s+-m\s+pip|pip)\s+install\s+--upgrade\s+pip\s*&&\s*"
    r"(?:python(?:3)?\s+-m\s+pip|pip)\s+install\s+-e\s+['\"]?\.\[(?P<extras>[^\]]+)\]['\"]?\s*$"
)
_INLINE_PLAIN = re.compile(
    r"^(?P<indent>\s*)run:\s*(?:python(?:3)?\s+-m\s+pip|pip)\s+install\s+-e\s+\.?\s*$"
)
_EDITABLE_ANYWHERE = re.compile(r"pip\s+install\s+-e\s+['\"]?\." )


def locked_block(indent: str, extras: str | None) -> list[str]:
    flags = ""
    if extras:
        flags = " " + " ".join(
            f"--extra {item.strip()}" for item in extras.split(",") if item.strip()
        )
    return [
        f"{indent}run: |",
        f"{indent}  python -m pip install --disable-pip-version-check 'uv=={UV_VERSION}'",
        f"{indent}  uv sync --frozen{flags}",
        f"{indent}  echo \"$PWD/.venv/bin\" >> \"$GITHUB_PATH\"",
    ]


def rewrite(path: Path) -> None:
    output: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        match = _INLINE_CHAINED.match(line) or _INLINE_EDITABLE.match(line)
        if match:
            output.extend(locked_block(match.group("indent"), match.group("extras")))
            continue
        plain = _INLINE_PLAIN.match(line)
        if plain:
            output.extend(locked_block(plain.group("indent"), None))
            continue
        if "npm install" in line and "--package-lock-only" not in line:
            line = line.replace("npm install", "npm ci")
        output.append(line)

    rendered = "\n".join(output) + "\n"
    if _EDITABLE_ANYWHERE.search(rendered):
        raise SystemExit(f"Unconverted editable Python install remains: {path.relative_to(ROOT)}")
    if "npm install" in rendered:
        raise SystemExit(f"Unconverted npm install remains: {path.relative_to(ROOT)}")
    path.write_text(rendered, encoding="utf-8")


def main() -> None:
    for path in sorted(WORKFLOWS.glob("*.y*ml")):
        rewrite(path)
    Path(__file__).unlink(missing_ok=True)


if __name__ == "__main__":
    main()
