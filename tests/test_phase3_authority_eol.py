from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_phase3_authority_files_use_canonical_lf() -> None:
    attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()
    required = {
        "config/toolchain.json text eol=lf",
        "uv.lock text eol=lf",
        "package-lock.json text eol=lf",
        "apps/web/package-lock.json text eol=lf",
    }
    assert required.issubset(set(attributes))
