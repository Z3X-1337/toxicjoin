from __future__ import annotations

from pathlib import Path

from toxicjoin.context import load_fixture_catalog
from toxicjoin.demo import default_fixture_catalog


ROOT = Path(__file__).parents[2]


def test_package_and_visible_fixture_catalogs_match() -> None:
    visible = load_fixture_catalog(ROOT / "demo" / "fixtures" / "catalog.json")
    packaged = default_fixture_catalog()

    assert visible.model_dump(mode="json") == packaged.model_dump(mode="json")
