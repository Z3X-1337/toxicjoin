"""Shared test fixtures.

``seed_database`` costs roughly twenty seconds because DuckDB's Python parameter binding
dominates row-by-row inserts. Reseeding per test made the suite take about an hour of wall
clock. The warehouse is deterministic by construction, so it is built once per session and
copied per test instead, which costs single-digit milliseconds and keeps every test fully
isolated on its own file.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from toxicjoin.demo import seed_database


@pytest.fixture(scope="session")
def golden_database(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build the deterministic synthetic warehouse exactly once per test session."""

    path = tmp_path_factory.mktemp("toxicjoin-golden") / "golden.duckdb"
    seed_database(path)
    return path


@pytest.fixture
def seeded_database(golden_database: Path, tmp_path: Path) -> Path:
    """Return a private, byte-identical copy of the session warehouse for one test."""

    target = tmp_path / "demo.duckdb"
    shutil.copyfile(golden_database, target)
    return target
