"""Conftest for EIP-8184 LUCID tests."""

from pathlib import Path

import pytest


def pytest_ignore_collect(
    collection_path: Path, config: pytest.Config
) -> bool | None:
    """
    Exclude unit-test files from fill collection.

    The fill framework's forks plugin (``selected_fork_set``) parametrizes
    every collected test with a fork, which breaks tests that have no fill
    spec type (``blockchain_test`` etc.).  Files named ``*_unit.py`` are
    plain pytest unit tests and must only be collected outside of fill.
    """
    if collection_path.name.endswith("_unit.py"):
        return hasattr(config, "selected_fork_set")
    return None
