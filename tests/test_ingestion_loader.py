# tests/test_ingestion_loader.py
# Pytest for nonubevigil.ingestion.loader.PluginLoader.

import tempfile
from pathlib import Path

import pytest

from nonubevigil.ingestion.loader import PluginLoader
from nonubevigil.rules.base import BaseRule


class TestPluginLoaderDefaults:
    """Tests for load_defaults()."""

    def test_load_defaults_returns_list_of_rules(self) -> None:
        loader = PluginLoader()
        rules = loader.load_defaults()
        assert isinstance(rules, list)
        assert len(rules) >= 1
        for r in rules:
            assert isinstance(r, BaseRule)
            assert r.rule_id != "BASE000"

    def test_load_defaults_has_expected_rule_ids(self) -> None:
        loader = PluginLoader()
        rules = loader.load_defaults()
        ids = {r.rule_id for r in rules}
        assert "SEC001" in ids  # HardcodedSecretRule


class TestPluginLoaderLoadFromDir:
    """Tests for load_from_dir()."""

    def test_load_from_dir_nonexistent_raises(self) -> None:
        loader = PluginLoader()
        with pytest.raises(NotADirectoryError, match="not found"):
            loader.load_from_dir("/nonexistent/dir/path")

    def test_load_from_dir_empty_returns_empty_list(self) -> None:
        loader = PluginLoader()
        with tempfile.TemporaryDirectory() as d:
            result = loader.load_from_dir(d)
            assert result == []


class TestPluginLoaderLoadForLanguage:
    """Tests for load_for_language()."""

    def test_load_for_language_returns_subset(self) -> None:
        loader = PluginLoader()
        all_rules = loader.load_defaults()
        py_rules = loader.load_for_language("python")
        assert len(py_rules) <= len(all_rules)
        assert len(py_rules) >= 1
        for r in py_rules:
            assert r in all_rules or not r.languages or "python" in r.languages
