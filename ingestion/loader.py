from __future__ import annotations

import importlib
import importlib.util
import inspect
from pathlib import Path

from ..rules.base import BaseRule


class PluginLoader:
    """
    Discovers and instantiates BaseRule subclasses.

    Two loading modes:
      - load_defaults()  : loads the built-in rules from vigil/rules/
      - load_from_dir()  : loads custom rules from a user-provided directory

    Both modes return a list of instantiated BaseRule objects ready
    to be passed to the analyzers.
    """

    def load_defaults(self) -> list[BaseRule]:
        """Load all built-in vigil rules."""
        from ..rules import (
            HardcodedSecretRule,
            SqlInjectionRule,
            XssRule,
            InsecureDeserializationRule,
        )
        return [
            HardcodedSecretRule(),
            SqlInjectionRule(),
            XssRule(),
            InsecureDeserializationRule(),
        ]

    def load_from_dir(self, rules_dir: str | Path) -> list[BaseRule]:
        """
        Dynamically load all BaseRule subclasses found in Python files
        inside rules_dir.

        Allows users to add custom rules without modifying vigil's core.
        """
        rules_dir = Path(rules_dir)
        if not rules_dir.is_dir():
            raise NotADirectoryError(f"Rules directory not found: {rules_dir}")

        rules: list[BaseRule] = []

        for path in sorted(rules_dir.glob("*.py")):
            if path.stem.startswith("_"):
                continue

            module = self._load_module(path)
            if module is None:
                continue

            for _, obj in inspect.getmembers(module, inspect.isclass):
                if (
                    issubclass(obj, BaseRule)
                    and obj is not BaseRule
                    and not inspect.isabstract(obj)
                ):
                    rules.append(obj())

        return rules

    def load_for_language(self, language: str) -> list[BaseRule]:
        """
        Return only the default rules that apply to a given language.
        Rules with an empty languages list are considered language-agnostic.
        """
        return [
            rule for rule in self.load_defaults()
            if not rule.languages or language in rule.languages
        ]

    @staticmethod
    def _load_module(path: Path) -> object | None:
        """Dynamically import a Python file as a module."""
        try:
            spec   = importlib.util.spec_from_file_location(path.stem, path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
        except Exception:
            return None