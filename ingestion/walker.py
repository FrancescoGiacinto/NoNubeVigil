from __future__ import annotations

import os
from pathlib import Path


# Supported extensions mapped to language name
EXTENSION_MAP: dict[str, str] = {
    ".py":   "python",
    ".js":   "javascript",
    ".ts":   "typescript",
    ".jsx":  "javascript",
    ".tsx":  "typescript",
    ".java": "java",
    ".php":  "php",
    ".rb":   "ruby",
    ".go":   "go",
}

# Directories to always skip
_IGNORE_DIRS: set[str] = {
    ".git", ".hg", ".svn",
    "node_modules", "vendor", "venv", ".venv",
    "__pycache__", ".mypy_cache", ".pytest_cache",
    "dist", "build", "target",
}


class FileWalker:
    """
    Recursively walks a directory and returns file paths to analyze.

    Filters by supported extensions and skips known irrelevant directories.
    Does not perform any analysis — pure I/O concern.
    """

    def __init__(
        self,
        extensions: list[str] | None = None,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.extensions  = set(extensions or EXTENSION_MAP.keys())
        self.ignore_dirs = ignore_dirs or _IGNORE_DIRS

    def walk(self, root: str | Path) -> list[Path]:
        """
        Return a sorted list of file paths under root that match
        the configured extensions.
        """
        root = Path(root).resolve()

        if not root.exists():
            raise FileNotFoundError(f"Path does not exist: {root}")

        if root.is_file():
            return [root] if root.suffix in self.extensions else []

        results: list[Path] = []

        for dirpath, dirnames, filenames in os.walk(root):
            # Prune ignored directories in-place so os.walk skips them
            dirnames[:] = [
                d for d in dirnames
                if d not in self.ignore_dirs and not d.startswith(".")
            ]

            for filename in filenames:
                path = Path(dirpath) / filename
                if path.suffix in self.extensions:
                    results.append(path)

        return sorted(results)

    def detect_language(self, path: str | Path) -> str:
        """Return the language name for a given file path."""
        return EXTENSION_MAP.get(Path(path).suffix, "unknown")