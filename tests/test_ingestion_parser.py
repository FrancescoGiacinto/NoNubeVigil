# tests/test_ingestion_parser.py
# Pytest for nonubevigil.ingestion.parser.SourceParser.

import tempfile
from pathlib import Path

import pytest

from nonubevigil.ingestion.parser import SourceParser
from nonubevigil.models import AnalysisContext


class TestSourceParser:
    """Tests for SourceParser."""

    def test_parse_returns_context_for_valid_file(self) -> None:
        parser = SourceParser(use_ast=False)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write("x = 1\nprint(x)\n")
            path = f.name
        try:
            ctx = parser.parse(path, "python")
            assert ctx is not None
            assert isinstance(ctx, AnalysisContext)
            assert ctx.language == "python"
            assert "x = 1" in ctx.source
            assert ctx.lines == ["x = 1", "print(x)"]
        finally:
            Path(path).unlink(missing_ok=True)

    def test_parse_nonexistent_raises(self) -> None:
        parser = SourceParser(use_ast=False)
        with pytest.raises(FileNotFoundError):
            parser.parse("/nonexistent/path/file.py", "python")

    def test_parse_with_ast_optional(self) -> None:
        """With use_ast=True, parser may or may not set context.ast depending on tree-sitter."""
        parser = SourceParser(use_ast=True)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write("pass\n")
            path = f.name
        try:
            ctx = parser.parse(path, "python")
            assert ctx is not None
            assert ctx.source == "pass\n" or "pass" in ctx.source
        finally:
            Path(path).unlink(missing_ok=True)

    def test_accepts_path_object(self) -> None:
        parser = SourceParser(use_ast=False)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write("a = 1\n")
            path = Path(f.name)
        try:
            ctx = parser.parse(path, "python")
            assert ctx is not None
            assert Path(ctx.file_path).name == path.name
        finally:
            path.unlink(missing_ok=True)
