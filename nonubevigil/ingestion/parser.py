from __future__ import annotations

from pathlib import Path

from ..models import AnalysisContext


# Encodings to try in order before giving up
_ENCODINGS = ("utf-8", "latin-1", "cp1252")


class SourceParser:
    """
    Reads a source file and produces an AnalysisContext.

    Handles encoding detection gracefully — never crashes on a binary
    or non-UTF-8 file, just skips it with a warning.

    AST parsing via tree-sitter is optional — if tree-sitter is not
    installed the context is still valid, analyzers that need the AST
    will simply skip their AST-based checks.
    """

    def __init__(self, use_ast: bool = True) -> None:
        self.use_ast = use_ast
        self._parsers: dict[str, object] = {}

        if use_ast:
            self._init_tree_sitter()

    def _init_tree_sitter(self) -> None:
        """
        Attempt to load tree-sitter language parsers.
        Fails silently if tree-sitter is not installed — AST analysis
        will be unavailable but pattern and dataflow analysis still work.
        """
        try:
            import tree_sitter_python     as tspython
            import tree_sitter_javascript as tsjs
            import tree_sitter_java       as tsjava
            from tree_sitter import Language, Parser

            self._parsers = {
                "python":     Parser(Language(tspython.language())),
                "javascript": Parser(Language(tsjs.language())),
                "typescript": Parser(Language(tsjs.language())),
                "java":       Parser(Language(tsjava.language())),
            }
        except ImportError:
            self._parsers = {}

    def parse(self, file_path: str | Path, language: str) -> AnalysisContext | None:
        """
        Read a file and return an AnalysisContext.
        Returns None if the file cannot be read (binary, permission error, etc.)
        """
        path = Path(file_path)
        source = self._read_source(path)

        if source is None:
            return None

        context = AnalysisContext(
            file_path = str(path),
            source    = source,
            language  = language,
        )

        if self.use_ast and language in self._parsers:
            context.ast = self._parse_ast(source, language)

        return context

    def _read_source(self, path: Path) -> str | None:
        """Try multiple encodings before giving up."""
        for encoding in _ENCODINGS:
            try:
                return path.read_text(encoding=encoding)
            except (UnicodeDecodeError, PermissionError):
                continue
        return None

    def _parse_ast(self, source: str, language: str) -> object | None:
        """Parse source into a tree-sitter AST. Returns None on failure."""
        try:
            parser = self._parsers[language]
            return parser.parse(source.encode())
        except Exception:
            return None