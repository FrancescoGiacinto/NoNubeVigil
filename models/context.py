from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class AnalysisContext:
    """
    Per-file state passed into every rule at analysis time.

    Created by Pipeline once per file, then handed to every analyzer
    and rule. Rules read from it; DataFlowAnalyzer also writes to it
    (adding tainted variables as it traces data flow).

    Fields
    ------
    file_path    : path to the file being analyzed
    source       : full raw source code as a string
    language     : detected language (e.g. "python", "javascript")
    lines        : source split into lines — populated automatically
    tainted_vars : set of variable names that carry user-controlled data
                   populated incrementally by DataFlowAnalyzer
    ast          : tree-sitter parse tree — populated by SourceParser
                   None until SourceParser runs
    metadata     : arbitrary key/value bag for rule-specific state
    """

    file_path:    str
    source:       str
    language:     str              = "unknown"
    lines:        list[str]        = field(default_factory=list)
    tainted_vars: set[str]         = field(default_factory=set)
    ast:          Optional[object] = None
    metadata:     dict[str, Any]   = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.lines:
            self.lines = self.source.splitlines()

    # ------------------------------------------------------------------
    # Taint tracking
    # ------------------------------------------------------------------

    def mark_tainted(self, var_name: str) -> None:
        """
        Mark a variable as carrying user-controlled (tainted) data.
        Called by DataFlowAnalyzer when it detects a source assignment
        e.g. request.args.get(), input(), sys.argv[], etc.
        """
        self.tainted_vars.add(var_name)

    def is_tainted(self, var_name: str) -> bool:
        """True if the variable has been marked as tainted."""
        return var_name in self.tainted_vars

    def propagate_taint(self, source_var: str, target_var: str) -> None:
        """
        If source_var is tainted, mark target_var as tainted too.
        Models assignments like: query = user_input
        """
        if self.is_tainted(source_var):
            self.mark_tainted(target_var)

    # ------------------------------------------------------------------
    # Line access
    # ------------------------------------------------------------------

    def get_line(self, line_num: int) -> str:
        """Return source line by 1-based line number. Empty string if out of range."""
        if 1 <= line_num <= len(self.lines):
            return self.lines[line_num - 1]
        return ""

    def get_window(self, line_num: int, before: int = 2, after: int = 2) -> list[tuple[int, str]]:
        """
        Return a window of source lines around a given line number.
        Used by PDFReporter to show context around a finding.
        Returns list of (line_number, line_content) tuples.
        """
        start = max(1, line_num - before)
        end   = min(len(self.lines), line_num + after)
        return [(i, self.lines[i - 1]) for i in range(start, end + 1)]