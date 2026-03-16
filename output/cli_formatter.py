from __future__ import annotations

from ..models import Finding, Severity
from ..scoring import ConfidenceScorer


RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"

SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "\033[35m",   # magenta
    Severity.HIGH:     "\033[31m",   # red
    Severity.MEDIUM:   "\033[33m",   # yellow
    Severity.LOW:      "\033[34m",   # blue
    Severity.INFO:     "\033[36m",   # cyan
}


class CLIFormatter:
    """
    Prints findings to the terminal with color coding and alignment.

    Output structure per finding
    ----------------------------
    [SEVERITY] file.py:line:col · RULE_ID · confidence 0.91
      Message text
      Snippet of source code
      Remediation guidance
      CWE / OWASP category

    Followed by a summary block with counts per severity level.
    """

    def __init__(self, verbose: bool = False, no_color: bool = False) -> None:
        self.verbose  = verbose
        self.no_color = no_color

    def print_results(self, findings: list[Finding], files_scanned: int, files_skipped: int, errors: list[str]) -> None:
        if not findings:
            self._print_clean(files_scanned)
            return

        self._print_header(len(findings), files_scanned)

        for finding in findings:
            self._print_finding(finding)

        self._print_summary(findings)

        if self.verbose and errors:
            self._print_errors(errors)

    # ------------------------------------------------------------------
    # Header
    # ------------------------------------------------------------------

    def _print_header(self, total: int, files_scanned: int) -> None:
        print()
        print(f"{BOLD}vigil{RESET} · {total} finding(s) across {files_scanned} file(s)")
        print("─" * 60)

    # ------------------------------------------------------------------
    # Single finding
    # ------------------------------------------------------------------

    def _print_finding(self, f: Finding) -> None:
        color = "" if self.no_color else SEVERITY_COLORS.get(f.severity, "")
        reset = "" if self.no_color else RESET
        bold  = "" if self.no_color else BOLD
        dim   = "" if self.no_color else DIM

        # Title line
        print(
            f"\n{color}{bold}[{f.severity.name:<8}]{reset} "
            f"{f.file}:{f.line}:{f.column} "
            f"{dim}· {f.rule_id} · confidence {f.confidence:.2f}{reset}"
        )

        # Message
        print(f"  {f.message}")

        # Snippet
        if f.snippet:
            print(f"  {dim}{f.snippet.rstrip()}{reset}")

        # Remediation
        print(f"  {bold}fix:{reset} {f.remediation}")

        # CWE + OWASP