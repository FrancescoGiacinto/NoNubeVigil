from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import AnalysisContext, Finding, Severity


class BaseRule(ABC):
    """
    Abstract base class for all vigil rules.

    Every rule in vigil extends this class and implements analyze().
    PluginLoader discovers rules by scanning for subclasses of BaseRule.

    Class attributes
    ----------------
    rule_id         : unique identifier (e.g. "SEC001") — used in Finding
                      and SARIF output
    severity        : default severity assigned to findings produced by
                      this rule — individual findings can override it
    confidence_base : starting confidence before ConfidenceScorer adjusts
    languages       : list of languages this rule applies to
                      empty list means language-agnostic
    description     : one-line summary shown in CLI --list-rules output
    """

    rule_id:         str       = "BASE000"
    severity:        Severity  = Severity.MEDIUM
    confidence_base: float     = 0.5
    languages:       list[str] = []
    description:     str       = ""

    @abstractmethod
    def analyze(self, context: AnalysisContext) -> list[Finding]:
        """
        Run the rule against the provided analysis context.

        Receives the full per-file AnalysisContext — including raw source,
        lines, AST (if available), and tainted variables set by
        DataFlowAnalyzer.

        Must return a list of Finding objects. Return an empty list if
        no issues are found — never return None.
        """
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Helpers available to all subclasses
    # ------------------------------------------------------------------

    def is_comment_line(self, line: str) -> bool:
        """
        Return True if the line is a comment in any supported language.
        Rules should skip comment lines to reduce false positives.
        """
        stripped = line.lstrip()
        return stripped.startswith(("#", "//", "*", "--", "<!--"))

    def make_finding(
        self,
        context:     AnalysisContext,
        line:        int,
        column:      int,
        message:     str,
        remediation: str,
        cwe_id:      str   = "CWE-000",
        confidence:  float = None,
        severity:    Severity = None,
        tags:        list[str] = None,
    ) -> Finding:
        """
        Convenience factory — avoids repeating boilerplate in every rule.

        Falls back to the rule's class-level severity and confidence_base
        if not explicitly provided.
        """
        return Finding(
            file        = context.file_path,
            line        = line,
            column      = column,
            rule_id     = self.rule_id,
            severity    = severity   or self.severity,
            confidence  = confidence or self.confidence_base,
            message     = message,
            remediation = remediation,
            cwe_id      = cwe_id,
            snippet     = context.get_line(line),
            tags        = tags or [],
        )

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} rule_id={self.rule_id}>"