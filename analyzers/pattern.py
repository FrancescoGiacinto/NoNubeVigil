from __future__ import annotations

from ..models import AnalysisContext, Finding
from ..rules.base import BaseRule


class PatternAnalyzer:
    """
    Runs regex-based rules against raw source text.

    Fastest analyzer — no AST required. Low precision on its own
    but catches a large surface area quickly. Results are refined
    by ConfidenceScorer downstream.
    """

    def __init__(self, rules: list[BaseRule]) -> None:
        self.rules = rules

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        """
        Run all rules against the context and collect findings.

        Each rule is run independently — a failure in one rule
        does not block the others.
        """
        findings: list[Finding] = []

        for rule in self.rules:
            if rule.languages and context.language not in rule.languages:
                continue
            try:
                findings.extend(rule.analyze(context))
            except Exception as exc:
                print(f"[warn] {rule.rule_id} failed on {context.file_path}: {exc}")

        return findings