from __future__ import annotations

import re
from collections import defaultdict

from ..models import Finding, Severity


# Variable name fragments that strongly suggest a secret context
_HIGH_RISK_NAME_FRAGMENTS: set[str] = {
    "key", "secret", "token", "password", "passwd", "credential",
    "auth", "api", "private", "cert", "seed", "salt", "hash",
}

# Value fragments that strongly suggest a placeholder — reduce confidence
_PLACEHOLDER_FRAGMENTS: set[str] = {
    "example", "placeholder", "changeme", "change_me", "your_",
    "insert", "replace", "todo", "fixme", "dummy", "fake",
    "test", "sample", "default", "none", "null", "undefined",
}


class ConfidenceScorer:
    """
    Post-processes findings produced by all analyzers and adjusts
    their confidence scores based on converging signals.

    Responsibilities
    ----------------
    1. Boost confidence when multiple analyzers flag the same location
    2. Penalize findings whose snippets contain known placeholder patterns
    3. Boost findings whose variable names contain high-risk fragments
    4. Deduplicate findings at the same (file, line, rule_id) location
    5. Filter out findings below the minimum confidence threshold

    This is the last step before findings reach the output layer.
    """

    def __init__(self, min_confidence: float = 0.30) -> None:
        if not 0.0 <= min_confidence <= 1.0:
            raise ValueError(
                f"min_confidence must be in [0.0, 1.0], got {min_confidence}"
            )
        self.min_confidence = min_confidence

    def score(self, findings: list[Finding]) -> list[Finding]:
        """
        Apply all scoring adjustments to a list of findings.

        Pipeline calls this once with the combined output of all
        analyzers. Returns a filtered, deduplicated, sorted list.
        """
        if not findings:
            return []

        # Step 1 — group by location to detect multi-analyzer convergence
        grouped = self._group_by_location(findings)

        # Step 2 — adjust confidence per group
        adjusted: list[Finding] = []
        for location_findings in grouped.values():
            adjusted.extend(self._adjust_group(location_findings))

        # Step 3 — filter below threshold
        filtered = [f for f in adjusted if f.confidence >= self.min_confidence]

        # Step 4 — sort by severity desc, confidence desc
        return sorted(
            filtered,
            key=lambda f: (f.severity.value, f.confidence),
            reverse=True,
        )

    # ------------------------------------------------------------------
    # Grouping
    # ------------------------------------------------------------------

    @staticmethod
    def _group_by_location(
        findings: list[Finding],
    ) -> dict[tuple, list[Finding]]:
        """
        Group findings by (file, line, cwe_id).

        Same location + same CWE from different analyzers = convergence.
        Different CWEs at the same line = separate issues, keep both.
        """
        groups: dict[tuple, list[Finding]] = defaultdict(list)
        for f in findings:
            key = (f.file, f.line, f.cwe_id)
            groups[key].append(f)
        return groups

    # ------------------------------------------------------------------
    # Per-group adjustment
    # ------------------------------------------------------------------

    def _adjust_group(self, group: list[Finding]) -> list[Finding]:
        """
        Adjust and deduplicate a group of findings at the same location.

        If multiple analyzers flagged the same location, keep the one
        with the highest base confidence and boost it.
        """
        # Pick the highest-confidence finding as the representative
        best = max(group, key=lambda f: f.confidence)

        # Apply all signal adjustments
        new_confidence = best.confidence
        new_confidence = self._apply_convergence_boost(new_confidence, len(group))
        new_confidence = self._apply_name_boost(new_confidence, best.snippet)
        new_confidence = self._apply_placeholder_penalty(new_confidence, best.snippet)
        new_confidence = self._apply_severity_floor(new_confidence, best.severity)
        new_confidence = round(min(new_confidence, 1.0), 3)

        # Dataclasses are frozen-friendly via replace pattern
        adjusted = Finding(
            file        = best.file,
            line        = best.line,
            column      = best.column,
            rule_id     = best.rule_id,
            severity    = self._recalculate_severity(new_confidence, best.severity),
            confidence  = new_confidence,
            message     = best.message,
            remediation = best.remediation,
            cwe_id      = best.cwe_id,
            snippet     = best.snippet,
            tags        = list(set(
                tag for f in group for tag in f.tags
            )),
        )

        return [adjusted]

    # ------------------------------------------------------------------
    # Signal adjustments
    # ------------------------------------------------------------------

    @staticmethod
    def _apply_convergence_boost(confidence: float, analyzer_count: int) -> float:
        """
        Boost confidence when multiple analyzers flagged the same location.

        1 analyzer  → no boost
        2 analyzers → +0.08
        3+ analyzers → +0.15
        """
        if analyzer_count == 2:
            return min(confidence + 0.08, 1.0)
        if analyzer_count >= 3:
            return min(confidence + 0.15, 1.0)
        return confidence

    @staticmethod
    def _apply_name_boost(confidence: float, snippet: str) -> float:
        """
        Boost confidence if the snippet contains a high-risk variable
        name fragment (e.g. 'api_key', 'db_password', 'auth_token').
        """
        snippet_lower = snippet.lower()
        if any(frag in snippet_lower for frag in _HIGH_RISK_NAME_FRAGMENTS):
            return min(confidence + 0.05, 1.0)
        return confidence

    @staticmethod
    def _apply_placeholder_penalty(confidence: float, snippet: str) -> float:
        """
        Penalize findings whose snippet looks like a placeholder value.
        Reduces false positives on tutorial code and example configs.
        """
        snippet_lower = snippet.lower()
        if any(frag in snippet_lower for frag in _PLACEHOLDER_FRAGMENTS):
            return confidence * 0.50
        return confidence

    @staticmethod
    def _apply_severity_floor(confidence: float, severity: Severity) -> float:
        """
        Critical findings get a minimum confidence floor of 0.50.
        Prevents critical issues from being filtered out due to low
        initial confidence — they should always be reviewed manually.
        """
        if severity == Severity.CRITICAL:
            return max(confidence, 0.50)
        return confidence

    @staticmethod
    def _recalculate_severity(confidence: float, original: Severity) -> Severity:
        """
        Downgrade severity if confidence dropped significantly after scoring.
        Never upgrades severity — only downgrades.
        """
        if confidence < 0.35 and original == Severity.CRITICAL:
            return Severity.HIGH
        if confidence < 0.25 and original == Severity.HIGH:
            return Severity.MEDIUM
        return original

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    @staticmethod
    def summarize(findings: list[Finding]) -> dict[str, int]:
        """
        Return a count of findings by severity.
        Used by CLIFormatter to print the summary line.
        """
        counts: dict[str, int] = {s.name: 0 for s in Severity}
        for f in findings:
            counts[f.severity.name] += 1
        return counts