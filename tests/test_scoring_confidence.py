# tests/test_scoring_confidence.py
# Pytest for nonubevigil.scoring.confidence.ConfidenceScorer.

import pytest

from nonubevigil.models import Finding, Severity
from nonubevigil.scoring.confidence import ConfidenceScorer


@pytest.fixture
def scorer() -> ConfidenceScorer:
    return ConfidenceScorer(min_confidence=0.30)


def _finding(
    file: str = "a.py",
    line: int = 1,
    confidence: float = 0.6,
    severity: Severity = Severity.MEDIUM,
    snippet: str = "",
    cwe_id: str = "CWE-798",
) -> Finding:
    return Finding(
        file=file,
        line=line,
        column=0,
        rule_id="SEC001",
        severity=severity,
        confidence=confidence,
        message="test",
        remediation="fix",
        snippet=snippet,
        cwe_id=cwe_id,
    )


class TestConfidenceScorerInit:
    """Tests for ConfidenceScorer constructor."""

    def test_valid_min_confidence(self) -> None:
        s = ConfidenceScorer(min_confidence=0.5)
        assert s.min_confidence == 0.5

    def test_invalid_min_confidence_low(self) -> None:
        with pytest.raises(ValueError, match="min_confidence"):
            ConfidenceScorer(min_confidence=-0.1)

    def test_invalid_min_confidence_high(self) -> None:
        with pytest.raises(ValueError, match="min_confidence"):
            ConfidenceScorer(min_confidence=1.5)


class TestConfidenceScorerScore:
    """Tests for score() method."""

    def test_empty_findings_returns_empty(self, scorer: ConfidenceScorer) -> None:
        assert scorer.score([]) == []

    def test_single_finding_above_threshold_returned(
        self, scorer: ConfidenceScorer
    ) -> None:
        findings = [_finding(confidence=0.8)]
        result = scorer.score(findings)
        assert len(result) == 1
        assert result[0].confidence >= 0.30

    def test_finding_below_threshold_filtered(self, scorer: ConfidenceScorer) -> None:
        findings = [_finding(confidence=0.20)]
        result = scorer.score(findings)
        assert len(result) == 0

    def test_deduplication_same_location(self, scorer: ConfidenceScorer) -> None:
        findings = [
            _finding(file="a.py", line=10, confidence=0.5),
            _finding(file="a.py", line=10, confidence=0.7),
        ]
        result = scorer.score(findings)
        assert len(result) == 1
        assert result[0].confidence >= 0.5  # convergence or best kept

    def test_summarize_counts_by_severity(self) -> None:
        findings = [
            _finding(severity=Severity.HIGH),
            _finding(severity=Severity.HIGH),
            _finding(severity=Severity.LOW),
        ]
        summary = ConfidenceScorer.summarize(findings)
        assert summary["HIGH"] == 2
        assert summary["LOW"] == 1


class TestConfidenceScorerGrouping:
    """Tests for _group_by_location."""

    def test_group_by_file_line_cwe(self) -> None:
        findings = [
            _finding(file="a.py", line=1, cwe_id="CWE-798"),
            _finding(file="a.py", line=1, cwe_id="CWE-798"),
            _finding(file="b.py", line=1, cwe_id="CWE-798"),
        ]
        groups = ConfidenceScorer._group_by_location(findings)
        assert len(groups) == 2
        key_a = ("a.py", 1, "CWE-798")
        key_b = ("b.py", 1, "CWE-798")
        assert len(groups[key_a]) == 2
        assert len(groups[key_b]) == 1
