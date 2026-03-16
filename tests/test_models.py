# tests/test_models.py
# Pytest for nonubevigil.models: Severity, Finding, AnalysisContext.

import pytest

from nonubevigil.models import AnalysisContext, Finding, Severity


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

class TestSeverity:
    """Tests for Severity enum."""

    def test_ordering(self) -> None:
        assert Severity.INFO < Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.LOW <= Severity.LOW
        assert Severity.MEDIUM >= Severity.LOW

    def test_value_order(self) -> None:
        assert Severity.INFO.value == 0
        assert Severity.CRITICAL.value == 4

    def test_color_is_ansi_escape(self) -> None:
        for s in Severity:
            assert s.color.startswith("\033[")
            assert "m" in s.color

    def test_label_fixed_width(self) -> None:
        for s in Severity:
            assert s.label == f"{s.name:<8}"


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

class TestFinding:
    """Tests for Finding dataclass."""

    def test_valid_finding_creation(self) -> None:
        f = Finding(
            file="a.py",
            line=1,
            column=0,
            rule_id="SEC001",
            severity=Severity.HIGH,
            confidence=0.8,
            message="msg",
            remediation="fix",
        )
        assert f.file == "a.py"
        assert f.line == 1
        assert f.column == 0
        assert f.confidence == 0.8

    def test_confidence_bounds_invalid_low(self) -> None:
        with pytest.raises(ValueError, match="confidence"):
            Finding(
                file="a.py",
                line=1,
                column=0,
                rule_id="SEC001",
                severity=Severity.MEDIUM,
                confidence=-0.1,
                message="m",
                remediation="r",
            )

    def test_confidence_bounds_invalid_high(self) -> None:
        with pytest.raises(ValueError, match="confidence"):
            Finding(
                file="a.py",
                line=1,
                column=0,
                rule_id="SEC001",
                severity=Severity.MEDIUM,
                confidence=1.5,
                message="m",
                remediation="r",
            )

    def test_line_must_be_positive(self) -> None:
        with pytest.raises(ValueError, match="line"):
            Finding(
                file="a.py",
                line=0,
                column=0,
                rule_id="SEC001",
                severity=Severity.MEDIUM,
                confidence=0.5,
                message="m",
                remediation="r",
            )

    def test_column_must_be_non_negative(self) -> None:
        with pytest.raises(ValueError, match="column"):
            Finding(
                file="a.py",
                line=1,
                column=-1,
                rule_id="SEC001",
                severity=Severity.MEDIUM,
                confidence=0.5,
                message="m",
                remediation="r",
            )

    def test_cwe_name_known(self) -> None:
        f = Finding(
            file="a.py",
            line=1,
            column=0,
            rule_id="SEC001",
            severity=Severity.HIGH,
            confidence=0.7,
            message="m",
            remediation="r",
            cwe_id="CWE-798",
        )
        assert "Hard-coded" in f.cwe_name or "798" in f.cwe_name

    def test_cwe_name_unknown_falls_back(self) -> None:
        f = Finding(
            file="a.py",
            line=1,
            column=0,
            rule_id="X",
            severity=Severity.LOW,
            confidence=0.5,
            message="m",
            remediation="r",
            cwe_id="CWE-99999",
        )
        assert f.cwe_name == "CWE-99999"

    def test_is_critical(self) -> None:
        f_high = Finding(
            file="a.py", line=1, column=0, rule_id="X",
            severity=Severity.HIGH, confidence=0.8, message="m", remediation="r",
        )
        f_crit = Finding(
            file="a.py", line=1, column=0, rule_id="X",
            severity=Severity.CRITICAL, confidence=0.8, message="m", remediation="r",
        )
        assert not f_high.is_critical
        assert f_crit.is_critical

    def test_is_actionable(self) -> None:
        f_high = Finding(
            file="a.py", line=1, column=0, rule_id="X",
            severity=Severity.MEDIUM, confidence=0.75, message="m", remediation="r",
        )
        f_low = Finding(
            file="a.py", line=1, column=0, rule_id="X",
            severity=Severity.MEDIUM, confidence=0.50, message="m", remediation="r",
        )
        assert f_high.is_actionable
        assert not f_low.is_actionable

    def test_fingerprint_deterministic(self) -> None:
        f = Finding(
            file="a.py", line=1, column=0, rule_id="SEC001",
            severity=Severity.HIGH, confidence=0.7, message="m", remediation="r",
            snippet="api_key = 'x'",
        )
        assert f.fingerprint == f.fingerprint
        assert len(f.fingerprint) == 16

    def test_to_dict_contains_expected_keys(self) -> None:
        f = Finding(
            file="a.py", line=1, column=0, rule_id="SEC001",
            severity=Severity.HIGH, confidence=0.7, message="m", remediation="r",
        )
        d = f.to_dict()
        assert "file" in d and "line" in d and "rule_id" in d
        assert "severity" in d and "confidence" in d
        assert d["severity"] == "HIGH"
        assert d["confidence"] == 0.7

    def test_to_sarif_result_structure(self) -> None:
        f = Finding(
            file="a.py", line=5, column=2, rule_id="SEC001",
            severity=Severity.HIGH, confidence=0.7, message="m", remediation="r",
        )
        sarif = f.to_sarif_result()
        assert sarif["ruleId"] == "SEC001"
        assert "message" in sarif and "locations" in sarif
        reg = sarif["locations"][0]["physicalLocation"]["region"]
        assert reg["startLine"] == 5
        assert reg["startColumn"] == 3  # column is 0-based in Finding


# ---------------------------------------------------------------------------
# AnalysisContext
# ---------------------------------------------------------------------------

class TestAnalysisContext:
    """Tests for AnalysisContext."""

    def test_lines_populated_from_source(self) -> None:
        ctx = AnalysisContext(file_path="x.py", source="a\nb\nc", language="python")
        assert ctx.lines == ["a", "b", "c"]

    def test_mark_tainted_and_is_tainted(self) -> None:
        ctx = AnalysisContext(file_path="x.py", source="x=1", language="python")
        assert not ctx.is_tainted("user_input")
        ctx.mark_tainted("user_input")
        assert ctx.is_tainted("user_input")

    def test_propagate_taint(self) -> None:
        ctx = AnalysisContext(file_path="x.py", source="x=1", language="python")
        ctx.mark_tainted("a")
        ctx.propagate_taint("a", "b")
        assert ctx.is_tainted("b")
        ctx.propagate_taint("c", "d")  # c not tainted
        assert not ctx.is_tainted("d")

    def test_get_line(self) -> None:
        ctx = AnalysisContext(file_path="x.py", source="first\nsecond\nthird", language="py")
        assert ctx.get_line(1) == "first"
        assert ctx.get_line(2) == "second"
        assert ctx.get_line(0) == ""
        assert ctx.get_line(10) == ""

    def test_get_window(self) -> None:
        ctx = AnalysisContext(
            file_path="x.py",
            source="L1\nL2\nL3\nL4\nL5",
            language="py",
        )
        win = ctx.get_window(3, before=1, after=1)
        assert win == [(2, "L2"), (3, "L3"), (4, "L4")]
        win2 = ctx.get_window(1, before=2, after=2)
        assert len(win2) == 3  # 1,2,3
        assert win2[0] == (1, "L1")
