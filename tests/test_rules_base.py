# tests/test_rules_base.py
# Pytest for nonubevigil.rules.base.BaseRule.

from nonubevigil.models import AnalysisContext, Finding, Severity
from nonubevigil.rules.base import BaseRule


class ConcreteRule(BaseRule):
    """Minimal concrete rule for testing BaseRule helpers."""

    rule_id = "TEST001"
    severity = Severity.MEDIUM
    confidence_base = 0.6
    languages = ["python"]
    description = "Test rule"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        return []


class TestBaseRuleCommentDetection:
    """Tests for is_comment_line."""

    def test_python_comment(self) -> None:
        rule = ConcreteRule()
        assert rule.is_comment_line("# comment") is True
        assert rule.is_comment_line("   # comment") is True

    def test_double_slash_comment(self) -> None:
        rule = ConcreteRule()
        assert rule.is_comment_line("// comment") is True
        assert rule.is_comment_line("  // comment") is True

    def test_not_comment(self) -> None:
        rule = ConcreteRule()
        assert rule.is_comment_line("x = 1") is False
        assert rule.is_comment_line("url = 'http://example.com'") is False


class TestBaseRuleMakeFinding:
    """Tests for make_finding helper."""

    def test_make_finding_uses_context_and_defaults(self) -> None:
        rule = ConcreteRule()
        ctx = AnalysisContext(
            file_path="/path/to/file.py",
            source="line1\nsecret = 'x'\nline3",
            language="python",
        )
        f = rule.make_finding(
            context=ctx,
            line=2,
            column=0,
            message="Found secret",
            remediation="Use env",
        )
        assert f.file == "/path/to/file.py"
        assert f.line == 2
        assert f.column == 0
        assert f.rule_id == "TEST001"
        assert f.severity == Severity.MEDIUM
        assert f.confidence == 0.6
        assert f.message == "Found secret"
        assert f.remediation == "Use env"
        assert f.snippet == "secret = 'x'"

    def test_make_finding_override_severity_confidence(self) -> None:
        rule = ConcreteRule()
        ctx = AnalysisContext(file_path="a.py", source="x", language="py")
        f = rule.make_finding(
            context=ctx,
            line=1,
            column=0,
            message="m",
            remediation="r",
            severity=Severity.CRITICAL,
            confidence=0.9,
        )
        assert f.severity == Severity.CRITICAL
        assert f.confidence == 0.9

    def test_make_finding_cwe_and_tags(self) -> None:
        rule = ConcreteRule()
        ctx = AnalysisContext(file_path="a.py", source="x", language="py")
        f = rule.make_finding(
            context=ctx,
            line=1,
            column=0,
            message="m",
            remediation="r",
            cwe_id="CWE-798",
            tags=["secret", "credential"],
        )
        assert f.cwe_id == "CWE-798"
        assert "secret" in f.tags and "credential" in f.tags


class TestBaseRuleRepr:
    """Tests for BaseRule __repr__."""

    def test_repr_contains_class_and_rule_id(self) -> None:
        rule = ConcreteRule()
        r = repr(rule)
        assert "ConcreteRule" in r
        assert "TEST001" in r
