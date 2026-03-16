# tests/conftest.py
# Shared pytest fixtures for nonubevigil tests.

from pathlib import Path

import pytest

from nonubevigil.models import AnalysisContext, Finding, Severity


@pytest.fixture
def sample_finding() -> Finding:
    """Minimal valid Finding for use in tests."""
    return Finding(
        file="src/app.py",
        line=10,
        column=0,
        rule_id="SEC001",
        severity=Severity.HIGH,
        confidence=0.75,
        message="Potential hardcoded secret",
        remediation="Use env vars",
    )


@pytest.fixture
def sample_context() -> AnalysisContext:
    """Minimal AnalysisContext with a few lines of source."""
    source = "x = 1\napi_key = 'sk-12345'\n# comment\n"
    return AnalysisContext(file_path="test.py", source=source, language="python")
