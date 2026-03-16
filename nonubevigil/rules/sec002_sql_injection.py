from __future__ import annotations

import re

from ..models import AnalysisContext, Finding, Severity
from .base import BaseRule


# Patterns that match dangerous string concatenation into SQL queries
_SQL_CONCAT_PATTERNS: list[re.Pattern] = [
    # Python: "SELECT * FROM " + user_var  or  f"SELECT ... {var}"
    re.compile(r'(?:execute|query|raw)\s*\(\s*["\'].*?(?:SELECT|INSERT|UPDATE|DELETE).*?["\']\s*[+%]', re.IGNORECASE),
    re.compile(r'f["\'].*?(?:SELECT|INSERT|UPDATE|DELETE).*?\{', re.IGNORECASE),
    # JS/TS: db.query("SELECT ... " + userInput)
    re.compile(r'(?:query|execute)\s*\(\s*["`\'].*?(?:SELECT|INSERT|UPDATE|DELETE).*?["`\']\s*\+', re.IGNORECASE),
    # Java: statement.executeQuery("SELECT ... " + var)
    re.compile(r'executeQuery\s*\(\s*".*?(?:SELECT|INSERT|UPDATE|DELETE).*?"\s*\+', re.IGNORECASE),
]

# Taint sources — assignments that bring user input into scope
_TAINT_SOURCES: list[re.Pattern] = [
    re.compile(r'([A-Za-z_]\w*)\s*=\s*request\.(?:args|form|json|data|params)'),
    re.compile(r'([A-Za-z_]\w*)\s*=\s*(?:input|raw_input)\s*\('),
    re.compile(r'([A-Za-z_]\w*)\s*=\s*req\.(?:body|query|params)'),
    re.compile(r'([A-Za-z_]\w*)\s*=\s*sys\.argv'),
]

# Sink patterns — dangerous SQL execution functions
_SQL_SINKS: list[re.Pattern] = [
    re.compile(r'(?:execute|executemany|raw|query)\s*\(([^)]+)\)'),
    re.compile(r'(?:executeQuery|executeUpdate|prepareStatement)\s*\(([^)]+)\)'),
]


class SqlInjectionRule(BaseRule):

    rule_id:         str       = "SEC002"
    severity:        Severity  = Severity.CRITICAL
    confidence_base: float     = 0.6
    languages:       list[str] = ["python", "javascript", "java"]
    description:     str       = "Detects SQL injection via string concatenation and taint analysis"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []

        # Pass 1 — collect taint sources into context
        self._collect_taint_sources(context)

        for line_num, line in enumerate(context.lines, start=1):
            if self.is_comment_line(line):
                continue

            # Gate 1 — direct string concatenation into SQL (high confidence)
            for pattern in _SQL_CONCAT_PATTERNS:
                if pattern.search(line):
                    findings.append(self.make_finding(
                        context     = context,
                        line        = line_num,
                        column      = pattern.search(line).start(),
                        message     = "SQL query built with string concatenation — potential SQL injection",
                        remediation = (
                            "Use parameterized queries or an ORM. "
                            "Never concatenate user input directly into SQL strings. "
                            "Example: cursor.execute('SELECT * FROM t WHERE id = %s', (user_id,))"
                        ),
                        cwe_id      = "CWE-089",
                        confidence  = 0.85,
                        severity    = Severity.CRITICAL,
                        tags        = ["sql-injection", "injection", "concatenation"],
                    ))

            # Gate 2 — tainted variable reaching a SQL sink (taint analysis)
            for sink_pattern in _SQL_SINKS:
                match = sink_pattern.search(line)
                if not match:
                    continue
                sink_args = match.group(1)
                for var in context.tainted_vars:
                    if var in sink_args:
                        findings.append(self.make_finding(
                            context     = context,
                            line        = line_num,
                            column      = match.start(),
                            message     = (
                                f"Tainted variable '{var}' (from user input) "
                                f"reaches SQL execution sink"
                            ),
                            remediation = (
                                "Use parameterized queries. "
                                f"'{var}' originates from user-controlled input — "
                                "pass it as a parameter, not as part of the query string."
                            ),
                            cwe_id      = "CWE-089",
                            confidence  = 0.90,
                            severity    = Severity.CRITICAL,
                            tags        = ["sql-injection", "taint", "injection"],
                        ))

        return findings

    @staticmethod
    def _collect_taint_sources(context: AnalysisContext) -> None:
        """
        First pass: mark variables that receive user-controlled input.
        Results are stored in context.tainted_vars for use in Gate 2
        and by other rules in the same pipeline run.
        """
        for line in context.lines:
            for pattern in _TAINT_SOURCES:
                match = pattern.search(line)
                if match:
                    context.mark_tainted(match.group(1))