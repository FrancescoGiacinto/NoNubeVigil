from __future__ import annotations

import re

from ..models import AnalysisContext, Finding, Severity


# User-controlled input sources by language
_SOURCES: dict[str, list[re.Pattern]] = {
    "python": [
        re.compile(r'([A-Za-z_]\w*)\s*=\s*request\.(?:args|form|json|data|files|cookies)\b'),
        re.compile(r'([A-Za-z_]\w*)\s*=\s*(?:input|raw_input)\s*\('),
        re.compile(r'([A-Za-z_]\w*)\s*=\s*sys\.argv\b'),
        re.compile(r'([A-Za-z_]\w*)\s*=\s*os\.environ\.get\s*\('),
    ],
    "javascript": [
        re.compile(r'([A-Za-z_]\w*)\s*=\s*req\.(?:body|query|params|headers)\b'),
        re.compile(r'([A-Za-z_]\w*)\s*=\s*request\.(?:body|query|params)\b'),
        re.compile(r'([A-Za-z_]\w*)\s*=\s*(?:location\.search|location\.hash)\b'),
    ],
    "java": [
        re.compile(r'([A-Za-z_]\w*)\s*=\s*request\.getParameter\s*\('),
        re.compile(r'([A-Za-z_]\w*)\s*=\s*request\.getHeader\s*\('),
    ],
}

# Dangerous sinks — reaching these with tainted data is a finding
_SINKS: dict[str, list[tuple[re.Pattern, str, str, str]]] = {
    "python": [
        (
            re.compile(r'(?:execute|executemany|raw)\s*\(([^)]+)\)'),
            "CWE-089", "Tainted variable reaches SQL execution sink",
            "Use parameterized queries instead of string interpolation.",
        ),
        (
            re.compile(r'os\.(?:system|popen)\s*\(([^)]+)\)'),
            "CWE-078", "Tainted variable reaches OS command execution sink",
            "Validate input strictly. Use subprocess with shell=False.",
        ),
        (
            re.compile(r'(?:open|file)\s*\(([^)]+)\)'),
            "CWE-022", "Tainted variable reaches file system sink — path traversal risk",
            "Sanitize and validate file paths. Use pathlib.Path.resolve() and check against a base directory.",
        ),
    ],
    "javascript": [
        (
            re.compile(r'\.innerHTML\s*=\s*([^;]+)'),
            "CWE-079", "Tainted variable reaches DOM XSS sink",
            "Use textContent instead of innerHTML, or sanitize with DOMPurify.",
        ),
        (
            re.compile(r'(?:query|db\.execute)\s*\(([^)]+)\)'),
            "CWE-089", "Tainted variable reaches SQL sink",
            "Use parameterized queries.",
        ),
    ],
    "java": [
        (
            re.compile(r'(?:executeQuery|executeUpdate)\s*\(([^)]+)\)'),
            "CWE-089", "Tainted variable reaches SQL sink",
            "Use PreparedStatement with parameterized queries.",
        ),
        (
            re.compile(r'Runtime\.exec\s*\(([^)]+)\)'),
            "CWE-078", "Tainted variable reaches command execution sink",
            "Validate input and use a whitelist of allowed commands.",
        ),
    ],
}

# Propagation — taint spreads through these assignment patterns
_PROPAGATION = re.compile(
    r'([A-Za-z_]\w*)\s*=\s*.*?([A-Za-z_]\w+)'
)

# Sanitizers — if these wrap a tainted var, remove taint
_SANITIZERS: list[re.Pattern] = [
    re.compile(r'escape\s*\('),
    re.compile(r'sanitize\s*\('),
    re.compile(r'quote\s*\('),
    re.compile(r'parameterize\s*\('),
    re.compile(r'bleach\.clean\s*\('),
    re.compile(r'DOMPurify\.sanitize\s*\('),
    re.compile(r'PreparedStatement'),
]


class DataFlowAnalyzer:
    """
    Tracks tainted data from user-controlled sources to dangerous sinks.

    This is the highest-precision analyzer in vigil. It performs a
    simplified single-pass taint analysis:

      1. Source pass  — identify variables assigned from user input
      2. Propagation  — spread taint through assignments
      3. Sink pass    — flag tainted variables reaching dangerous functions

    Findings from this analyzer carry the highest confidence scores
    because they require both a source and a sink to fire.
    """

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []

        sources = _SOURCES.get(context.language, [])
        sinks   = _SINKS.get(context.language, [])

        if not sources or not sinks:
            return findings

        # Pass 1 — collect taint sources
        self._collect_sources(context, sources)

        # Pass 2 — propagate taint through assignments
        self._propagate(context)

        # Pass 3 — check sinks
        findings.extend(self._check_sinks(context, sinks))

        return findings

    # ------------------------------------------------------------------
    # Pass 1 — sources
    # ------------------------------------------------------------------

    def _collect_sources(
        self,
        context: AnalysisContext,
        sources: list[re.Pattern],
    ) -> None:
        for line in context.lines:
            for pattern in sources:
                match = pattern.search(line)
                if match:
                    context.mark_tainted(match.group(1))

    # ------------------------------------------------------------------
    # Pass 2 — propagation
    # ------------------------------------------------------------------

    def _propagate(self, context: AnalysisContext) -> None:
        """
        Single-pass propagation — if the RHS of an assignment contains
        a tainted variable, the LHS becomes tainted too.

        Runs twice to catch chains: a = input(); b = a; c = b
        """
        for _ in range(2):
            for line in context.lines:
                match = _PROPAGATION.search(line)
                if not match:
                    continue
                target = match.group(1)
                source = match.group(2)
                context.propagate_taint(source, target)

    # ------------------------------------------------------------------
    # Pass 3 — sinks
    # ------------------------------------------------------------------

    def _check_sinks(
        self,
        context: AnalysisContext,
        sinks:   list[tuple],
    ) -> list[Finding]:
        findings: list[Finding] = []

        for line_num, line in enumerate(context.lines, start=1):
            stripped = line.lstrip()
            if stripped.startswith(("#", "//", "*", "--")):
                continue

            is_sanitized = any(s.search(line) for s in _SANITIZERS)

            for sink_pattern, cwe_id, message, remediation in sinks:
                match = sink_pattern.search(line)
                if not match:
                    continue

                sink_args = match.group(1)

                # Find which tainted variables reach this sink
                tainted_in_sink = [
                    var for var in context.tainted_vars
                    if var in sink_args
                ]

                if not tainted_in_sink:
                    continue

                confidence = 0.90 if not is_sanitized else 0.25

                if confidence < 0.30:
                    continue

                findings.append(Finding(
                    file        = context.file_path,
                    line        = line_num,
                    column      = match.start(),
                    rule_id     = "DFA001",
                    severity    = Severity.CRITICAL,
                    confidence  = confidence,
                    message     = (
                        f"{message} — tainted variable(s): "
                        f"{', '.join(tainted_in_sink)}"
                    ),
                    remediation = remediation,
                    cwe_id      = cwe_id,
                    snippet     = context.get_line(line_num),
                    tags        = ["taint", "dataflow", cwe_id.lower()],
                ))

        return findings