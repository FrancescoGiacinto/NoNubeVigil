from __future__ import annotations

import re

from ..models import AnalysisContext, Finding, Severity
from .base import BaseRule


# Dangerous sinks that write unsanitized content to the DOM or response
_XSS_SINK_PATTERNS: list[re.Pattern] = [
    # JS: element.innerHTML = var  /  document.write(var)
    re.compile(r'\.innerHTML\s*=\s*([A-Za-z_]\w*)', re.IGNORECASE),
    re.compile(r'document\.write\s*\(([^)]+)\)',     re.IGNORECASE),
    re.compile(r'\.outerHTML\s*=\s*([A-Za-z_]\w*)', re.IGNORECASE),
    # Python/Jinja: Markup(var) or render without escaping
    re.compile(r'Markup\s*\(\s*([A-Za-z_]\w*)\s*\)'),
    # Python: return var directly in response without escaping
    re.compile(r'(?:HttpResponse|make_response)\s*\(\s*([A-Za-z_]\w*)'),
]

# Taint sources specific to XSS context
_XSS_TAINT_SOURCES: list[re.Pattern] = [
    re.compile(r'([A-Za-z_]\w*)\s*=\s*request\.(?:args|form|json|data|params)'),
    re.compile(r'([A-Za-z_]\w*)\s*=\s*req\.(?:body|query|params)'),
    re.compile(r'([A-Za-z_]\w*)\s*=\s*(?:location\.search|location\.hash|document\.URL)'),
]

# Safe patterns — if these appear on the same line, confidence drops
_SANITIZERS: list[re.Pattern] = [
    re.compile(r'escape\s*\('),
    re.compile(r'sanitize\s*\('),
    re.compile(r'encodeURIComponent\s*\('),
    re.compile(r'DOMPurify\.sanitize\s*\('),
    re.compile(r'bleach\.clean\s*\('),
]


class XssRule(BaseRule):

    rule_id:         str       = "SEC003"
    severity:        Severity  = Severity.HIGH
    confidence_base: float     = 0.65
    languages:       list[str] = ["javascript", "python", "typescript"]
    description:     str       = "Detects reflected and stored XSS via taint analysis on DOM sinks"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []

        self._collect_taint_sources(context)

        for line_num, line in enumerate(context.lines, start=1):
            if self.is_comment_line(line):
                continue

            # Check if a sanitizer is already applied on this line
            is_sanitized = any(s.search(line) for s in _SANITIZERS)

            for sink_pattern in _XSS_SINK_PATTERNS:
                match = sink_pattern.search(line)
                if not match:
                    continue

                sink_var   = match.group(1).strip()
                confidence = 0.5

                # Boost confidence if the sink variable is tainted
                if context.is_tainted(sink_var):
                    confidence = 0.90
                # Lower confidence if a sanitizer is present on the same line
                if is_sanitized:
                    confidence *= 0.3

                if confidence < 0.30:
                    continue

                findings.append(self.make_finding(
                    context     = context,
                    line        = line_num,
                    column      = match.start(),
                    message     = (
                        f"Unsanitized variable '{sink_var}' written to "
                        f"XSS sink — potential cross-site scripting"
                    ),
                    remediation = (
                        "Sanitize all user-controlled data before writing to the DOM or HTTP response. "
                        "Use DOMPurify for HTML, encodeURIComponent for URLs, "
                        "or a templating engine with auto-escaping enabled."
                    ),
                    cwe_id      = "CWE-079",
                    confidence  = round(confidence, 2),
                    severity    = Severity.HIGH if confidence >= 0.70 else Severity.MEDIUM,
                    tags        = ["xss", "injection", "dom"],
                ))

        return findings

    @staticmethod
    def _collect_taint_sources(context: AnalysisContext) -> None:
        for line in context.lines:
            for pattern in _XSS_TAINT_SOURCES:
                match = pattern.search(line)
                if match:
                    context.mark_tainted(match.group(1))