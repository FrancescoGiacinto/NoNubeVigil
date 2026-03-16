from __future__ import annotations

import re

from ..models import AnalysisContext, Finding, Severity
from .base import BaseRule


# Dangerous deserialization functions by language
_DESER_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # (pattern, language_hint, description)
    (
        re.compile(r'pickle\.loads?\s*\('),
        "python",
        "pickle.load() deserializes arbitrary Python objects — remote code execution if input is untrusted",
    ),
    (
        re.compile(r'yaml\.load\s*\([^,)]+\)(?!\s*,\s*Loader\s*=\s*yaml\.SafeLoader)'),
        "python",
        "yaml.load() without SafeLoader allows arbitrary code execution",
    ),
    (
        re.compile(r'marshal\.loads?\s*\('),
        "python",
        "marshal.load() is unsafe with untrusted data",
    ),
    (
        re.compile(r'ObjectInputStream\s*\('),
        "java",
        "Java ObjectInputStream deserializes arbitrary classes — potential RCE",
    ),
    (
        re.compile(r'JSON\.parse\s*\([^)]*\+'),
        "javascript",
        "JSON.parse() called with concatenated input — validate before parsing",
    ),
    (
        re.compile(r'unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'),
        "php",
        "PHP unserialize() on user input — critical RCE risk",
    ),
]

# Taint sources
_TAINT_SOURCES: list[re.Pattern] = [
    re.compile(r'([A-Za-z_]\w*)\s*=\s*request\.(?:body|data|get_data|stream)'),
    re.compile(r'([A-Za-z_]\w*)\s*=\s*(?:sys\.stdin|open\s*\()'),
    re.compile(r'([A-Za-z_]\w*)\s*=\s*socket\.recv\s*\('),
]


class InsecureDeserializationRule(BaseRule):

    rule_id:         str       = "SEC004"
    severity:        Severity  = Severity.CRITICAL
    confidence_base: float     = 0.75
    languages:       list[str] = ["python", "java", "javascript", "php"]
    description:     str       = "Detects use of insecure deserialization functions on potentially untrusted data"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []

        self._collect_taint_sources(context)

        for line_num, line in enumerate(context.lines, start=1):
            if self.is_comment_line(line):
                continue

            for pattern, lang_hint, description in _DESER_PATTERNS:
                match = pattern.search(line)
                if not match:
                    continue

                # Check if any tainted variable appears in this line
                taint_match = any(var in line for var in context.tainted_vars)

                confidence = 0.90 if taint_match else 0.75

                findings.append(self.make_finding(
                    context     = context,
                    line        = line_num,
                    column      = match.start(),
                    message     = description,
                    remediation = (
                        "Never deserialize data from untrusted sources with unsafe functions. "
                        "For Python: use json instead of pickle, yaml.safe_load() instead of yaml.load(). "
                        "For Java: use a deserialization filter (ObjectInputFilter) or switch to JSON/Protobuf. "
                        "For PHP: avoid unserialize() on user input entirely."
                    ),
                    cwe_id      = "CWE-502",
                    confidence  = confidence,
                    severity    = Severity.CRITICAL,
                    tags        = ["deserialization", "rce", lang_hint],
                ))

        return findings

    @staticmethod
    def _collect_taint_sources(context: AnalysisContext) -> None:
        for line in context.lines:
            for pattern in _TAINT_SOURCES:
                match = pattern.search(line)
                if match:
                    context.mark_tainted(match.group(1))