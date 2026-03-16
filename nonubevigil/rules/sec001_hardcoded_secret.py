from __future__ import annotations

import math
import re

from ..models import AnalysisContext, Finding, Severity
from .base import BaseRule


_SECRET_KEY_PATTERN = re.compile(
    r"""
    (?:^|[_\-\.\s])
    (?:
        api[_\-]?key         |
        secret[_\-]?key      |
        access[_\-]?token    |
        auth[_\-]?token      |
        bearer[_\-]?token    |
        private[_\-]?key     |
        client[_\-]?secret   |
        db[_\-]?pass(?:word)?|
        database[_\-]?pass   |
        smtp[_\-]?pass       |
        aws[_\-]?secret      |
        github[_\-]?token    |
        stripe[_\-]?key      |
        twilio[_\-]?token    |
        slack[_\-]?token     |
        jwt[_\-]?secret      |
        encryption[_\-]?key  |
        passwd | password
    )
    (?:[_\-\.\s]|$)
    """,
    re.IGNORECASE | re.VERBOSE,
)

_ASSIGNMENT_PATTERNS: list[re.Pattern] = [
    re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["\']([^"\']{8,})["\']'),
    re.compile(r'(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["\']([^"\']{8,})["\']'),
    re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\s*[=:]\s*["\']?([A-Za-z0-9+/=_\-\.]{8,})["\']?'),
    re.compile(r'(?:String|final\s+String)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"]{8,})"'),
]

_PLACEHOLDERS = {
    "change_me", "changeme", "your_key_here", "your_secret_here",
    "placeholder", "example", "todo", "fixme", "insert_here",
    "replace_me", "dummy", "test", "fake", "sample",
}

_ENTROPY_THRESHOLD = 3.5


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def _confidence_from_entropy(entropy: float, value_len: int) -> float:
    if value_len < 8:
        return 0.0
    if entropy >= 4.5:
        return 0.95
    if entropy >= 4.0:
        return 0.85
    if entropy >= 3.5:
        length_bonus = min(0.1, (value_len - 8) * 0.005)
        return round(0.70 + length_bonus, 2)
    if entropy >= 3.0:
        return 0.40
    return 0.0


class HardcodedSecretRule(BaseRule):

    rule_id:         str       = "SEC001"
    severity:        Severity  = Severity.HIGH
    confidence_base: float     = 0.7
    languages:       list[str] = []
    description:     str       = "Detects hardcoded secrets using key name patterns and Shannon entropy"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []

        for line_num, line in enumerate(context.lines, start=1):
            if self.is_comment_line(line):
                continue

            for pattern in _ASSIGNMENT_PATTERNS:
                for match in pattern.finditer(line):
                    key_name = match.group(1)
                    value    = match.group(2)

                    if not _SECRET_KEY_PATTERN.search(key_name):
                        continue

                    if value.lower() in _PLACEHOLDERS:
                        continue

                    entropy    = _shannon_entropy(value)
                    confidence = _confidence_from_entropy(entropy, len(value))

                    if confidence == 0.0:
                        continue

                    severity = (
                        Severity.HIGH   if confidence >= 0.70 else
                        Severity.MEDIUM if confidence >= 0.40 else
                        Severity.LOW
                    )

                    findings.append(self.make_finding(
                        context     = context,
                        line        = line_num,
                        column      = match.start(),
                        message     = (
                            f"Potential hardcoded secret in '{key_name}' "
                            f"(entropy: {entropy:.2f} bits/char, length: {len(value)})"
                        ),
                        remediation = (
                            "Move the value to an environment variable or a secrets manager "
                            "(e.g. AWS Secrets Manager, HashiCorp Vault, .env + python-dotenv). "
                            "Never commit secrets to version control."
                        ),
                        cwe_id      = "CWE-798",
                        confidence  = confidence,
                        severity    = severity,
                        tags        = ["hardcoded-secret", "credentials"],
                    ))

        return self._deduplicate(findings)

    @staticmethod
    def _deduplicate(findings: list[Finding]) -> list[Finding]:
        best: dict[tuple[str, int], Finding] = {}
        for f in findings:
            key = (f.file, f.line)
            if key not in best or f.confidence > best[key].confidence:
                best[key] = f
        return list(best.values())