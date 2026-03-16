from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from .severity import Severity


# ---------------------------------------------------------------------------
# CWE registry (subset)
# ---------------------------------------------------------------------------

CWE_NAMES: dict[str, str] = {
    "CWE-078": "Improper Neutralization of Special Elements (OS Command Injection)",
    "CWE-079": "Improper Neutralization of Input During Web Page Generation (XSS)",
    "CWE-089": "Improper Neutralization of Special Elements in SQL Command (SQL Injection)",
    "CWE-094": "Improper Control of Generation of Code (Code Injection)",
    "CWE-200": "Exposure of Sensitive Information to Unauthorized Actor",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-328": "Use of Weak Hash",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-611": "Improper Restriction of XML External Entity Reference (XXE)",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
}

CWE_TO_OWASP: dict[str, str] = {
    "CWE-078": "A03:2021 – Injection",
    "CWE-079": "A03:2021 – Injection",
    "CWE-089": "A03:2021 – Injection",
    "CWE-094": "A03:2021 – Injection",
    "CWE-200": "A02:2021 – Cryptographic Failures",
    "CWE-306": "A07:2021 – Identification and Authentication Failures",
    "CWE-327": "A02:2021 – Cryptographic Failures",
    "CWE-328": "A02:2021 – Cryptographic Failures",
    "CWE-502": "A08:2021 – Software and Data Integrity Failures",
    "CWE-611": "A05:2021 – Security Misconfiguration",
    "CWE-798": "A07:2021 – Identification and Authentication Failures",
    "CWE-918": "A10:2021 – Server-Side Request Forgery",
}


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """
    Single rule match result — the core output unit of vigil.

    Every analyzer and rule produces a list[Finding].
    Pipeline collects them all, ConfidenceScorer adjusts them,
    and the output layer (CLIFormatter / SARIFExporter / PDFReporter)
    consumes them.

    Fields
    ------
    file        : absolute or relative path to the scanned file
    line        : 1-based line number of the finding
    column      : 0-based column offset of the match
    rule_id     : unique rule identifier (e.g. "SEC001")
    severity    : Severity enum value
    confidence  : float in [0.0, 1.0] — certainty that this is a real issue
    message     : one-line human-readable description
    remediation : actionable fix guidance
    cwe_id      : CWE identifier (e.g. "CWE-798")
    snippet     : raw source line for context
    tags        : free-form labels (e.g. ["taint", "input-validation"])
    """

    # Required fields
    file:        str
    line:        int
    column:      int
    rule_id:     str
    severity:    Severity
    confidence:  float
    message:     str
    remediation: str

    # Optional fields
    cwe_id:  str       = "CWE-000"
    snippet: str       = ""
    tags:    list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._validate()

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                f"Finding.confidence must be in [0.0, 1.0], got {self.confidence}"
            )
        if self.line < 1:
            raise ValueError(
                f"Finding.line must be >= 1, got {self.line}"
            )
        if self.column < 0:
            raise ValueError(
                f"Finding.column must be >= 0, got {self.column}"
            )

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def cwe_name(self) -> str:
        return CWE_NAMES.get(self.cwe_id, self.cwe_id)

    @property
    def owasp_category(self) -> str:
        return CWE_TO_OWASP.get(self.cwe_id, "")

    @property
    def is_critical(self) -> bool:
        return self.severity == Severity.CRITICAL

    @property
    def is_actionable(self) -> bool:
        return self.confidence >= 0.70

    @property
    def fingerprint(self) -> str:
        raw = f"{self.file}:{self.rule_id}:{self.line}:{self.snippet[:60]}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint":    self.fingerprint,
            "file":           self.file,
            "line":           self.line,
            "column":         self.column,
            "rule_id":        self.rule_id,
            "severity":       self.severity.name,
            "confidence":     round(self.confidence, 3),
            "message":        self.message,
            "remediation":    self.remediation,
            "cwe_id":         self.cwe_id,
            "cwe_name":       self.cwe_name,
            "owasp_category": self.owasp_category,
            "snippet":        self.snippet,
            "tags":           self.tags,
        }

    def to_sarif_result(self) -> dict[str, Any]:
        return {
            "ruleId":  self.rule_id,
            "level":   self._sarif_level(),
            "message": {"text": self.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": self.file},
                    "region": {
                        "startLine":   self.line,
                        "startColumn": self.column + 1,
                        "snippet":     {"text": self.snippet},
                    },
                }
            }],
            "properties": {
                "confidence":  self.confidence,
                "cwe":         self.cwe_id,
                "owasp":       self.owasp_category,
                "fingerprint": self.fingerprint,
                "tags":        self.tags,
            },
        }

    def _sarif_level(self) -> str:
        return {
            Severity.CRITICAL: "error",
            Severity.HIGH:     "error",
            Severity.MEDIUM:   "warning",
            Severity.LOW:      "note",
            Severity.INFO:     "none",
        }[self.severity]

    # ------------------------------------------------------------------
    # Display
    # ------------------------------------------------------------------

    def __str__(self) -> str:
        color = self.severity.color
        reset = "\033[0m"
        return (
            f"{color}[{self.severity.label}]{reset} "
            f"{self.file}:{self.line}:{self.column} "
            f"· {self.rule_id} "
            f"· confidence {self.confidence:.2f}\n"
            f"  {self.message}\n"
            f"  {self.snippet.strip()}"
        )