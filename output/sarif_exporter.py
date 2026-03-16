from __future__ import annotations

import json
from pathlib import Path

from ..models import Finding
from ..rules  import (
    HardcodedSecretRule,
    SqlInjectionRule,
    XssRule,
    InsecureDeserializationRule,
)


# SARIF 2.1 schema URI — required by GitHub Code Scanning
_SARIF_SCHEMA  = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json"
_SARIF_VERSION = "2.1.0"
_TOOL_NAME     = "vigil"
_TOOL_VERSION  = "0.1.0"


class SARIFExporter:
    """
    Serializes findings to SARIF 2.1 format.

    SARIF (Static Analysis Results Interchange Format) is the standard
    consumed by GitHub Code Scanning, GitLab SAST, VSCode, and most
    CI/CD security pipelines.

    Usage
    -----
        exporter = SARIFExporter()
        exporter.export(findings, output_path="results.sarif.json")

    The output file can be uploaded directly to GitHub via:
        gh code-scanning upload-results --sarif results.sarif.json
    """

    def export(
        self,
        findings:    list[Finding],
        output_path: str | Path,
    ) -> Path:
        """
        Write a SARIF 2.1 document to output_path.
        Returns the resolved output path.
        """
        output_path = Path(output_path)
        document    = self._build_document(findings)

        output_path.write_text(
            json.dumps(document, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return output_path

    def to_string(self, findings: list[Finding]) -> str:
        """Return the SARIF document as a JSON string (for testing)."""
        return json.dumps(self._build_document(findings), indent=2)

    # ------------------------------------------------------------------
    # Document structure
    # ------------------------------------------------------------------

    def _build_document(self, findings: list[Finding]) -> dict:
        return {
            "$schema": _SARIF_SCHEMA,
            "version": _SARIF_VERSION,
            "runs": [self._build_run(findings)],
        }

    def _build_run(self, findings: list[Finding]) -> dict:
        return {
            "tool": self._build_tool(),
            "results": [f.to_sarif_result() for f in findings],
            "artifacts": self._build_artifacts(findings),
        }

    # ------------------------------------------------------------------
    # Tool metadata
    # ------------------------------------------------------------------

    def _build_tool(self) -> dict:
        return {
            "driver": {
                "name":            _TOOL_NAME,
                "version":         _TOOL_VERSION,
                "informationUri":  "https://github.com/yourusername/vigil",
                "rules":           self._build_rule_descriptors(),
            }
        }

    @staticmethod
    def _build_rule_descriptors() -> list[dict]:
        """
        SARIF requires a descriptor for every rule that may appear
        in results. Used by GitHub to display rule metadata in the UI.
        """
        rules = [
            HardcodedSecretRule(),
            SqlInjectionRule(),
            XssRule(),
            InsecureDeserializationRule(),
        ]
        return [
            {
                "id":               rule.rule_id,
                "name":             rule.__class__.__name__,
                "shortDescription": {"text": rule.description},
                "helpUri":          f"https://cwe.mitre.org/data/definitions/{rule.rule_id}.html",
                "properties": {
                    "tags":     rule.languages,
                    "severity": rule.severity.name,
                },
            }
            for rule in rules
        ]

    # ------------------------------------------------------------------
    # Artifacts
    # ------------------------------------------------------------------

    @staticmethod
    def _build_artifacts(findings: list[Finding]) -> list[dict]:
        """
        List every scanned file as a SARIF artifact.
        Deduplicated — each file appears once regardless of finding count.
        """
        seen: set[str] = set()
        artifacts = []
        for f in findings:
            if f.file not in seen:
                seen.add(f.file)
                artifacts.append({
                    "location": {"uri": f.file}
                })
        return artifacts