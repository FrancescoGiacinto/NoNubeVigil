from __future__ import annotations

from pathlib import Path
from datetime import datetime

from ..models  import Finding, Severity
from ..scoring import ConfidenceScorer


class PDFReporter:
    """
    Generates a professional pentest-style PDF report.

    Requires the `reportlab` library:
        pip install reportlab

    Report structure
    ----------------
    1. Cover page     — tool name, scan target, date
    2. Executive summary — finding counts by severity, risk overview
    3. Findings detail   — one section per finding with snippet,
                           remediation, CWE reference, OWASP category
    4. Appendix          — methodology, tool version, full file list

    This is your primary portfolio artifact — it demonstrates that
    vigil produces professional, client-ready output.
    """

    def export(
        self,
        findings:    list[Finding],
        output_path: str | Path,
        target:      str = "Unknown",
    ) -> Path:
        """
        Generate a PDF report and write it to output_path.
        Returns the resolved output path.
        """
        try:
            from reportlab.lib.pagesizes    import A4
            from reportlab.lib.styles       import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units        import cm
            from reportlab.lib             import colors
            from reportlab.platypus         import (
                SimpleDocTemplate, Paragraph, Spacer,
                Table, TableStyle, PageBreak, HRFlowable,
            )
        except ImportError:
            raise ImportError(
                "reportlab is required for PDF export. "
                "Install it with: pip install reportlab"
            )

        output_path = Path(output_path)
        doc         = SimpleDocTemplate(
            str(output_path),
            pagesize    = A4,
            leftMargin  = 2 * cm,
            rightMargin = 2 * cm,
            topMargin   = 2 * cm,
            bottomMargin= 2 * cm,
        )

        styles  = getSampleStyleSheet()
        story   = []

        # -- Cover page --
        story.extend(self._build_cover(styles, target, len(findings)))
        story.append(PageBreak())

        # -- Executive summary --
        story.extend(self._build_summary(styles, findings))
        story.append(PageBreak())

        # -- Findings detail --
        story.extend(self._build_findings(styles, findings))
        story.append(PageBreak())

        # -- Appendix --
        story.extend(self._build_appendix(styles, findings, target))

        doc.build(story)
        return output_path

    # ------------------------------------------------------------------
    # Cover page
    # ------------------------------------------------------------------

    def _build_cover(self, styles, target: str, total: int) -> list:
        from reportlab.platypus import Paragraph, Spacer
        from reportlab.lib.units import cm

        title_style = styles["Title"]
        body_style  = styles["Normal"]

        return [
            Spacer(1, 4 * cm),
            Paragraph("vigil", title_style),
            Paragraph("Security Code Review Report", styles["Heading2"]),
            Spacer(1, 1 * cm),
            Paragraph(f"Target: {target}", body_style),
            Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}", body_style),
            Paragraph(f"Total findings: {total}", body_style),
            Spacer(1, 1 * cm),
            Paragraph(
                "This report was generated automatically by vigil — "
                "a static application security testing (SAST) tool. "
                "All findings should be reviewed by a qualified security professional.",
                body_style,
            ),
        ]

    # ------------------------------------------------------------------
    # Executive summary
    # ------------------------------------------------------------------

    def _build_summary(self, styles, findings: list[Finding]) -> list:
        from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
        from reportlab.lib      import colors

        counts = ConfidenceScorer.summarize(findings)

        story = [
            Paragraph("Executive Summary", styles["Heading1"]),
            Spacer(1, 0.3),
        ]

        # Severity table
        data = [["Severity", "Count", "Risk"]]
        risk_map = {
            "CRITICAL": "Immediate action required",
            "HIGH":     "Remediate within 7 days",
            "MEDIUM":   "Remediate within 30 days",
            "LOW":      "Remediate at next release",
            "INFO":     "Informational",
        }
        for sev in reversed(Severity):
            count = counts.get(sev.name, 0)
            data.append([sev.name, str(count), risk_map[sev.name]])

        color_map = {
            "CRITICAL": colors.HexColor("#9B30FF"),
            "HIGH":     colors.HexColor("#FF4444"),
            "MEDIUM":   colors.HexColor("#FFA500"),
            "LOW":      colors.HexColor("#4444FF"),
            "INFO":     colors.HexColor("#00AAAA"),
        }

        table = Table(data, colWidths=[4 * 28, 2 * 28, 8 * 28])
        table.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0),  colors.HexColor("#2C2C2A")),
            ("TEXTCOLOR",   (0, 0), (-1, 0),  colors.white),
            ("FONTNAME",    (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, -1), 10),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F5F5")]),
            ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
            ("PADDING",     (0, 0), (-1, -1), 6),
        ]))

        story.append(table)
        return story

    # ------------------------------------------------------------------
    # Findings detail
    # ------------------------------------------------------------------

    def _build_findings(self, styles, findings: list[Finding]) -> list:
        from reportlab.platypus import Paragraph, Spacer, HRFlowable
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib        import colors
        from reportlab.platypus import Paragraph, Spacer, HRFlowable, Table, TableStyle

        mono_style = ParagraphStyle(
            "Mono",
            parent    = styles["Code"],
            fontSize  = 8,
            textColor = colors.HexColor("#333333"),
            backColor = colors.HexColor("#F5F5F5"),
            leftIndent= 10,
        )

        story = [Paragraph("Findings", styles["Heading1"])]

        for i, f in enumerate(findings, start=1):
            story.append(Spacer(1, 0.4))
            story.append(Paragraph(
                f"{i}. [{f.severity.name}] {f.rule_id} — {f.message}",
                styles["Heading3"],
            ))

            # Metadata table
            meta = [
                ["File",        f.file],
                ["Line",        str(f.line)],
                ["Confidence",  f"{f.confidence:.0%}"],
                ["CWE",         f"{f.cwe_id} — {f.cwe_name}"],
                ["OWASP",       f.owasp_category or "—"],
            ]
            meta_table = Table(meta, colWidths=[3 * 28, 12 * 28])
            meta_table.setStyle(TableStyle([
                ("FONTSIZE",  (0, 0), (-1, -1), 9),
                ("FONTNAME",  (0, 0), (0, -1),  "Helvetica-Bold"),
                ("GRID",      (0, 0), (-1, -1), 0.3, colors.HexColor("#DDDDDD")),
                ("PADDING",   (0, 0), (-1, -1), 4),
            ]))
            story.append(meta_table)

            # Snippet
            if f.snippet:
                story.append(Spacer(1, 0.2))
                story.append(Paragraph(f.snippet.strip(), mono_style))

            # Remediation
            story.append(Spacer(1, 0.2))
            story.append(Paragraph(
                f"<b>Remediation:</b> {f.remediation}",
                styles["Normal"],
            ))
            story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#DDDDDD")))

        return story

    # ------------------------------------------------------------------
    # Appendix
    # ------------------------------------------------------------------

    def _build_appendix(self, styles, findings: list[Finding], target: str) -> list:
        from reportlab.platypus import Paragraph, Spacer

        unique_files = sorted({f.file for f in findings})

        story = [
            Paragraph("Appendix", styles["Heading1"]),
            Paragraph("Methodology", styles["Heading2"]),
            Paragraph(
                "vigil performs multi-layer static analysis combining: "
                "(1) pattern matching against known vulnerability signatures, "
                "(2) AST-based analysis using tree-sitter, and "
                "(3) dataflow taint analysis tracking user input from sources to sinks. "
                "Each finding is assigned a confidence score (0.0–1.0) based on "
                "converging signals from multiple analyzers.",
                styles["Normal"],
            ),
            Spacer(1, 0.4),
            Paragraph("Scanned Files", styles["Heading2"]),
        ]

        for file in unique_files:
            story.append(Paragraph(f"• {file}", styles["Normal"]))

        return story