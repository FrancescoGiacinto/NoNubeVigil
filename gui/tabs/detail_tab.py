from __future__ import annotations

import tkinter as tk
import customtkinter as ctk
from pathlib import Path

from nonubevigil.models import Finding, Severity
from gui.state import AppState


SEVERITY_COLORS = {
    "CRITICAL": "#E76361",
    "HIGH":     "#E76361",
    "MEDIUM":   "#FFE69F",
    "LOW":      "#486290",
    "INFO":     "#486290",
}


class DetailTab:
    """
    Tab 3 — Full detail view of the selected finding.

    Sections
    --------
    - Header       : severity badge, rule id, confidence
    - Location     : file, line, column
    - Message      : full finding message
    - Snippet      : source code context
    - Remediation  : fix guidance
    - References   : CWE, OWASP category, tags
    - Empty state  : shown when no finding is selected
    """

    def __init__(self, parent, state: AppState, colors: dict) -> None:
        self.parent = parent
        self.state  = state
        self.colors = colors

        self._build()
        self._register_callbacks()
        self._show_empty()

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------

    def _build(self) -> None:
        self.parent.configure(fg_color=self.colors["lapis_mid"])
        self.parent.rowconfigure(0, weight=1)
        self.parent.columnconfigure(0, weight=1)

        # Scrollable container
        self.scroll = ctk.CTkScrollableFrame(
            self.parent,
            fg_color      = self.colors["lapis_mid"],
            scrollbar_button_color       = self.colors["lapis"],
            scrollbar_button_hover_color = self.colors["lapis_dark"],
        )
        self.scroll.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        self.scroll.columnconfigure(0, weight=1)

        # Empty state
        self.empty_label = ctk.CTkLabel(
            self.scroll,
            text       = "Select a finding from the Findings tab\nto view its details here.",
            font       = ctk.CTkFont(size=14),
            text_color = self.colors["lapis"],
            justify    = "center",
        )

        # Detail widgets (hidden until a finding is selected)
        self._build_header_section()
        self._build_location_section()
        self._build_message_section()
        self._build_snippet_section()
        self._build_remediation_section()
        self._build_references_section()

    # ------------------------------------------------------------------
    # Header
    # ------------------------------------------------------------------

    def _build_header_section(self) -> None:
        self.header_frame = ctk.CTkFrame(
            self.scroll,
            fg_color      = self.colors["lapis_dark"],
            corner_radius = 10,
        )

        # Severity badge + rule id row
        top_row = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        top_row.pack(fill="x", padx=16, pady=(14, 4))

        self.severity_badge = ctk.CTkLabel(
            top_row,
            text          = "HIGH",
            font          = ctk.CTkFont(size=12, weight="bold"),
            text_color    = self.colors["lapis_dark"],
            fg_color      = self.colors["indian_red"],
            corner_radius = 6,
            padx          = 10,
            pady          = 4,
        )
        self.severity_badge.pack(side="left")

        self.rule_label = ctk.CTkLabel(
            top_row,
            text       = "SEC001",
            font       = ctk.CTkFont(size=13, weight="bold"),
            text_color = self.colors["light_vanilla"],
        )
        self.rule_label.pack(side="left", padx=10)

        # Confidence bar row
        conf_row = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        conf_row.pack(fill="x", padx=16, pady=(4, 14))

        ctk.CTkLabel(
            conf_row,
            text       = "Confidence",
            font       = ctk.CTkFont(size=11),
            text_color = self.colors["lapis"],
        ).pack(side="left")

        self.conf_bar = ctk.CTkProgressBar(
            conf_row,
            width          = 180,
            height         = 8,
            fg_color       = self.colors["lapis_mid"],
            progress_color = self.colors["lapis"],
        )
        self.conf_bar.pack(side="left", padx=(8, 6))
        self.conf_bar.set(0)

        self.conf_label = ctk.CTkLabel(
            conf_row,
            text       = "0%",
            font       = ctk.CTkFont(size=11, weight="bold"),
            text_color = self.colors["white"],
        )
        self.conf_label.pack(side="left")

    # ------------------------------------------------------------------
    # Location
    # ------------------------------------------------------------------

    def _build_location_section(self) -> None:
        self.location_frame = self._section_frame("Location")

        self.file_label = self._info_row(
            self.location_frame, "File", "—"
        )
        self.line_label = self._info_row(
            self.location_frame, "Line", "—"
        )
        self.col_label = self._info_row(
            self.location_frame, "Column", "—"
        )

    # ------------------------------------------------------------------
    # Message
    # ------------------------------------------------------------------

    def _build_message_section(self) -> None:
        self.message_frame = self._section_frame("Message")

        self.message_text = ctk.CTkTextbox(
            self.message_frame,
            fg_color   = self.colors["lapis_mid"],
            text_color = self.colors["light_gray"],
            font       = ctk.CTkFont(size=12),
            wrap       = "word",
            height     = 60,
            state      = "disabled",
        )
        self.message_text.pack(fill="x", padx=12, pady=(0, 12))

    # ------------------------------------------------------------------
    # Snippet
    # ------------------------------------------------------------------

    def _build_snippet_section(self) -> None:
        self.snippet_frame = self._section_frame("Source snippet")

        self.snippet_text = ctk.CTkTextbox(
            self.snippet_frame,
            fg_color   = self.colors["charcoal"],
            text_color = self.colors["light_vanilla"],
            font       = ctk.CTkFont(family="Courier", size=12),
            wrap       = "none",
            height     = 60,
            state      = "disabled",
        )
        self.snippet_text.pack(fill="x", padx=12, pady=(0, 12))

    # ------------------------------------------------------------------
    # Remediation
    # ------------------------------------------------------------------

    def _build_remediation_section(self) -> None:
        self.remediation_frame = self._section_frame("Remediation")

        # Accent bar on the left
        accent = ctk.CTkFrame(
            self.remediation_frame,
            fg_color      = self.colors["indian_red"],
            width         = 4,
            corner_radius = 2,
        )
        accent.pack(side="left", fill="y", padx=(12, 0), pady=(0, 12))

        self.remediation_text = ctk.CTkTextbox(
            self.remediation_frame,
            fg_color   = self.colors["lapis_mid"],
            text_color = self.colors["light_gray"],
            font       = ctk.CTkFont(size=12),
            wrap       = "word",
            height     = 80,
            state      = "disabled",
        )
        self.remediation_text.pack(
            fill="x", padx=(8, 12), pady=(0, 12), side="left", expand=True
        )

    # ------------------------------------------------------------------
    # References
    # ------------------------------------------------------------------

    def _build_references_section(self) -> None:
        self.references_frame = self._section_frame("References")

        self.cwe_label   = self._info_row(self.references_frame, "CWE",   "—")
        self.owasp_label = self._info_row(self.references_frame, "OWASP", "—")
        self.fp_label    = self._info_row(self.references_frame, "Fingerprint", "—")

        # Tags
        self.tags_frame = ctk.CTkFrame(
            self.references_frame,
            fg_color = "transparent",
        )
        self.tags_frame.pack(fill="x", padx=12, pady=(4, 12))

    # ------------------------------------------------------------------
    # Refresh
    # ------------------------------------------------------------------

    def refresh(self) -> None:
        finding = self.state.selected_finding
        if finding is None:
            self._show_empty()
            return
        self._show_finding(finding)

    def _show_finding(self, f: Finding) -> None:
        self._hide_empty()

        # Header
        sev_color = SEVERITY_COLORS.get(f.severity.name, self.colors["lapis"])
        self.severity_badge.configure(
            text     = f.severity.name,
            fg_color = sev_color,
            text_color = self.colors["lapis_dark"] if f.severity.name == "MEDIUM"
                         else self.colors["white"],
        )
        self.rule_label.configure(text=f.rule_id)
        self.conf_bar.set(f.confidence)
        self.conf_label.configure(text=f"{f.confidence:.0%}")

        # Confidence bar color
        if f.confidence >= 0.80:
            bar_color = self.colors["indian_red"]
        elif f.confidence >= 0.50:
            bar_color = self.colors["light_vanilla"]
        else:
            bar_color = self.colors["lapis"]
        self.conf_bar.configure(progress_color=bar_color)

        # Location
        self.file_label.configure(text=f.file)
        self.line_label.configure(text=str(f.line))
        self.col_label.configure(text=str(f.column))

        # Message
        self._set_textbox(self.message_text, f.message)

        # Snippet
        self._set_textbox(
            self.snippet_text,
            f.snippet.strip() if f.snippet else "No snippet available",
        )

        # Remediation
        self._set_textbox(self.remediation_text, f.remediation)

        # References
        cwe_text = f"{f.cwe_id} — {f.cwe_name}" if f.cwe_name != f.cwe_id else f.cwe_id
        self.cwe_label.configure(text=cwe_text)
        self.owasp_label.configure(text=f.owasp_category or "—")
        self.fp_label.configure(text=f.fingerprint)

        # Tags
        self._render_tags(f.tags)

    # ------------------------------------------------------------------
    # Empty state
    # ------------------------------------------------------------------

    def _show_empty(self) -> None:
        self._hide_all_sections()
        self.empty_label.pack(expand=True, pady=60)

    def _hide_empty(self) -> None:
        self.empty_label.pack_forget()
        self._show_all_sections()

    def _hide_all_sections(self) -> None:
        for section in self._all_sections():
            section.pack_forget()

    def _show_all_sections(self) -> None:
        for section in self._all_sections():
            section.pack(fill="x", padx=8, pady=4)

    def _all_sections(self) -> list:
        return [
            self.header_frame,
            self.location_frame,
            self.message_frame,
            self.snippet_frame,
            self.remediation_frame,
            self.references_frame,
        ]

    # ------------------------------------------------------------------
    # Callbacks
    # ------------------------------------------------------------------

    def _register_callbacks(self) -> None:
        self.state.on("on_finding_select", lambda _: self.refresh())
        self.state.on("on_scan_start",     lambda:   self._show_empty())

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _section_frame(self, title: str) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(
            self.scroll,
            fg_color      = self.colors["lapis_dark"],
            corner_radius = 10,
        )
        ctk.CTkLabel(
            frame,
            text       = title,
            font       = ctk.CTkFont(size=12, weight="bold"),
            text_color = self.colors["lapis"],
        ).pack(anchor="w", padx=12, pady=(10, 4))
        return frame

    def _info_row(
        self,
        parent,
        label: str,
        value: str,
    ) -> ctk.CTkLabel:
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=12, pady=2)

        ctk.CTkLabel(
            row,
            text       = f"{label}:",
            font       = ctk.CTkFont(size=11, weight="bold"),
            text_color = self.colors["lapis"],
            width      = 90,
            anchor     = "w",
        ).pack(side="left")

        value_label = ctk.CTkLabel(
            row,
            text       = value,
            font       = ctk.CTkFont(size=11),
            text_color = self.colors["light_gray"],
            anchor     = "w",
            wraplength = 500,
        )
        value_label.pack(side="left", fill="x", expand=True)
        return value_label

    def _render_tags(self, tags: list[str]) -> None:
        for widget in self.tags_frame.winfo_children():
            widget.destroy()

        if not tags:
            return

        ctk.CTkLabel(
            self.tags_frame,
            text       = "Tags:",
            font       = ctk.CTkFont(size=11, weight="bold"),
            text_color = self.colors["lapis"],
            width      = 90,
            anchor     = "w",
        ).pack(side="left")

        for tag in tags:
            ctk.CTkLabel(
                self.tags_frame,
                text          = tag,
                font          = ctk.CTkFont(size=10),
                text_color    = self.colors["lapis_dark"],
                fg_color      = self.colors["lapis"],
                corner_radius = 4,
                padx          = 6,
                pady          = 2,
            ).pack(side="left", padx=(0, 4))

    @staticmethod
    def _set_textbox(textbox: ctk.CTkTextbox, content: str) -> None:
        textbox.configure(state="normal")
        textbox.delete("1.0", "end")
        textbox.insert("1.0", content)
        textbox.configure(state="disabled")