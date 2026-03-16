from __future__ import annotations

from pathlib import Path
import tkinter as tk
from tkinter import ttk

import customtkinter as ctk

from nonubevigil.models import Finding, Severity
from gui.state import AppState
from gui.components.severity_chart import SeverityChart


SEVERITY_COLORS = {
    "CRITICAL": "#E76361",
    "HIGH":     "#E76361",
    "MEDIUM":   "#FFE69F",
    "LOW":      "#486290",
    "INFO":     "#486290",
}


class FindingsTab:
    """
    Tab 2 — Findings table with filters and severity chart.

    Sections
    --------
    - Summary bar      : total findings + counts per severity
    - Filter bar       : filter by severity, rule_id, free text search
    - Findings table   : sortable treeview with all findings
    - Severity chart   : donut chart (bottom right)
    """

    def __init__(self, parent, state: AppState, colors: dict) -> None:
        self.parent  = parent
        self.state   = state
        self.colors  = colors
        self._all_findings: list[Finding] = []

        self._build()
        self._register_callbacks()

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------

    def _build(self) -> None:
        self.parent.configure(fg_color=self.colors["lapis_mid"])
        self.parent.rowconfigure(2, weight=1)
        self.parent.columnconfigure(0, weight=1)

        self._build_summary_bar()
        self._build_filter_bar()
        self._build_main_area()

    def _build_summary_bar(self) -> None:
        bar = ctk.CTkFrame(
            self.parent,
            fg_color      = self.colors["lapis_dark"],
            corner_radius = 8,
            height        = 48,
        )
        bar.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 4))
        bar.pack_propagate(False)
        bar.columnconfigure(tuple(range(7)), weight=1)

        self._summary_labels: dict[str, ctk.CTkLabel] = {}

        # Total
        ctk.CTkLabel(
            bar,
            text       = "Total",
            font       = ctk.CTkFont(size=11),
            text_color = self.colors["lapis"],
        ).pack(side="left", padx=(16, 4))

        self._summary_labels["total"] = ctk.CTkLabel(
            bar,
            text       = "0",
            font       = ctk.CTkFont(size=15, weight="bold"),
            text_color = self.colors["white"],
        )
        self._summary_labels["total"].pack(side="left", padx=(0, 16))

        # Per severity
        for sev in reversed(Severity):
            color = SEVERITY_COLORS.get(sev.name, self.colors["lapis"])

            ctk.CTkLabel(
                bar,
                text       = sev.name,
                font       = ctk.CTkFont(size=10),
                text_color = color,
            ).pack(side="left", padx=(8, 2))

            lbl = ctk.CTkLabel(
                bar,
                text       = "0",
                font       = ctk.CTkFont(size=13, weight="bold"),
                text_color = color,
            )
            lbl.pack(side="left", padx=(0, 8))
            self._summary_labels[sev.name] = lbl

    def _build_filter_bar(self) -> None:
        bar = ctk.CTkFrame(
            self.parent,
            fg_color      = self.colors["lapis_dark"],
            corner_radius = 8,
        )
        bar.grid(row=1, column=0, sticky="ew", padx=8, pady=4)

        # Search
        ctk.CTkLabel(
            bar,
            text       = "Search",
            font       = ctk.CTkFont(size=11),
            text_color = self.colors["lapis"],
        ).pack(side="left", padx=(12, 4), pady=8)

        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._apply_filters())
        ctk.CTkEntry(
            bar,
            textvariable     = self.search_var,
            placeholder_text = "file, message, rule...",
            fg_color         = self.colors["lapis_mid"],
            border_color     = self.colors["lapis"],
            text_color       = self.colors["white"],
            width            = 220,
            height           = 32,
        ).pack(side="left", padx=(0, 12), pady=8)

        # Severity filter
        ctk.CTkLabel(
            bar,
            text       = "Severity",
            font       = ctk.CTkFont(size=11),
            text_color = self.colors["lapis"],
        ).pack(side="left", padx=(0, 4))

        self.severity_filter_var = tk.StringVar(value="ALL")
        ctk.CTkOptionMenu(
            bar,
            variable     = self.severity_filter_var,
            values       = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
            fg_color     = self.colors["lapis_mid"],
            button_color = self.colors["lapis"],
            text_color   = self.colors["white"],
            width        = 110,
            command      = lambda _: self._apply_filters(),
        ).pack(side="left", padx=(0, 12), pady=8)

        # Rule filter
        ctk.CTkLabel(
            bar,
            text       = "Rule",
            font       = ctk.CTkFont(size=11),
            text_color = self.colors["lapis"],
        ).pack(side="left", padx=(0, 4))

        self.rule_filter_var = tk.StringVar(value="ALL")
        self.rule_menu = ctk.CTkOptionMenu(
            bar,
            variable     = self.rule_filter_var,
            values       = ["ALL"],
            fg_color     = self.colors["lapis_mid"],
            button_color = self.colors["lapis"],
            text_color   = self.colors["white"],
            width        = 110,
            command      = lambda _: self._apply_filters(),
        )
        self.rule_menu.pack(side="left", padx=(0, 12), pady=8)

        # Clear button
        ctk.CTkButton(
            bar,
            text        = "Clear filters",
            width       = 90,
            height      = 32,
            fg_color    = self.colors["lapis_mid"],
            hover_color = self.colors["lapis"],
            text_color  = self.colors["white"],
            command     = self._clear_filters,
        ).pack(side="left", pady=8)

    def _build_main_area(self) -> None:
        area = ctk.CTkFrame(self.parent, fg_color="transparent")
        area.grid(row=2, column=0, sticky="nsew", padx=8, pady=(4, 8))
        area.rowconfigure(0, weight=1)
        area.columnconfigure(0, weight=3)
        area.columnconfigure(1, weight=1)

        self._build_table(area)
        self._build_chart_panel(area)

    def _build_table(self, parent) -> None:
        frame = ctk.CTkFrame(parent, fg_color=self.colors["lapis_dark"])
        frame.grid(row=0, column=0, sticky="nsew", padx=(0, 4))
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        # Style treeview to match palette
        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "Vigil.Treeview",
            background    = self.colors["lapis_dark"],
            foreground    = self.colors["light_gray"],
            fieldbackground = self.colors["lapis_dark"],
            rowheight     = 28,
            borderwidth   = 0,
            font          = ("Helvetica", 11),
        )
        style.configure(
            "Vigil.Treeview.Heading",
            background  = self.colors["lapis_mid"],
            foreground  = self.colors["white"],
            relief      = "flat",
            font        = ("Helvetica", 11, "bold"),
        )
        style.map(
            "Vigil.Treeview",
            background  = [("selected", self.colors["lapis"])],
            foreground  = [("selected", self.colors["white"])],
        )

        columns = ("severity", "confidence", "rule", "file", "line", "message")
        self.tree = ttk.Treeview(
            frame,
            columns      = columns,
            show         = "headings",
            style        = "Vigil.Treeview",
            selectmode   = "browse",
        )

        # Column config
        self.tree.heading("severity",   text="Severity",   command=lambda: self._sort("severity"))
        self.tree.heading("confidence", text="Confidence", command=lambda: self._sort("confidence"))
        self.tree.heading("rule",       text="Rule",       command=lambda: self._sort("rule"))
        self.tree.heading("file",       text="File",       command=lambda: self._sort("file"))
        self.tree.heading("line",       text="Line",       command=lambda: self._sort("line"))
        self.tree.heading("message",    text="Message",    command=lambda: self._sort("message"))

        self.tree.column("severity",   width=90,  anchor="center")
        self.tree.column("confidence", width=90,  anchor="center")
        self.tree.column("rule",       width=80,  anchor="center")
        self.tree.column("file",       width=180, anchor="w")
        self.tree.column("line",       width=50,  anchor="center")
        self.tree.column("message",    width=300, anchor="w")

        # Tag colors per severity
        for sev, color in SEVERITY_COLORS.items():
            self.tree.tag_configure(sev, foreground=color)

        # Scrollbar
        scrollbar = ctk.CTkScrollbar(frame, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        self.tree.bind("<<TreeviewSelect>>", self._on_row_select)

    def _build_chart_panel(self, parent) -> None:
        panel = ctk.CTkFrame(parent, fg_color=self.colors["lapis_dark"])
        panel.grid(row=0, column=1, sticky="nsew", padx=(4, 0))
        panel.rowconfigure(1, weight=1)
        panel.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            panel,
            text       = "Severity breakdown",
            font       = ctk.CTkFont(size=12, weight="bold"),
            text_color = self.colors["white"],
        ).grid(row=0, column=0, pady=(12, 4))

        self.chart = SeverityChart(panel, self.colors)
        self.chart.widget.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))

    # ------------------------------------------------------------------
    # Callbacks
    # ------------------------------------------------------------------

    def _register_callbacks(self) -> None:
        """Register with AppState so the tab refreshes when a scan completes."""
        self.state.on("on_scan_done", self.refresh)

    # ------------------------------------------------------------------
    # Data
    # ------------------------------------------------------------------

    def refresh(self) -> None:
        """Called by AppState callback when scan completes."""
        self._all_findings = self.state.findings
        self._update_summary()
        self._update_rule_menu()
        self._apply_filters()
        self.chart.update(self.state.summary())

    def _update_summary(self) -> None:
        counts = self.state.summary()
        self._summary_labels["total"].configure(
            text=str(len(self._all_findings))
        )
        for sev_name, count in counts.items():
            if sev_name in self._summary_labels:
                self._summary_labels[sev_name].configure(text=str(count))

    def _update_rule_menu(self) -> None:
        rule_ids = sorted({f.rule_id for f in self._all_findings})
        self.rule_menu.configure(values=["ALL"] + rule_ids)
        self.rule_filter_var.set("ALL")

    def _apply_filters(self) -> None:
        search   = self.search_var.get().lower()
        severity = self.severity_filter_var.get()
        rule     = self.rule_filter_var.get()

        filtered = [
            f for f in self._all_findings
            if (severity == "ALL" or f.severity.name == severity)
            and (rule == "ALL" or f.rule_id == rule)
            and (
                not search
                or search in f.file.lower()
                or search in f.message.lower()
                or search in f.rule_id.lower()
            )
        ]

        self._populate_table(filtered)

    def _populate_table(self, findings: list[Finding]) -> None:
        self.tree.delete(*self.tree.get_children())
        for f in findings:
            self.tree.insert(
                "",
                "end",
                iid    = f.fingerprint,
                values = (
                    f.severity.name,
                    f"{f.confidence:.0%}",
                    f.rule_id,
                    Path(f.file).name,
                    f.line,
                    f.message[:80] + ("..." if len(f.message) > 80 else ""),
                ),
                tags   = (f.severity.name,),
            )

    # ------------------------------------------------------------------
    # Sorting
    # ------------------------------------------------------------------

    def _sort(self, col: str) -> None:
        col_map = {
            "severity":   lambda f: f.severity.value,
            "confidence": lambda f: f.confidence,
            "rule":       lambda f: f.rule_id,
            "file":       lambda f: f.file,
            "line":       lambda f: f.line,
            "message":    lambda f: f.message,
        }
        key = col_map.get(col, lambda f: f.rule_id)
        sorted_findings = sorted(self._all_findings, key=key, reverse=True)
        self._populate_table(sorted_findings)

    # ------------------------------------------------------------------
    # Selection
    # ------------------------------------------------------------------

    def _on_row_select(self, event) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        fingerprint = selected[0]
        finding = next(
            (f for f in self._all_findings if f.fingerprint == fingerprint),
            None,
        )
        if finding:
            self.state.select_finding(finding)

    # ------------------------------------------------------------------
    # Filters
    # ------------------------------------------------------------------

    def _clear_filters(self) -> None:
        self.search_var.set("")
        self.severity_filter_var.set("ALL")
        self.rule_filter_var.set("ALL")
        self._apply_filters()