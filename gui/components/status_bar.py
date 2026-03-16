# gui/components/status_bar.py
# Status bar at the bottom of the main window (scan status, files count, target).

from __future__ import annotations

import customtkinter as ctk

from gui.state import AppState, ScanStatus


class StatusBar:
    """
    Thin status bar at the bottom of the main window.

    Shows:
    - Current scan status (idle / running / done / error)
    - Files scanned count
    - Last scan target
    """

    def __init__(self, parent, state: AppState, colors: dict) -> None:
        self.state  = state
        self.colors = colors

        self.frame = ctk.CTkFrame(
            parent,
            fg_color      = self.colors["lapis_dark"],
            corner_radius = 6,
            height        = 28,
        )
        self.frame.pack_propagate(False)

        # Status dot
        self.dot = ctk.CTkLabel(
            self.frame,
            text       = "●",
            font       = ctk.CTkFont(size=10),
            text_color = self.colors["lapis"],
            width      = 20,
        )
        self.dot.pack(side="left", padx=(10, 2))

        # Status text
        self.status_label = ctk.CTkLabel(
            self.frame,
            text       = "Ready",
            font       = ctk.CTkFont(size=11),
            text_color = self.colors["lapis"],
        )
        self.status_label.pack(side="left", padx=(0, 16))

        # Files scanned
        self.files_label = ctk.CTkLabel(
            self.frame,
            text       = "",
            font       = ctk.CTkFont(size=11),
            text_color = self.colors["lapis"],
        )
        self.files_label.pack(side="left")

        # Target (right aligned)
        self.target_label = ctk.CTkLabel(
            self.frame,
            text       = "",
            font       = ctk.CTkFont(size=10),
            text_color = self.colors["lapis_mid"],
        )
        self.target_label.pack(side="right", padx=10)

        self._register_callbacks()

    def pack(self, **kwargs) -> None:
        self.frame.pack(**kwargs)

    # ------------------------------------------------------------------
    # Callbacks
    # ------------------------------------------------------------------

    def _register_callbacks(self) -> None:
        self.state.on("on_scan_start", self._on_start)
        self.state.on("on_scan_done",  self._on_done)
        self.state.on("on_scan_error", self._on_error)

    def _on_start(self) -> None:
        self.dot.configure(text_color=self.colors["light_vanilla"])
        self.status_label.configure(
            text       = "Scanning...",
            text_color = self.colors["light_vanilla"],
        )
        self.files_label.configure(text="")
        self.target_label.configure(text=self.state.scan_target)

    def _on_done(self) -> None:
        count = len(self.state.findings)
        color = (
            self.colors["indian_red"] if count > 0
            else "#4CAF50"
        )
        self.dot.configure(text_color=color)
        self.status_label.configure(
            text       = f"{count} finding(s)",
            text_color = color,
        )
        self.files_label.configure(
            text = (
                f"  ·  {self.state.files_scanned} file(s) scanned"
                + (f"  ·  {self.state.files_skipped} skipped"
                   if self.state.files_skipped else "")
            ),
            text_color = self.colors["lapis"],
        )

    def _on_error(self, message: str) -> None:
        self.dot.configure(text_color=self.colors["indian_red"])
        self.status_label.configure(
            text       = f"Error: {message[:60]}",
            text_color = self.colors["indian_red"],
        )
