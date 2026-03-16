from __future__ import annotations

from pathlib import Path
import tkinter as tk
import customtkinter as ctk

from nonubevigil import PipelineConfig
from gui.state import AppState, ScanStatus


class ScanTab:
    """
    Tab 1 — Scan configuration and execution.

    Sections
    --------
    - Target selector  : file/directory picker
    - Options          : severity, confidence, language, AST toggle
    - Run button       : launches the scan
    - Log panel        : live output during scan
    """

    def __init__(
        self,
        parent,
        state:  AppState,
        colors: dict,
        on_run: callable,
    ) -> None:
        self.parent = parent
        self.state  = state
        self.colors = colors
        self.on_run = on_run

        self._build()
        self._register_callbacks()

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------

    def _build(self) -> None:
        self.parent.configure(fg_color=self.colors["lapis_mid"])

        # Two-column layout
        self.parent.columnconfigure(0, weight=2)
        self.parent.columnconfigure(1, weight=3)
        self.parent.rowconfigure(0, weight=1)

        self._build_left_panel()
        self._build_right_panel()

    def _build_left_panel(self) -> None:
        left = ctk.CTkFrame(self.parent, fg_color=self.colors["lapis_dark"])
        left.grid(row=0, column=0, sticky="nsew", padx=(8, 4), pady=8)
        left.columnconfigure(0, weight=1)

        # Title
        ctk.CTkLabel(
            left,
            text       = "Scan Configuration",
            font       = ctk.CTkFont(size=15, weight="bold"),
            text_color = self.colors["white"],
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(16, 8))

        # Target
        self._build_target_section(left, row=1)

        # Options
        self._build_options_section(left, row=2)

        # Run button
        self.run_button = ctk.CTkButton(
            left,
            text          = "Run Scan",
            font          = ctk.CTkFont(size=14, weight="bold"),
            fg_color      = self.colors["indian_red"],
            hover_color   = "#c94f4d",
            text_color    = self.colors["white"],
            height        = 44,
            corner_radius = 8,
            command       = self._on_run_clicked,
        )
        self.run_button.grid(row=3, column=0, sticky="ew", padx=16, pady=(16, 8))

        # Progress bar
        self.progress = ctk.CTkProgressBar(
            left,
            fg_color          = self.colors["lapis_mid"],
            progress_color    = self.colors["lapis"],
            height            = 6,
        )
        self.progress.set(0)
        self.progress.grid(row=4, column=0, sticky="ew", padx=16, pady=(0, 16))

    def _build_target_section(self, parent, row: int) -> None:
        frame = ctk.CTkFrame(parent, fg_color=self.colors["lapis_mid"], corner_radius=8)
        frame.grid(row=row, column=0, sticky="ew", padx=16, pady=4)
        frame.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            frame,
            text       = "Target",
            font       = ctk.CTkFont(size=12, weight="bold"),
            text_color = self.colors["lapis"],
        ).grid(row=0, column=0, sticky="w", padx=12, pady=(10, 2))

        # Path entry + browse button
        entry_row = ctk.CTkFrame(frame, fg_color="transparent")
        entry_row.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 10))
        entry_row.columnconfigure(0, weight=1)

        self.target_var = tk.StringVar()
        self.target_entry = ctk.CTkEntry(
            entry_row,
            textvariable  = self.target_var,
            placeholder_text = "Select file or directory...",
            fg_color      = self.colors["lapis_dark"],
            border_color  = self.colors["lapis"],
            text_color    = self.colors["white"],
            height        = 36,
        )
        self.target_entry.grid(row=0, column=0, sticky="ew", padx=(0, 6))

        ctk.CTkButton(
            entry_row,
            text        = "Browse",
            width       = 70,
            height      = 36,
            fg_color    = self.colors["lapis"],
            hover_color = self.colors["lapis_mid"],
            text_color  = self.colors["white"],
            command     = self._browse,
        ).grid(row=0, column=1)

    def _build_options_section(self, parent, row: int) -> None:
        frame = ctk.CTkFrame(parent, fg_color=self.colors["lapis_mid"], corner_radius=8)
        frame.grid(row=row, column=0, sticky="ew", padx=16, pady=4)
        frame.columnconfigure(0, weight=1)
        frame.columnconfigure(1, weight=1)

        ctk.CTkLabel(
            frame,
            text       = "Options",
            font       = ctk.CTkFont(size=12, weight="bold"),
            text_color = self.colors["lapis"],
        ).grid(row=0, column=0, columnspan=2, sticky="w", padx=12, pady=(10, 4))

        # Minimum severity
        ctk.CTkLabel(
            frame,
            text       = "Min severity",
            text_color = self.colors["light_gray"],
            font       = ctk.CTkFont(size=11),
        ).grid(row=1, column=0, sticky="w", padx=12, pady=2)

        self.severity_var = tk.StringVar(value="LOW")
        ctk.CTkOptionMenu(
            frame,
            variable    = self.severity_var,
            values      = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
            fg_color    = self.colors["lapis_dark"],
            button_color= self.colors["lapis"],
            text_color  = self.colors["white"],
            width       = 120,
        ).grid(row=1, column=1, sticky="e", padx=12, pady=2)

        # Minimum confidence
        ctk.CTkLabel(
            frame,
            text       = "Min confidence",
            text_color = self.colors["light_gray"],
            font       = ctk.CTkFont(size=11),
        ).grid(row=2, column=0, sticky="w", padx=12, pady=2)

        self.confidence_var = tk.DoubleVar(value=0.30)
        conf_row = ctk.CTkFrame(frame, fg_color="transparent")
        conf_row.grid(row=2, column=1, sticky="e", padx=12, pady=2)

        self.conf_label = ctk.CTkLabel(
            conf_row,
            text       = "0.30",
            text_color = self.colors["light_vanilla"],
            font       = ctk.CTkFont(size=11),
            width      = 32,
        )
        self.conf_label.pack(side="right")

        ctk.CTkSlider(
            conf_row,
            from_           = 0.0,
            to              = 1.0,
            number_of_steps = 20,
            variable        = self.confidence_var,
            width           = 80,
            button_color    = self.colors["indian_red"],
            progress_color  = self.colors["lapis"],
            command         = self._on_confidence_change,
        ).pack(side="right", padx=(0, 4))

        # AST toggle
        ctk.CTkLabel(
            frame,
            text       = "AST analysis",
            text_color = self.colors["light_gray"],
            font       = ctk.CTkFont(size=11),
        ).grid(row=3, column=0, sticky="w", padx=12, pady=(2, 10))

        self.ast_var = tk.BooleanVar(value=True)
        ctk.CTkSwitch(
            frame,
            text          = "",
            variable      = self.ast_var,
            onvalue       = True,
            offvalue      = False,
            button_color  = self.colors["indian_red"],
            progress_color= self.colors["lapis"],
        ).grid(row=3, column=1, sticky="e", padx=12, pady=(2, 10))

    def _build_right_panel(self) -> None:
        right = ctk.CTkFrame(self.parent, fg_color=self.colors["lapis_dark"])
        right.grid(row=0, column=1, sticky="nsew", padx=(4, 8), pady=8)
        right.rowconfigure(1, weight=1)
        right.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            right,
            text       = "Scan Log",
            font       = ctk.CTkFont(size=15, weight="bold"),
            text_color = self.colors["white"],
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(16, 8))

        self.log_box = ctk.CTkTextbox(
            right,
            fg_color      = self.colors["lapis_mid"],
            text_color    = self.colors["light_gray"],
            font          = ctk.CTkFont(family="Courier", size=11),
            wrap          = "word",
            state         = "disabled",
        )
        self.log_box.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0, 16))

    # ------------------------------------------------------------------
    # Callbacks
    # ------------------------------------------------------------------

    def _register_callbacks(self) -> None:
        self.state.on("on_scan_start", self._on_scan_start)
        self.state.on("on_scan_done",  self._on_scan_done)
        self.state.on("on_scan_error", self._on_scan_error)

    def _on_scan_start(self) -> None:
        self.run_button.configure(state="disabled", text="Scanning...")
        self.progress.configure(mode="indeterminate")
        self.progress.start()
        self._log_clear()
        self._log(f"scanning {self.state.scan_target} ...\n")

    def _on_scan_done(self) -> None:
        self.run_button.configure(state="normal", text="Run Scan")
        self.progress.stop()
        self.progress.configure(mode="determinate")
        self.progress.set(1)
        total = len(self.state.findings)
        self._log(f"\ndone — {total} finding(s) across {self.state.files_scanned} file(s)")
        if self.state.files_skipped:
            self._log(f"skipped {self.state.files_skipped} file(s)")

    def _on_scan_error(self, message: str) -> None:
        self.run_button.configure(state="normal", text="Run Scan")
        self.progress.stop()
        self.progress.configure(mode="determinate")
        self.progress.set(0)
        self._log(f"\nerror: {message}")

    def _on_run_clicked(self) -> None:
        target = self.target_var.get().strip()
        if not target:
            self._log("error: please select a target file or directory")
            return
        if not Path(target).exists():
            self._log(f"error: path does not exist: {target}")
            return

        config = PipelineConfig(
            target         = target,
            min_confidence = round(self.confidence_var.get(), 2),
            min_severity   = self.severity_var.get(),
            use_ast        = self.ast_var.get(),
        )
        self.on_run(config)

    def _on_confidence_change(self, value: float) -> None:
        self.conf_label.configure(text=f"{value:.2f}")

    def _browse(self) -> None:
        from tkinter import filedialog
        path = filedialog.askdirectory(title="Select target directory")
        if not path:
            path = filedialog.askopenfilename(
                title      = "Select target file",
                filetypes  = [
                    ("Source files", "*.py *.js *.ts *.java *.php *.rb *.go"),
                    ("All files",    "*.*"),
                ],
            )
        if path:
            self.target_var.set(path)

    # ------------------------------------------------------------------
    # Log helpers
    # ------------------------------------------------------------------

    def _log(self, message: str) -> None:
        self.log_box.configure(state="normal")
        self.log_box.insert("end", message + "\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def _log_clear(self) -> None:
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")

    def show_error(self, message: str) -> None:
        self._log(f"error: {message}")
