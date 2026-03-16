from __future__ import annotations

import threading
from pathlib import Path

import customtkinter as ctk
from PIL import Image

from nonubevigil import Pipeline, PipelineConfig
from gui.state import AppState, ScanStatus
from gui.tabs.scan_tab import ScanTab
from gui.tabs.findings_tab import FindingsTab
from gui.tabs.detail_tab import DetailTab
from gui.components.status_bar import StatusBar


# ---------------------------------------------------------------------------
# Color palette
# ---------------------------------------------------------------------------

COLORS = {
    "bease":         "#E8E4D9",
    "lapis":         "#486290",
    "lapis_dark":    "#0F2C5C",
    "lapis_mid":     "#2B426E",
    "indian_red":    "#E76361",
    "charcoal":      "#374151",
    "white":         "#FFFFFF",
    "light_gray":    "#F0F4F8",
    "light_vanilla": "#FFE69F",
}

SEVERITY_COLORS = {
    "CRITICAL": "#E76361",   # indian red
    "HIGH":     "#E76361",   # indian red lighter
    "MEDIUM":   "#FFE69F",   # light vanilla
    "LOW":      "#486290",   # lapis
    "INFO":     "#486290",   # lapis
}


# ---------------------------------------------------------------------------
# CustomTkinter theme setup
# ---------------------------------------------------------------------------

def apply_theme() -> None:
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------

class VIGILApp(ctk.CTk):
    """
    Main application window.

    Owns the tab manager and the shared AppState.
    Responsible for launching Pipeline in a worker thread
    and polling the result queue to update the UI.
    """

    def __init__(self) -> None:
        super().__init__()
        apply_theme()

        self.app_state = AppState()
        self._setup_window()
        self._build_layout()
        self._register_callbacks()

    # ------------------------------------------------------------------
    # Window setup
    # ------------------------------------------------------------------

    def _setup_window(self) -> None:
        self.title("vigil — Security Code Analyzer")
        self.geometry("1100x720")
        self.minsize(900, 600)
        self.configure(fg_color=COLORS["lapis_dark"])

        # Center on screen
        self.update_idletasks()
        x = (self.winfo_screenwidth()  // 2) - (1100 // 2)
        y = (self.winfo_screenheight() // 2) - (720  // 2)
        self.geometry(f"+{x}+{y}")

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def _build_layout(self) -> None:
        # Header
        self._build_header()

        # Tab view
        self.tabview = ctk.CTkTabview(
            self,
            fg_color        = COLORS["lapis_mid"],
            segmented_button_fg_color         = COLORS["lapis_dark"],
            segmented_button_selected_color   = COLORS["lapis"],
            segmented_button_unselected_color = COLORS["lapis_dark"],
            segmented_button_selected_hover_color   = COLORS["lapis"],
            segmented_button_unselected_hover_color = COLORS["lapis_mid"],
            text_color       = COLORS["white"],
            text_color_disabled = COLORS["lapis"],
        )
        self.tabview.pack(fill="both", expand=True, padx=12, pady=(0, 8))

        # Add tabs
        self.tabview.add("Scan")
        self.tabview.add("Findings")
        self.tabview.add("Detail")

        # Instantiate tab controllers
        self.scan_tab = ScanTab(
            parent = self.tabview.tab("Scan"),
            state  = self.app_state,
            colors = COLORS,
            on_run = self._run_scan,
        )
        self.findings_tab = FindingsTab(
            parent = self.tabview.tab("Findings"),
            state  = self.app_state,
            colors = COLORS,
        )
        self.detail_tab = DetailTab(
            parent = self.tabview.tab("Detail"),
            state  = self.app_state,
            colors = COLORS,
        )

        # Status bar
        self.status_bar = StatusBar(self, self.app_state, COLORS)
        self.status_bar.pack(fill="x", padx=12, pady=(0, 6))

    def _build_header(self) -> None:
        header = ctk.CTkFrame(self, fg_color=COLORS["lapis_dark"], height=56)
        header.pack(fill="x", padx=12, pady=(12, 4))
        header.pack_propagate(False)

        logo_path = Path(__file__).resolve().parent / "static" / "logo.png"
        if logo_path.exists():
            pil_image = Image.open(logo_path).copy()
            logo_image = ctk.CTkImage(
                light_image=pil_image,
                dark_image=pil_image,
                size=(36, 36),
            )
            logo_label = ctk.CTkLabel(header, image=logo_image, text="")
            logo_label.pack(side="left", padx=(16, 8))
        ctk.CTkLabel(
            header,
            text       = "vigil",
            font       = ctk.CTkFont(size=24, weight="bold"),
            text_color = COLORS["white"],
        ).pack(side="left", padx=(0, 4))

        ctk.CTkLabel(
            header,
            text       = "Security Code Analyzer",
            font       = ctk.CTkFont(size=13),
            text_color = COLORS["bease"],
        ).pack(side="left", padx=4)

        # Version badge
        ctk.CTkLabel(
            header,
            text       = "v0.1.0",
            font       = ctk.CTkFont(size=11),
            text_color = COLORS["lapis_dark"],
            fg_color   = COLORS["bease"],
            corner_radius = 6,
            padx       = 8,
            pady       = 2,
        ).pack(side="right", padx=16)

    # ------------------------------------------------------------------
    # Callbacks
    # ------------------------------------------------------------------

    def _register_callbacks(self) -> None:
        self.app_state.on("on_scan_done",  self._on_scan_done)
        self.app_state.on("on_scan_error", self._on_scan_error)
        self.app_state.on("on_finding_select", self._on_finding_select)

    def _on_scan_done(self) -> None:
        """Switch to Findings tab automatically when scan completes."""
        self.tabview.set("Findings")
        self.findings_tab.refresh()

    def _on_scan_error(self, message: str) -> None:
        self.scan_tab.show_error(message)

    def _on_finding_select(self, finding) -> None:
        """Switch to Detail tab when a finding is selected."""
        self.tabview.set("Detail")
        self.detail_tab.refresh()

    # ------------------------------------------------------------------
    # Scan execution
    # ------------------------------------------------------------------

    def _run_scan(self, config: PipelineConfig) -> None:
        """
        Launch Pipeline.run() in a worker thread.
        Poll the result queue every 100ms from the main thread.
        """
        self.app_state.start_scan(config.target)

        def worker() -> None:
            try:
                result = Pipeline(config).run()
                self.app_state.result_queue.put(("done", result))
            except Exception as exc:
                self.app_state.result_queue.put(("error", str(exc)))

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()

        self._poll_queue()

    def _poll_queue(self) -> None:
        """
        Check the result queue every 100ms.
        Runs on the main thread — safe to update UI here.
        """
        try:
            event, payload = self.app_state.result_queue.get_nowait()
            if event == "done":
                self.app_state.finish_scan(
                    findings      = payload.findings,
                    files_scanned = payload.files_scanned,
                    files_skipped = payload.files_skipped,
                )
            elif event == "error":
                self.app_state.fail_scan(payload)
        except Exception:
            # Queue empty — check again in 100ms
            self.after(100, self._poll_queue)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    app = VIGILApp()
    app.mainloop()


if __name__ == "__main__":
    main()
