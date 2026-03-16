from __future__ import annotations

from tkinter import ttk
import customtkinter as ctk
import matplotlib
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

matplotlib.use("TkAgg")


SEVERITY_CHART_COLORS = {
    "CRITICAL": "#E76361",
    "HIGH":     "#c94f4d",
    "MEDIUM":   "#FFE69F",
    "LOW":      "#486290",
    "INFO":     "#2B426E",
}


class SeverityChart:
    """
    Donut chart showing findings breakdown by severity.

    Embedded in FindingsTab via FigureCanvasTkAgg.
    Updates in-place when refresh() is called — no widget recreation.
    """

    def __init__(self, parent, colors: dict) -> None:
        self.colors = colors
        self._fig, self._ax = self._build_figure()
        self.widget = self._embed(parent)
        self._draw_empty()

    # ------------------------------------------------------------------
    # Figure setup
    # ------------------------------------------------------------------

    def _build_figure(self) -> tuple[Figure, plt.Axes]:
        fig, ax = plt.subplots(figsize=(3.2, 3.2), subplot_kw=dict(aspect="equal"))
        fig.patch.set_facecolor(self.colors["lapis_dark"])
        ax.set_facecolor(self.colors["lapis_dark"])
        ax.axis("off")
        fig.tight_layout(pad=1.0)
        return fig, ax

    def _embed(self, parent) -> FigureCanvasTkAgg:
        canvas = FigureCanvasTkAgg(self._fig, master=parent)
        canvas.draw()
        return canvas.get_tk_widget()

    # ------------------------------------------------------------------
    # Draw
    # ------------------------------------------------------------------

    def _draw_empty(self) -> None:
        self._ax.clear()
        self._ax.set_facecolor(self.colors["lapis_dark"])
        self._ax.axis("off")
        self._ax.text(
            0.5, 0.5,
            "No findings",
            ha         = "center",
            va         = "center",
            color      = self.colors["lapis"],
            fontsize   = 11,
            transform  = self._ax.transAxes,
        )
        self._fig.canvas.draw_idle()

    def update(self, summary: dict[str, int]) -> None:
        """
        Redraw the chart with new data.
        summary = {"CRITICAL": 2, "HIGH": 3, ...}
        """
        self._ax.clear()
        self._ax.set_facecolor(self.colors["lapis_dark"])

        # Filter zero counts
        data = {k: v for k, v in summary.items() if v > 0}

        if not data:
            self._draw_empty()
            return

        labels = list(data.keys())
        values = list(data.values())
        colors = [SEVERITY_CHART_COLORS.get(l, self.colors["lapis"]) for l in labels]
        total  = sum(values)

        # Donut
        wedges, _ = self._ax.pie(
            values,
            colors        = colors,
            startangle    = 90,
            wedgeprops    = dict(width=0.5, edgecolor=self.colors["lapis_dark"], linewidth=2),
            counterclock  = False,
        )

        # Center text — total count
        self._ax.text(
            0, 0,
            str(total),
            ha        = "center",
            va        = "center",
            color     = self.colors["white"],
            fontsize  = 20,
            fontweight= "bold",
        )
        self._ax.text(
            0, -0.22,
            "findings",
            ha       = "center",
            va       = "center",
            color    = self.colors["lapis"],
            fontsize = 9,
        )

        # Legend
        self._ax.legend(
            wedges,
            [f"{l}  {v}" for l, v in zip(labels, values)],
            loc            = "lower center",
            bbox_to_anchor = (0.5, -0.28),
            ncol           = 2,
            frameon        = False,
            fontsize       = 8,
            labelcolor     = self.colors["light_gray"],
        )

        self._fig.canvas.draw_idle()