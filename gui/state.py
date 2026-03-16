from __future__ import annotations

import queue
import threading
from dataclasses import dataclass, field
from typing import Callable, Optional

from nonubevigil.models import Finding, Severity


# ---------------------------------------------------------------------------
# Scan state
# ---------------------------------------------------------------------------

class ScanStatus:
    IDLE     = "idle"
    RUNNING  = "running"
    DONE     = "done"
    ERROR    = "error"


@dataclass
class AppState:
    """
    Shared state across all tabs.

    Passed to every tab at construction time.
    Tabs read and write to this object — never communicate directly
    with each other.

    Fields
    ------
    findings        : list of findings from the last scan
    status          : current scan status (idle / running / done / error)
    scan_target     : path being scanned
    files_scanned   : number of files analyzed in last scan
    files_skipped   : number of files skipped in last scan
    error_message   : error message if status == ERROR
    result_queue    : thread-safe queue between worker and UI
    selected_finding: currently selected finding in FindingsTable
    callbacks       : registered UI callbacks triggered on state change
    """

    findings:         list[Finding]      = field(default_factory=list)
    status:           str                = ScanStatus.IDLE
    scan_target:      str                = ""
    files_scanned:    int                = 0
    files_skipped:    int                = 0
    error_message:    str                = ""
    result_queue:     queue.Queue        = field(default_factory=queue.Queue)
    selected_finding: Optional[Finding]  = None
    _callbacks:       dict[str, list[Callable]] = field(
        default_factory=lambda: {
            "on_scan_start":    [],
            "on_scan_done":     [],
            "on_scan_error":    [],
            "on_finding_select":[],
        }
    )
    _lock: threading.Lock = field(default_factory=threading.Lock)

    # ------------------------------------------------------------------
    # Callback registration
    # ------------------------------------------------------------------

    def on(self, event: str, callback: Callable) -> None:
        """Register a callback for a state change event."""
        if event in self._callbacks:
            self._callbacks[event].append(callback)

    def emit(self, event: str, *args) -> None:
        """Fire all callbacks registered for an event."""
        for cb in self._callbacks.get(event, []):
            cb(*args)

    # ------------------------------------------------------------------
    # State transitions
    # ------------------------------------------------------------------

    def start_scan(self, target: str) -> None:
        with self._lock:
            self.status        = ScanStatus.RUNNING
            self.scan_target   = target
            self.findings      = []
            self.files_scanned = 0
            self.files_skipped = 0
            self.error_message = ""
            self.selected_finding = None
        self.emit("on_scan_start")

    def finish_scan(self, findings: list[Finding], files_scanned: int, files_skipped: int) -> None:
        with self._lock:
            self.status        = ScanStatus.DONE
            self.findings      = findings
            self.files_scanned = files_scanned
            self.files_skipped = files_skipped
        self.emit("on_scan_done")

    def fail_scan(self, message: str) -> None:
        with self._lock:
            self.status        = ScanStatus.ERROR
            self.error_message = message
        self.emit("on_scan_error", message)

    def select_finding(self, finding: Finding) -> None:
        with self._lock:
            self.selected_finding = finding
        self.emit("on_finding_select", finding)

    # ------------------------------------------------------------------
    # Convenience filters
    # ------------------------------------------------------------------

    def findings_by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def findings_above(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity >= severity]

    def summary(self) -> dict[str, int]:
        counts = {s.name: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.name] += 1
        return counts