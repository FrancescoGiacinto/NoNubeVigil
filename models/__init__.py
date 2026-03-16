"""
vigil/models.py
Phase 1 — Data models
 
Core data structures used by every other module in vigil.
No dependencies on other vigil modules — only stdlib.
 
Classes:
    Severity        — enum of finding severity levels
    Confidence      — validated float wrapper (0.0 – 1.0)
    Finding         — single rule match result (main output unit)
    AnalysisContext — per-file state passed into every rule
"""
# vigil/models/__init__.py
from .severity import Severity
from .finding  import Finding
from .context  import AnalysisContext

__all__ = ["Severity", "Finding", "AnalysisContext"]