"""
NoNubeVigil — static analysis rules and models.
Root package so that rules and models are importable as a single package.
"""
from .pipeline import Pipeline, PipelineConfig, ScanResult

__all__ = ["Pipeline", "PipelineConfig", "ScanResult"]