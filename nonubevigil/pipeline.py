from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .ingestion  import FileWalker, SourceParser, PluginLoader
from .analyzers  import PatternAnalyzer, ASTAnalyzer, DataFlowAnalyzer
from .scoring    import ConfidenceScorer
from .models     import Finding


# ---------------------------------------------------------------------------
# Pipeline configuration
# ---------------------------------------------------------------------------

@dataclass
class PipelineConfig:
    """
    All tunable parameters for a vigil scan.

    Passed to Pipeline at construction time — never mutated during a scan.

    Fields
    ------
    target          : file or directory to scan
    min_confidence  : findings below this threshold are discarded
    min_severity    : findings below this severity are discarded
    use_ast         : whether to attempt tree-sitter AST parsing
    rules_dir       : optional path to a directory of custom rules
    languages       : restrict scan to these languages (empty = all)
    """
    target:         str | Path
    min_confidence: float      = 0.30
    min_severity:   str        = "LOW"
    use_ast:        bool       = True
    rules_dir:      str | Path | None = None
    languages:      list[str]  = field(default_factory=list)


# ---------------------------------------------------------------------------
# Scan result
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    """
    Output of a complete pipeline run.

    Consumed by the output layer (CLIFormatter, SARIFExporter, PDFReporter).

    Fields
    ------
    findings        : final scored and sorted list of findings
    files_scanned   : number of files analyzed
    files_skipped   : number of files that could not be parsed
    errors          : per-file error messages for debugging
    """
    findings:      list[Finding]
    files_scanned: int
    files_skipped: int
    errors:        list[str]    = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.findings)

    @property
    def is_clean(self) -> bool:
        """True if no findings were produced."""
        return len(self.findings) == 0


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

class Pipeline:
    """
    Main orchestrator — runs the full vigil scan end to end.

    Flow per file
    -------------
    FileWalker → SourceParser → PluginLoader
        → PatternAnalyzer
        → ASTAnalyzer
        → DataFlowAnalyzer
        → ConfidenceScorer
        → ScanResult

    Error isolation
    ---------------
    Failures are caught at the per-file level — one unreadable file
    or one crashing rule never aborts the full scan.
    """

    def __init__(self, config: PipelineConfig) -> None:
        self.config = config

        self._walker  = FileWalker()
        self._parser  = SourceParser(use_ast=config.use_ast)
        self._loader  = PluginLoader()
        self._scorer  = ConfidenceScorer(min_confidence=config.min_confidence)

        self._rules   = self._load_rules()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> ScanResult:
        """
        Execute the full scan and return a ScanResult.
        This is the only method the CLI and tests need to call.
        """
        files         = self._walker.walk(self.config.target)
        all_findings: list[Finding] = []
        files_scanned = 0
        files_skipped = 0
        errors:       list[str] = []

        for file_path in files:
            language = self._walker.detect_language(file_path)

            # Filter by language if configured
            if self.config.languages and language not in self.config.languages:
                continue

            context = self._parser.parse(file_path, language)

            if context is None:
                files_skipped += 1
                errors.append(f"Could not parse: {file_path}")
                continue

            file_findings = self._analyze_file(context, errors)
            all_findings.extend(file_findings)
            files_scanned += 1

        # Score and filter all findings together
        scored = self._scorer.score(all_findings)
        scored = self._apply_severity_filter(scored)

        return ScanResult(
            findings      = scored,
            files_scanned = files_scanned,
            files_skipped = files_skipped,
            errors        = errors,
        )

    # ------------------------------------------------------------------
    # Per-file analysis
    # ------------------------------------------------------------------

    def _analyze_file(self, context, errors: list[str]) -> list[Finding]:
        """
        Run all three analyzers on a single file.
        Each analyzer is wrapped in try/except — a crash in one
        does not prevent the others from running.
        """
        findings: list[Finding] = []

        for analyzer_cls, analyzer in [
            ("PatternAnalyzer",  PatternAnalyzer(self._rules)),
            ("ASTAnalyzer",      ASTAnalyzer()),
            ("DataFlowAnalyzer", DataFlowAnalyzer()),
        ]:
            try:
                findings.extend(analyzer.analyze(context))
            except Exception as exc:
                errors.append(
                    f"[{analyzer_cls}] failed on {context.file_path}: {exc}"
                )

        return findings

    # ------------------------------------------------------------------
    # Rule loading
    # ------------------------------------------------------------------

    def _load_rules(self):
        """
        Load built-in rules, then append custom rules from rules_dir
        if provided.
        """
        rules = self._loader.load_defaults()

        if self.config.rules_dir:
            try:
                custom = self._loader.load_from_dir(self.config.rules_dir)
                rules.extend(custom)
            except NotADirectoryError as exc:
                print(f"[warn] {exc}")

        return rules

    # ------------------------------------------------------------------
    # Severity filter
    # ------------------------------------------------------------------

    def _apply_severity_filter(self, findings: list[Finding]) -> list[Finding]:
        """
        Discard findings below the configured minimum severity.
        Severity comparison uses the ordinal defined in Severity enum.
        """
        from .models import Severity
        try:
            min_sev = Severity[self.config.min_severity.upper()]
        except KeyError:
            min_sev = Severity.LOW

        return [f for f in findings if f.severity >= min_sev]