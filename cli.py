from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .pipeline import Pipeline, PipelineConfig, ScanResult
from .output   import CLIFormatter, SARIFExporter, PDFReporter


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog        = "vigil",
        description = "Static application security testing with taint analysis",
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog = """
examples:
  vigil scan ./src
  vigil scan ./src --severity high --format sarif --output results.sarif.json
  vigil scan ./src --language python javascript --min-confidence 0.5
  vigil scan ./app --rules ./custom_rules/ --format pdf --output report.pdf
  vigil list-rules
        """,
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # ------------------------------------------------------------------
    # scan command
    # ------------------------------------------------------------------

    scan = subparsers.add_parser(
        "scan",
        help        = "Scan a file or directory for security issues",
    )

    scan.add_argument(
        "target",
        type    = str,
        help    = "File or directory to scan",
    )
    scan.add_argument(
        "--format", "-f",
        choices = ["cli", "sarif", "pdf"],
        default = "cli",
        help    = "Output format (default: cli)",
    )
    scan.add_argument(
        "--output", "-o",
        type    = str,
        default = None,
        help    = "Output file path (required for sarif and pdf formats)",
    )
    scan.add_argument(
        "--severity", "-s",
        choices = ["info", "low", "medium", "high", "critical"],
        default = "low",
        help    = "Minimum severity to report (default: low)",
    )
    scan.add_argument(
        "--min-confidence", "-c",
        type    = float,
        default = 0.30,
        metavar = "FLOAT",
        help    = "Minimum confidence threshold 0.0–1.0 (default: 0.30)",
    )
    scan.add_argument(
        "--language", "-l",
        nargs   = "+",
        default = [],
        metavar = "LANG",
        dest    = "languages",
        help    = "Restrict scan to these languages (e.g. python javascript)",
    )
    scan.add_argument(
        "--rules", "-r",
        type    = str,
        default = None,
        metavar = "DIR",
        dest    = "rules_dir",
        help    = "Directory containing custom rule files",
    )
    scan.add_argument(
        "--no-ast",
        action  = "store_true",
        default = False,
        help    = "Disable tree-sitter AST analysis (faster, less precise)",
    )
    scan.add_argument(
        "--verbose", "-v",
        action  = "store_true",
        default = False,
        help    = "Show tags, warnings, and skipped files",
    )
    scan.add_argument(
        "--no-color",
        action  = "store_true",
        default = False,
        help    = "Disable terminal color output",
    )
    scan.add_argument(
        "--exit-zero",
        action  = "store_true",
        default = False,
        help    = "Always exit with code 0 (useful in CI to not block the pipeline)",
    )

    # ------------------------------------------------------------------
    # list-rules command
    # ------------------------------------------------------------------

    subparsers.add_parser(
        "list-rules",
        help = "List all available rules",
    )

    return parser


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def cmd_scan(args: argparse.Namespace) -> int:
    """Execute a scan and produce output in the requested format."""

    # Validate output path requirement
    if args.format in ("sarif", "pdf") and not args.output:
        print(
            f"error: --output is required when --format is '{args.format}'",
            file=sys.stderr,
        )
        return 2

    # Validate confidence range
    if not 0.0 <= args.min_confidence <= 1.0:
        print(
            "error: --min-confidence must be between 0.0 and 1.0",
            file=sys.stderr,
        )
        return 2

    # Build config and run pipeline
    config = PipelineConfig(
        target         = args.target,
        min_confidence = args.min_confidence,
        min_severity   = args.severity.upper(),
        use_ast        = not args.no_ast,
        rules_dir      = args.rules_dir,
        languages      = args.languages,
    )

    print(f"scanning {args.target} ...", file=sys.stderr)

    result: ScanResult = Pipeline(config).run()

    # Dispatch to output format
    if args.format == "cli":
        _output_cli(result, args)
    elif args.format == "sarif":
        _output_sarif(result, args)
    elif args.format == "pdf":
        _output_pdf(result, args)

    # Exit code — non-zero if findings exist (useful for CI)
    if args.exit_zero:
        return 0
    return 1 if result.findings else 0


def cmd_list_rules(args: argparse.Namespace) -> int:
    """Print all available rules with metadata."""
    from .ingestion import PluginLoader

    rules = PluginLoader().load_defaults()

    print(f"\n{'ID':<10} {'SEVERITY':<10} {'LANGUAGES':<25} DESCRIPTION")
    print("─" * 80)

    for rule in rules:
        langs = ", ".join(rule.languages) if rule.languages else "all"
        print(
            f"{rule.rule_id:<10} "
            f"{rule.severity.name:<10} "
            f"{langs:<25} "
            f"{rule.description}"
        )
    print()
    return 0


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _output_cli(result: ScanResult, args: argparse.Namespace) -> None:
    formatter = CLIFormatter(
        verbose  = args.verbose,
        no_color = args.no_color,
    )
    formatter.print_results(
        findings      = result.findings,
        files_scanned = result.files_scanned,
        files_skipped = result.files_skipped,
        errors        = result.errors,
    )


def _output_sarif(result: ScanResult, args: argparse.Namespace) -> None:
    output = SARIFExporter().export(result.findings, args.output)
    print(f"sarif report written to {output}", file=sys.stderr)


def _output_pdf(result: ScanResult, args: argparse.Namespace) -> None:
    output = PDFReporter().export(
        findings    = result.findings,
        output_path = args.output,
        target      = args.target,
    )
    print(f"pdf report written to {output}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    handlers = {
        "scan":       cmd_scan,
        "list-rules": cmd_list_rules,
    }

    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(2)

    sys.exit(handler(args))


if __name__ == "__main__":
    main()