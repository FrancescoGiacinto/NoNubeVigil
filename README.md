# NoNubeVigil

[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Coverage](https://img.shields.io/badge/coverage-pytest--cov-informational)](https://github.com/)

**NoNubeVigil** (vigil) is a static application security testing (SAST) tool that analyzes source code for security issues using pattern matching, tree-sitter AST analysis, and taint/dataflow analysis. It supports multiple languages, configurable rules, and outputs findings in CLI, SARIF, or PDF formats. A desktop GUI is also available.

---

## Example output

Running `vigil scan ./src` produces human-readable findings with location, rule, confidence, and remediation:

```
vigil · 2 finding(s) across 12 file(s)
------------------------------------------------------------

[HIGH     ] src/auth.py:14:4 · SEC001 · confidence 0.89
  Possible hardcoded secret: API key or credential in source.
    api_key = "sk_live_abc123xyz"
  fix: Move secrets to environment variables or a secret manager. Do not commit.

[MEDIUM   ] src/views.py:28:12 · SEC003 · confidence 0.72
  User-controlled data may be reflected in HTML without sanitization (XSS).
    return HttpResponse(user_input)
  fix: Encode or sanitize user input before rendering. Use a template engine with auto-escaping.

summary: HIGH: 1, MEDIUM: 1
```

SARIF output can be uploaded to GitHub so findings appear in the **Security** tab and in PR checks (see [SARIF + GitHub Actions](#sarif--github-actions) below).

---

## Features

### Analysis & languages

- **Multi-language support**: Python, JavaScript, TypeScript, Java (with AST); PHP, Ruby, Go (pattern-based). File extensions: `.py`, `.js`, `.ts`, `.jsx`, `.tsx`, `.java`, `.php`, `.rb`, `.go`.
- **Optional AST**: Full tree-sitter AST and dataflow analysis when installed with `--extras ast`; use `--no-ast` for faster, pattern-only scans.

### Rules & scoring

- **Built-in security rules**: Hardcoded secrets (SEC001), SQL injection (SEC002), XSS (SEC003), insecure deserialization (SEC004) — each mapped to CWE/OWASP.
- **Confidence scoring**: Findings scored 0.0–1.0; set `--min-confidence` to reduce noise.
- **Severity filtering**: Report only findings at or above a level: info, low, medium, high, critical.
- **Custom rules**: Load extra rules from a directory; implement Python classes extending `BaseRule`.

### Output & integration

- **Output formats**: Human-readable CLI, SARIF (for CI and GitHub Security tab), and PDF reports.
- **SARIF + GitHub**: Upload SARIF so results show in the repository Security tab and in pull request checks (example workflow below).
- **GUI**: Desktop app (CustomTkinter) with Scan, Findings, and Detail tabs.

---

## Requirements

- **Python**: 3.13+
- **Package manager**: [Poetry](https://python-poetry.org/) (recommended)

---

## Installation

Clone the repository and install with Poetry:

```bash
git clone <repository-url>
cd NoNubeVigil
poetry install
```

- **Pattern-only (no AST)**: The default `poetry install` does not include tree-sitter. Scans use pattern matching only; use `--no-ast` if you never install AST extras.
- **Full AST support**: For tree-sitter parsing and dataflow analysis (recommended for Python, JavaScript, TypeScript, Java):

  ```bash
  poetry install --extras ast
  ```

  Without the `ast` extra, the pipeline still runs but AST-based and dataflow checks are skipped.

Activate the virtual environment and run the tools:

```bash
poetry shell
# Then use: vigil ... or vigil-gui
```

Or run without activating the shell:

```bash
poetry run vigil scan ./src
poetry run vigil-gui
```

---

## Usage

### Command-line interface (CLI)

Entry point: **`vigil`** (or `poetry run vigil`).

#### Scan a target

```bash
vigil scan <path>              # path = file or directory
vigil scan ./src                # scan directory
vigil scan ./src --severity high --min-confidence 0.5
vigil scan ./src --language python javascript
vigil scan ./src --rules ./custom_rules/ --format sarif --output results.sarif.json
vigil scan ./src --format pdf --output report.pdf
vigil scan ./src --no-ast       # disable AST (faster, less precise)
vigil scan ./src --verbose      # show tags, warnings, skipped files
vigil scan ./src --no-color     # disable colored output
vigil scan ./src --exit-zero    # always exit 0 (e.g. for CI)
```

**Scan options:**

| Option | Short | Description | Default |
|--------|--------|-------------|---------|
| `--format` | `-f` | Output format: `cli`, `sarif`, `pdf` | `cli` |
| `--output` | `-o` | Output file (required for `sarif` and `pdf`) | — |
| `--severity` | `-s` | Minimum severity: `info`, `low`, `medium`, `high`, `critical` | `low` |
| `--min-confidence` | `-c` | Minimum confidence 0.0–1.0 | `0.30` |
| `--language` | `-l` | Restrict to languages (e.g. `python javascript`) | all |
| `--rules` | `-r` | Directory with custom rule modules | built-in only |
| `--no-ast` | — | Disable tree-sitter AST analysis | AST on |
| `--verbose` | `-v` | Show tags, warnings, skipped files | off |
| `--no-color` | — | Disable colored CLI output | on |
| `--exit-zero` | — | Always exit with code 0 | off |

Exit code: **0** if no findings (or with `--exit-zero`); **1** if there are findings; **2** on usage/validation error.

#### List built-in rules

```bash
vigil list-rules
```

Shows rule ID, severity, languages, and description for all loaded rules.

---

### GUI

Entry point: **`vigil-gui`** (or `poetry run vigil-gui`).

- **Scan tab**: Set target path and scan options, run scan.
- **Findings tab**: List of findings after a scan; select one to view details.
- **Detail tab**: Full details for the selected finding (location, message, severity, CWE/OWASP, code snippet, etc.).

Scans run in a background thread; the UI updates when the scan completes.

---

## Built-in rules

| Rule ID | Description | Severity |
|---------|-------------|----------|
| SEC001 | Hardcoded secrets / credentials | High |
| SEC002 | SQL injection | High |
| SEC003 | Cross-site scripting (XSS) | Medium |
| SEC004 | Insecure deserialization | High |

Rules are implemented in `nonubevigil/rules/` and can be extended via custom rule directories.

---

## Custom rules

1. Create a directory (e.g. `custom_rules/`).
2. Add Python files (no leading `_`) that define classes inheriting from `BaseRule` from the vigil package.
3. Implement `analyze(self, context: AnalysisContext) -> list[Finding]`.
4. Set class attributes: `rule_id`, `severity`, `confidence_base`, `languages`, `description`.
5. Run with: `vigil scan ./src --rules ./custom_rules/`.

Only files with `.py` extension and classes that are subclasses of `BaseRule` are loaded.

---

## Output formats

- **CLI**: Human-readable list of findings (file, line, rule, severity, message). Use `--verbose` for extra detail.
- **SARIF**: Standard format for static analysis; use `--format sarif --output <path>`.
- **PDF**: Summary report; use `--format pdf --output <path>`.

---

## SARIF + GitHub Actions

Vigil’s SARIF output integrates with GitHub’s **Code scanning** so findings appear in the repository **Security** tab and as status checks on pull requests. Example workflow:

```yaml
# .github/workflows/vigil.yml
name: Vigil SAST

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

jobs:
  vigil:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.13"

      - name: Install Poetry
        run: pip install poetry

      - name: Install dependencies
        run: poetry install --extras ast

      - name: Run Vigil (SARIF)
        run: |
          poetry run vigil scan . \
            --format sarif \
            --output vigil-results.sarif.json \
            --severity low

      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: vigil-results.sarif.json
```

After the workflow runs, open **Security → Code scanning** in the repo to see Vigil’s findings. Use `--exit-zero` in the scan step if you want the job to succeed even when findings exist (e.g. to only report, not block).

---

## Project structure (overview)

```
NoNubeVigil/
├── nonubevigil/           # Core engine
│   ├── cli.py             # CLI entry (vigil)
│   ├── pipeline.py        # Orchestrator: ingestion → analyze → score → output
│   ├── ingestion/         # File discovery, parsing, rule loading
│   ├── analyzers/         # Pattern, AST, dataflow analysis
│   ├── rules/             # Built-in security rules (BaseRule subclasses)
│   ├── models/            # Finding, Severity, AnalysisContext
│   ├── scoring/           # Confidence scoring
│   └── output/            # CLI formatter, SARIF exporter, PDF reporter
├── gui/                   # Desktop GUI (vigil-gui)
│   ├── app.py             # Main window and entry point
│   ├── state.py           # Shared app state and events
│   ├── tabs/              # Scan, Findings, Detail tabs
│   └── components/        # Status bar, severity chart, etc.
├── tests/                 # Pytest tests
├── pyproject.toml         # Project metadata, Poetry config, scripts
└── README.md
```

---

## Development and testing

- **Linting**: Ruff (see `pyproject.toml`).
- **Type checking**: basedpyright.
- **Tests**: Pytest with coverage:

  ```bash
  poetry run pytest
  ```

  Coverage is reported for the `nonubevigil` package.

---

## License

MIT.

---

## Author

Francesco Giacinto — [francesco.giacinto@outlook.com](mailto:francesco.giacinto@outlook.com)
