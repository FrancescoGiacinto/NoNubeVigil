from __future__ import annotations

from ..models import AnalysisContext, Finding, Severity


# Dangerous function calls by language
# Structure: { language: { function_name: (cwe_id, message, remediation) } }
_DANGEROUS_CALLS: dict[str, dict[str, tuple[str, str, str]]] = {
    "python": {
        "eval": (
            "CWE-094",
            "eval() executes arbitrary code — never call with user input",
            "Remove eval(). Use ast.literal_eval() for safe expression parsing.",
        ),
        "exec": (
            "CWE-094",
            "exec() executes arbitrary code — never call with user input",
            "Remove exec(). Redesign to avoid dynamic code execution.",
        ),
        "compile": (
            "CWE-094",
            "compile() with untrusted input enables code injection",
            "Avoid compile() on user-controlled strings.",
        ),
        "subprocess.call": (
            "CWE-078",
            "subprocess.call() with shell=True enables command injection",
            "Use shell=False and pass arguments as a list.",
        ),
        "os.system": (
            "CWE-078",
            "os.system() is vulnerable to command injection",
            "Use subprocess.run() with shell=False instead.",
        ),
        "md5": (
            "CWE-328",
            "MD5 is a weak hashing algorithm — do not use for security",
            "Use hashlib.sha256() or bcrypt for password hashing.",
        ),
    },
    "javascript": {
        "eval": (
            "CWE-094",
            "eval() executes arbitrary code — never call with user input",
            "Remove eval(). Use JSON.parse() for data, or redesign the logic.",
        ),
        "Function": (
            "CWE-094",
            "new Function() is equivalent to eval() — code injection risk",
            "Avoid dynamic function construction from strings.",
        ),
        "setTimeout": (
            "CWE-094",
            "setTimeout() with a string argument evaluates it as code",
            "Pass a function reference instead of a string.",
        ),
        "setInterval": (
            "CWE-094",
            "setInterval() with a string argument evaluates it as code",
            "Pass a function reference instead of a string.",
        ),
    },
    "java": {
        "Runtime.exec": (
            "CWE-078",
            "Runtime.exec() with user input enables command injection",
            "Validate and sanitize input. Use ProcessBuilder with a fixed command list.",
        ),
        "ProcessBuilder": (
            "CWE-078",
            "ProcessBuilder with user-controlled arguments may enable command injection",
            "Whitelist allowed commands and arguments before passing to ProcessBuilder.",
        ),
    },
}


class ASTAnalyzer:
    """
    Visits AST nodes to identify dangerous function calls and
    insecure API usage.

    Operates on the tree-sitter AST stored in AnalysisContext.
    Falls back to line-based heuristics if AST is unavailable —
    ensuring the analyzer always produces output even without
    tree-sitter installed.
    """

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        if context.ast is not None:
            return self._analyze_ast(context)
        return self._analyze_lines(context)

    # ------------------------------------------------------------------
    # AST-based analysis (precise)
    # ------------------------------------------------------------------

    def _analyze_ast(self, context: AnalysisContext) -> list[Finding]:
        """
        Walk the tree-sitter AST and flag dangerous call expressions.
        """
        findings: list[Finding] = []
        dangerous = _DANGEROUS_CALLS.get(context.language, {})

        if not dangerous:
            return findings

        self._visit_node(context.ast.root_node, context, dangerous, findings)
        return findings

    def _visit_node(
        self,
        node:     object,
        context:  AnalysisContext,
        dangerous: dict,
        findings: list[Finding],
    ) -> None:
        """Recursively visit every node in the tree-sitter AST."""
        if node.type in ("call_expression", "call"):
            call_text = context.source[node.start_byte:node.end_byte]
            for func_name, (cwe_id, message, remediation) in dangerous.items():
                if func_name in call_text:
                    line_num = node.start_point[0] + 1   # tree-sitter is 0-based
                    col      = node.start_point[1]
                    findings.append(Finding(
                        file        = context.file_path,
                        line        = line_num,
                        column      = col,
                        rule_id     = "AST001",
                        severity    = Severity.HIGH,
                        confidence  = 0.80,
                        message     = message,
                        remediation = remediation,
                        cwe_id      = cwe_id,
                        snippet     = context.get_line(line_num),
                        tags        = ["dangerous-function", "ast"],
                    ))

        for child in node.children:
            self._visit_node(child, context, dangerous, findings)

    # ------------------------------------------------------------------
    # Line-based fallback (when AST unavailable)
    # ------------------------------------------------------------------

    def _analyze_lines(self, context: AnalysisContext) -> list[Finding]:
        """
        Heuristic fallback — scans lines for dangerous function names.
        Lower confidence than AST analysis due to potential false positives.
        """
        import re
        findings: list[Finding] = []
        dangerous = _DANGEROUS_CALLS.get(context.language, {})

        for line_num, line in enumerate(context.lines, start=1):
            stripped = line.lstrip()
            if stripped.startswith(("#", "//", "*", "--")):
                continue

            for func_name, (cwe_id, message, remediation) in dangerous.items():
                pattern = re.compile(
                    rf'\b{re.escape(func_name)}\s*\(', re.IGNORECASE
                )
                match = pattern.search(line)
                if match:
                    findings.append(Finding(
                        file        = context.file_path,
                        line        = line_num,
                        column      = match.start(),
                        rule_id     = "AST001",
                        severity    = Severity.HIGH,
                        confidence  = 0.60,   # lower — no AST confirmation
                        message     = message,
                        remediation = remediation,
                        cwe_id      = cwe_id,
                        snippet     = context.get_line(line_num),
                        tags        = ["dangerous-function", "heuristic"],
                    ))

        return findings