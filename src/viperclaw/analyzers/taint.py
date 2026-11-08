"""
Multi-Language Source-to-Sink Taint SAST Engine (`viperclaw.analyzers.taint`).

Synthesizes the best ideas from Vulnhuntr and Raptor without legacy Python 3.10 / Jedi lock-in:
- Scans Python, TypeScript/JavaScript, Go, and PHP source trees.
- Uses native Python `ast` analysis + multi-language structural taint tracking to trace
  remote user input sources down to dangerous sinks (RCE, SQLi, SSRF, LFI/Path Traversal,
  Insecure Deserialization, SSTI).
- Emits compact Call-Chain Context Slices so an AI agent can verify reachability and
  craft a deterministic Proof-of-Concept without reading thousands of irrelevant lines.
"""

from __future__ import annotations

import ast
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List


LANGUAGE_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".go": "go",
    ".php": "php",
}

SOURCE_PATTERNS: Dict[str, List[re.Pattern[str]]] = {
    "python": [
        re.compile(r"\brequest\.(?:args|form|json|values|data|files|headers|cookies|query_params)\b"),
        re.compile(r"\b(?:Query|Body|Form|Header|Path)\s*\("),
        re.compile(r"\bsys\.argv\b"),
    ],
    "javascript": [
        re.compile(r"\breq\.(?:body|query|params|headers|cookies)\b"),
        re.compile(r"\b(?:searchParams|useSearchParams|context\.params)\b"),
    ],
    "typescript": [
        re.compile(r"\breq\.(?:body|query|params|headers|cookies)\b"),
        re.compile(r"@(?:Body|Query|Param|Headers)\s*\("),
    ],
    "go": [
        re.compile(r"\br\.(?:URL\.Query|FormValue|PostFormValue|Body|Header\.Get)\b"),
        re.compile(r"\bc\.(?:Query|Param|PostForm|ShouldBindJSON|BindJSON)\b"),
    ],
    "php": [
        re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b"),
        re.compile(r"\$request->(?:input|query|post|all|get)\b"),
    ],
}

SINK_DEFINITIONS: List[Dict[str, Any]] = [
    {
        "vuln_class": "Command Injection / RCE",
        "cwe_id": "CWE-78",
        "severity": "CRITICAL",
        "pattern": re.compile(
            r"\b(?:os\.system|os\.popen|subprocess\.(?:Popen|run|call|check_output)|eval|exec|child_process\.exec(?:Sync)?|shell_exec|passthru|proc_open|exec\.Command)\s*\("
        ),
    },
    {
        "vuln_class": "SQL Injection (SQLi)",
        "cwe_id": "CWE-89",
        "severity": "HIGH",
        "pattern": re.compile(
            r"(?:cursor\.execute|\.raw\s*\(|sequelize\.query|db\.Query|db\.Exec|\$pdo->query|mysqli_query)\s*\(\s*(?:f[\"']|[\"'].*?(?:%s|\+|\.\s*\$|\$\{))"
        ),
    },
    {
        "vuln_class": "Server-Side Request Forgery (SSRF)",
        "cwe_id": "CWE-918",
        "severity": "HIGH",
        "pattern": re.compile(
            r"\b(?:requests\.(?:get|post|put|delete|request)|httpx\.(?:get|post|AsyncClient)|urllib\.request\.urlopen|axios\.(?:get|post|request)|http\.Get|curl_exec)\s*\("
        ),
    },
    {
        "vuln_class": "Insecure Deserialization",
        "cwe_id": "CWE-502",
        "severity": "CRITICAL",
        "pattern": re.compile(
            r"\b(?:pickle\.loads?|yaml\.(?:load|unsafe_load)|marshal\.loads|jsonpickle\.decode|unserialize)\s*\("
        ),
    },
    {
        "vuln_class": "Arbitrary File Read / LFI / Path Traversal",
        "cwe_id": "CWE-22",
        "severity": "HIGH",
        "pattern": re.compile(
            r"\b(?:send_file|os\.path\.join|fs\.readFile(?:Sync)?|os\.ReadFile|file_get_contents|include|require)\s*\("
        ),
    },
    {
        "vuln_class": "Server-Side Template Injection (SSTI)",
        "cwe_id": "CWE-1336",
        "severity": "CRITICAL",
        "pattern": re.compile(r"\b(?:render_template_string|Template\s*\(|Twig_Loader_String)\b"),
    },
]


@dataclass
class TaintFlow:
    file_path: str
    language: str
    function_name: str
    vuln_class: str
    cwe_id: str
    severity: str
    source_line: int
    sink_line: int
    source_expr: str
    sink_expr: str
    tainted_vars: List[str] = field(default_factory=list)
    context_slice: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class TaintAnalyzer:
    """Traces remote user input sources to dangerous execution/data sinks."""

    @classmethod
    def _analyze_python_ast(cls, content: str, file_path: str) -> List[TaintFlow]:
        flows: List[TaintFlow] = []
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return flows

        lines = content.splitlines()
        src_regexes = SOURCE_PATTERNS["python"]

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            start_line = node.lineno
            end_line = getattr(node, "end_lineno", start_line + 40)
            func_lines = lines[start_line - 1 : end_line]
            func_text = "\n".join(func_lines)

            # Collect parameter names + variables assigned from request sources
            tainted_vars = {arg.arg for arg in node.args.args if arg.arg not in {"self", "cls", "db"}}
            source_line = start_line
            source_expr = f"def {node.name}({', '.join(sorted(tainted_vars))})"

            for idx, raw_line in enumerate(func_lines, start=start_line):
                for s_re in src_regexes:
                    if s_re.search(raw_line):
                        source_line = idx
                        source_expr = raw_line.strip()
                        assign_match = re.match(r"\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=", raw_line)
                        if assign_match:
                            tainted_vars.add(assign_match.group(1))

            if not tainted_vars and not any(r.search(func_text) for r in src_regexes):
                continue

            for idx, raw_line in enumerate(func_lines, start=start_line):
                for sink_def in SINK_DEFINITIONS:
                    if sink_def["pattern"].search(raw_line):
                        # Check if any tainted variable or direct source expression appears in the sink line
                        used_vars = [v for v in tainted_vars if re.search(rf"\b{re.escape(v)}\b", raw_line)]
                        direct_src = any(r.search(raw_line) for r in src_regexes)
                        if used_vars or direct_src:
                            slice_start = max(1, min(source_line, idx) - 2)
                            slice_end = min(len(lines), max(source_line, idx) + 2)
                            snippet = "\n".join(
                                f"{ln}: {lines[ln - 1]}" for ln in range(slice_start, slice_end + 1)
                            )
                            flows.append(
                                TaintFlow(
                                    file_path=file_path,
                                    language="python",
                                    function_name=node.name,
                                    vuln_class=sink_def["vuln_class"],
                                    cwe_id=sink_def["cwe_id"],
                                    severity=sink_def["severity"],
                                    source_line=source_line,
                                    sink_line=idx,
                                    source_expr=source_expr,
                                    sink_expr=raw_line.strip(),
                                    tainted_vars=sorted(used_vars),
                                    context_slice=snippet,
                                )
                            )
        return flows

    @classmethod
    def _analyze_generic(cls, content: str, file_path: str, language: str) -> List[TaintFlow]:
        flows: List[TaintFlow] = []
        lines = content.splitlines()
        src_regexes = SOURCE_PATTERNS.get(language, [])
        if not src_regexes:
            return flows

        tainted_vars: Dict[str, tuple[int, str]] = {}
        for idx, raw_line in enumerate(lines, start=1):
            for s_re in src_regexes:
                if s_re.search(raw_line):
                    var_match = re.search(
                        r"(?:const|let|var|\$)?([a-zA-Z_][a-zA-Z0-9_]*)\s*(?::=|=)", raw_line
                    )
                    vname = var_match.group(1) if var_match else "user_input"
                    tainted_vars[vname] = (idx, raw_line.strip())

        if not tainted_vars:
            return flows

        for idx, raw_line in enumerate(lines, start=1):
            for sink_def in SINK_DEFINITIONS:
                if sink_def["pattern"].search(raw_line):
                    matched_vars = [
                        v for v in tainted_vars if re.search(rf"\b{re.escape(v)}\b", raw_line)
                    ]
                    direct_src = any(r.search(raw_line) for r in src_regexes)
                    if matched_vars or direct_src:
                        first_var = matched_vars[0] if matched_vars else next(iter(tainted_vars))
                        src_ln, src_expr = tainted_vars[first_var]
                        slice_start = max(1, min(src_ln, idx) - 2)
                        slice_end = min(len(lines), max(src_ln, idx) + 2)
                        snippet = "\n".join(
                            f"{ln}: {lines[ln - 1]}" for ln in range(slice_start, slice_end + 1)
                        )
                        flows.append(
                            TaintFlow(
                                file_path=file_path,
                                language=language,
                                function_name="handler",
                                vuln_class=sink_def["vuln_class"],
                                cwe_id=sink_def["cwe_id"],
                                severity=sink_def["severity"],
                                source_line=src_ln,
                                sink_line=idx,
                                source_expr=src_expr,
                                sink_expr=raw_line.strip(),
                                tainted_vars=matched_vars,
                                context_slice=snippet,
                            )
                        )
        return flows

    @classmethod
    def analyze_file(cls, file_path: str | Path) -> List[TaintFlow]:
        path = Path(file_path)
        lang = LANGUAGE_EXTENSIONS.get(path.suffix.lower())
        if not lang:
            return []
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []

        if lang == "python":
            ast_flows = cls._analyze_python_ast(content, str(path))
            if ast_flows:
                return ast_flows
        return cls._analyze_generic(content, str(path), lang)

    @classmethod
    def scan_path(cls, target_path: str | Path) -> Dict[str, Any]:
        path = Path(target_path)
        files: List[Path] = []
        if path.is_file():
            files = [path]
        elif path.is_dir():
            files = sorted(
                p
                for p in path.rglob("*")
                if p.suffix.lower() in LANGUAGE_EXTENSIONS
                and not any(skip in p.parts for skip in ("node_modules", ".git", ".venv", "venv", "__pycache__"))
            )

        all_flows: List[TaintFlow] = []
        for f in files:
            all_flows.extend(cls.analyze_file(f))

        return {
            "files_scanned": len(files),
            "total_flows": len(all_flows),
            "flows": [fl.to_dict() for fl in all_flows],
        }
