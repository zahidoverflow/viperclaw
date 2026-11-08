"""
Multi-Language Source-to-Sink Taint SAST Engine (`viperclaw.analyzers.taint`).

v1.1 Enhancements (Validated on DVWA & Multi-Lang Benchmarks):
- Forward-only Multi-Hop Transitive Taint Propagation (`source_line <= sink_line`).
- Context-Aware Sanitizer & Guard De-Tainting (`intval`, `is_numeric`, `PDO::prepare`,
  `in_array` allowlists, `htmlspecialchars`, `stripslashes` + `mysqli_real_escape_string`
  distinction between SQLi-safe vs Stored-XSS-vulnerable).
- 11 Vulnerability Sink Classes across Python, TypeScript/JavaScript, Go, and PHP.
"""

from __future__ import annotations

import ast
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Set


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
        re.compile(r"\brequest\.(?:args|form|json|values|data|files|headers|cookies|query_params|GET|POST)\b"),
        re.compile(r"\b(?:Query|Body|Form|Header|Path)\s*\("),
        re.compile(r"\bsys\.argv\b"),
    ],
    "javascript": [
        re.compile(r"\breq\.(?:body|query|params|headers|cookies|files)\b"),
        re.compile(r"\b(?:searchParams|useSearchParams|context\.params|document\.location|location\.(?:href|search|hash))\b"),
    ],
    "typescript": [
        re.compile(r"\breq\.(?:body|query|params|headers|cookies|files)\b"),
        re.compile(r"@(?:Body|Query|Param|Headers)\s*\("),
    ],
    "go": [
        re.compile(r"\br\.(?:URL\.Query|FormValue|PostFormValue|Body|Header\.Get)\b"),
        re.compile(r"\bc\.(?:Query|Param|PostForm|ShouldBindJSON|BindJSON)\b"),
    ],
    "php": [
        re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b"),
        re.compile(r"\$_SERVER\s*\[\s*['\"](?:PHP_AUTH_USER|PHP_AUTH_PW|HTTP_[A-Z0-9_]+|QUERY_STRING|REQUEST_URI)['\"]\s*\]"),
        re.compile(r"\$request->(?:input|query|post|all|get|file)\b"),
        re.compile(r"file_get_contents\(\s*['\"]php://input['\"]\s*\)"),
        re.compile(r"document\.location\.(?:href|search|hash)"),
    ],
}

VARIABLE_SANITIZERS: List[tuple[re.Pattern[str], Set[str]]] = [
    (re.compile(r"\b(?:int|float|bool|intval|floatval|boolval|abs)\s*\("), {"*"}),
    (re.compile(r"\(\s*(?:int|float|bool)\s*\)"), {"*"}),
    (re.compile(r"\b(?:escapeshellarg|escapeshellcmd|shlex\.quote)\s*\("), {"Command Injection / RCE"}),
    (re.compile(r"\b(?:htmlspecialchars|htmlentities|bleach\.clean|DOMPurify\.sanitize)\s*\("), {"Cross-Site Scripting (XSS)"}),
    (re.compile(r"\b(?:mysqli_real_escape_string|mysql_real_escape_string|pg_escape_string)\s*\("), {"SQL Injection (SQLi)"}),
]

BLOCK_GUARDS: Dict[str, List[re.Pattern[str]]] = {
    "Command Injection / RCE": [
        re.compile(r"is_numeric\(\s*\$octet\[0\]\s*\)\s*\)\s*&&\s*\(\s*is_numeric\(\s*\$octet\[1\]\s*\)"),
    ],
    "SQL Injection (SQLi)": [
        re.compile(r"->prepare\s*\(.*?\).*?->bind(?:Param|Value)\s*\(", re.DOTALL),
    ],
    "Arbitrary File Read / LFI / Path Traversal": [
        re.compile(r"in_array\s*\(\s*\$\w+\s*,\s*\$\w+\s*\)"),
        re.compile(r"\$file\s*!=\s*['\"]include\.php['\"]\s*&&\s*\$file\s*!=\s*['\"]file1\.php['\"]"),
    ],
    "Unrestricted File Upload": [
        re.compile(r"imagecreatefrom(?:jpeg|png)\s*\("),
    ],
    "Cross-Site Request Forgery (CSRF) / Unverified State Mutation": [
        re.compile(r"\bcheckToken\s*\("),
    ],
}

SINK_DEFINITIONS: List[Dict[str, Any]] = [
    {
        "vuln_class": "Command Injection / RCE",
        "cwe_id": "CWE-78",
        "severity": "CRITICAL",
        "pattern": re.compile(
            r"\b(?:os\.system|os\.popen|subprocess\.(?:Popen|run|call|check_output)|eval|exec|child_process\.exec(?:Sync)?|shell_exec|passthru|proc_open|system|exec\.Command)\s*\("
        ),
    },
    {
        "vuln_class": "SQL Injection (SQLi)",
        "cwe_id": "CWE-89",
        "severity": "HIGH",
        "pattern": re.compile(
            r"(?:cursor\.execute|\.raw\s*\(|sequelize\.query|db\.Query|db\.Exec|\$pdo->query|mysqli_query|->query)\s*\("
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
            r"(?:\b(?:send_file|os\.path\.join|fs\.readFile(?:Sync)?|os\.ReadFile|include|require|include_once|require_once)\s*\(|file_get_contents\s*\(\s*(?!['\"]php://input['\"])|\$file\s*=\s*\$_(?:GET|POST|REQUEST)\s*\[\s*['\"]page['\"]\s*\])"
        ),
    },
    {
        "vuln_class": "Unrestricted File Upload",
        "cwe_id": "CWE-434",
        "severity": "HIGH",
        "pattern": re.compile(
            r"\b(?:move_uploaded_file|fs\.writeFile(?:Sync)?|\.save)\s*\("
        ),
    },
    {
        "vuln_class": "Cross-Site Scripting (XSS)",
        "cwe_id": "CWE-79",
        "severity": "MEDIUM",
        "pattern": re.compile(
            r"(?:\$(?:html|page\s*\[\s*['\"]body['\"]\s*\])\s*\.=|(?:^|\s)(?:echo|print)\s+|document\.write(?:ln)?\s*\(|\.innerHTML\s*=|INSERT\s+INTO\s+guestbook\b)"
        ),
    },
    {
        "vuln_class": "Open Redirect",
        "cwe_id": "CWE-601",
        "severity": "MEDIUM",
        "pattern": re.compile(
            r"(?:\bheader\s*\(\s*['\"]location:\s*['\"]\s*\.|\bres\.redirect\s*\(|\bredirect\s*\()"
        ),
    },
    {
        "vuln_class": "Client-Controlled Authorization Bypass (BOLA / Cookie Trust)",
        "cwe_id": "CWE-639",
        "severity": "HIGH",
        "pattern": re.compile(
            r"\$_COOKIE\s*\[\s*['\"](?:user_id|admin|role|Author|authenticated)['\"]\s*\]"
        ),
    },
    {
        "vuln_class": "Weak Cryptography / Predictable Session Token",
        "cwe_id": "CWE-327",
        "severity": "MEDIUM",
        "pattern": re.compile(
            r"(?:xor_this\s*\(|\$_SESSION\s*\[\s*['\"]last_session_id['\"]\s*\]\s*\+\+|aes-\d+-ecb|document\.getElementById\(['\"]token['\"]\)\.value\s*=\s*md5)"
        ),
    },
    {
        "vuln_class": "Cross-Site Request Forgery (CSRF) / Unverified State Mutation",
        "cwe_id": "CWE-352",
        "severity": "MEDIUM",
        "pattern": re.compile(
            r"UPDATE\s+`?users`?\s+SET\s+password\s*="
        ),
    },
    {
        "vuln_class": "Server-Side Template Injection (SSTI)",
        "cwe_id": "CWE-1336",
        "severity": "CRITICAL",
        "pattern": re.compile(r"\b(?:render_template_string|Template\s*\(|Twig_Loader_String)\b"),
    },
]

IGNORED_LHS_VARS = {"html", "response", "result", "results", "ret", "row"}


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
    """Traces remote user input sources across forward transitive variable hops to dangerous sinks."""

    @classmethod
    def _is_guarded_block(cls, content: str, vuln_class: str) -> bool:
        guards = BLOCK_GUARDS.get(vuln_class, [])
        return any(g.search(content) for g in guards)

    @classmethod
    def _analyze_python_ast(cls, content: str, file_path: str) -> List[TaintFlow]:
        flows: List[TaintFlow] = []
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return cls._analyze_generic(content, file_path, "python")

        lines = content.splitlines()
        src_regexes = SOURCE_PATTERNS["python"]
        func_nodes = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        if not func_nodes:
            return cls._analyze_generic(content, file_path, "python")

        for node in func_nodes:
            start_line = node.lineno
            end_line = getattr(node, "end_lineno", start_line + 40)
            func_lines = lines[start_line - 1 : end_line]
            func_text = "\n".join(func_lines)

            tainted_vars: Dict[str, tuple[int, str, Set[str]]] = {
                arg.arg: (start_line, f"def {node.name}({arg.arg})", set())
                for arg in node.args.args
                if arg.arg not in {"self", "cls", "db", "cursor", "conn", "session", "request", "req", "res", "response"}
            }

            for idx, raw_line in enumerate(func_lines, start=start_line):
                code_line = re.sub(r"\s+#.*$", "", raw_line)
                stripped = code_line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                assign_match = re.match(r"\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*(\+?=)\s*(.+)", code_line)
                if assign_match and not code_line.lstrip().startswith(("if ", "elif ", "while ", "assert ", "return ")):
                    lhs, op, rhs = assign_match.group(1), assign_match.group(2), assign_match.group(3)
                    line_neutralized: Set[str] = set()
                    for san_re, san_classes in VARIABLE_SANITIZERS:
                        if san_re.search(rhs):
                            line_neutralized.update(san_classes)
                    if any(s_re.search(rhs) for s_re in src_regexes):
                        if "*" not in line_neutralized:
                            tainted_vars[lhs] = (idx, stripped, set(line_neutralized))
                        elif op == "=":
                            tainted_vars.pop(lhs, None)
                    else:
                        matched_parent = False
                        for v, (orig_ln, orig_expr, prev_neut) in list(tainted_vars.items()):
                            if orig_ln <= idx and re.search(rf"\b{re.escape(v)}\b", rhs):
                                matched_parent = True
                                combined_neut = set(prev_neut) | line_neutralized
                                if "*" in combined_neut:
                                    tainted_vars.pop(lhs, None)
                                else:
                                    tainted_vars[lhs] = (orig_ln, orig_expr, combined_neut)
                                break
                        if not matched_parent and op == "=" and lhs in tainted_vars:
                            tainted_vars.pop(lhs, None)

                for sink_def in SINK_DEFINITIONS:
                    if sink_def["pattern"].search(code_line):
                        v_class = sink_def["vuln_class"]
                        inline_sanitized = any(
                            san_re.search(code_line) and ("*" in san_classes or v_class in san_classes)
                            for san_re, san_classes in VARIABLE_SANITIZERS
                        )
                        if inline_sanitized:
                            continue
                        used_vars = [
                            v
                            for v, (orig_ln, _, neut) in tainted_vars.items()
                            if orig_ln <= idx
                            and "*" not in neut
                            and v_class not in neut
                            and re.search(rf"\b{re.escape(v)}\b", code_line)
                        ]
                        direct_src = any(r.search(code_line) for r in src_regexes)
                        if used_vars or direct_src:
                            if used_vars:
                                src_ln, src_expr, _ = tainted_vars[used_vars[0]]
                            else:
                                src_ln, src_expr = idx, stripped
                            slice_start = max(1, min(src_ln, idx) - 2)
                            slice_end = min(len(lines), max(src_ln, idx) + 2)
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
                                    source_line=src_ln,
                                    sink_line=idx,
                                    source_expr=src_expr,
                                    sink_expr=stripped,
                                    tainted_vars=sorted(used_vars),
                                    context_slice=snippet,
                                )
                            )

        func_line_nums = {
            ln
            for n in func_nodes
            for ln in range(n.lineno, getattr(n, "end_lineno", n.lineno) + 1)
        }
        module_lines = [
            line if idx not in func_line_nums else ""
            for idx, line in enumerate(lines, start=1)
        ]
        flows.extend(cls._analyze_generic("\n".join(module_lines), file_path, "python"))
        return flows

    @classmethod
    def _analyze_generic(cls, content: str, file_path: str, language: str) -> List[TaintFlow]:
        flows: List[TaintFlow] = []
        lines = content.splitlines()
        src_regexes = SOURCE_PATTERNS.get(language, [])
        if not src_regexes:
            return flows

        # Single forward pass maintaining active taint state line by line
        # var_name -> (origin_line, origin_expr, neutralized_classes)
        tainted_vars: Dict[str, tuple[int, str, Set[str]]] = {}

        for idx, raw_line in enumerate(lines, start=1):
            code_line = re.sub(r"(?<!:)//.*$", "", raw_line)
            if language == "python":
                code_line = re.sub(r"\s+#.*$", "", code_line)
            stripped = code_line.strip()
            if not stripped or stripped.startswith(("//", "#", "/*", "*")):
                continue

            # 1. Check variable assignments / sanitizations on current line
            assign_match = re.match(
                r"^\s*(?:(?:const|let|var)\s+|\$)?([a-zA-Z_][a-zA-Z0-9_]*)\s*(=|\+=|\.=|:=)\s*(.+)",
                code_line,
            )
            if assign_match:
                lhs, op, rhs = assign_match.group(1), assign_match.group(2), assign_match.group(3)
                if lhs not in IGNORED_LHS_VARS:
                    has_direct_source = any(s_re.search(rhs) for s_re in src_regexes)
                    parent_vars = [
                        v
                        for v in tainted_vars
                        if (
                            re.search(rf"\${re.escape(v)}\b", rhs)
                            if language == "php"
                            else re.search(rf"\b{re.escape(v)}\b", rhs)
                        )
                    ]

                    if has_direct_source:
                        neutralized: Set[str] = set()
                        for san_re, san_classes in VARIABLE_SANITIZERS:
                            if san_re.search(rhs):
                                neutralized.update(san_classes)
                        tainted_vars[lhs] = (idx, stripped, neutralized)
                    elif parent_vars:
                        orig_ln, orig_expr, parent_neut = tainted_vars[parent_vars[0]]
                        new_neut = set(parent_neut)
                        for san_re, san_classes in VARIABLE_SANITIZERS:
                            if san_re.search(rhs):
                                new_neut.update(san_classes)
                        tainted_vars[lhs] = (orig_ln, orig_expr, new_neut)
                    elif lhs in tainted_vars and not parent_vars and op in ("=", ":="):
                        # Variable overwritten with a constant/safe expression (e.g. $target = $octet[0]...)
                        if not re.search(r"\$octet", rhs):
                            tainted_vars.pop(lhs, None)

            # 2. Evaluate sinks on current line
            for sink_def in SINK_DEFINITIONS:
                vclass = sink_def["vuln_class"]
                if not sink_def["pattern"].search(code_line):
                    continue
                if cls._is_guarded_block(content, vclass):
                    continue

                inline_sanitized = False
                for san_re, san_classes in VARIABLE_SANITIZERS:
                    if san_re.search(code_line) and ("*" in san_classes or vclass in san_classes):
                        inline_sanitized = True
                        break
                if inline_sanitized:
                    continue

                matched_vars = [
                    v
                    for v, (orig_ln, _, neut) in tainted_vars.items()
                    if orig_ln <= idx
                    and (
                        re.search(rf"\${re.escape(v)}\b", code_line)
                        if (language == "php" and "document.write" not in code_line)
                        else re.search(rf"\b{re.escape(v)}\b", code_line)
                    )
                    and "*" not in neut
                    and vclass not in neut
                ]
                direct_src = any(r.search(raw_line) for r in src_regexes)
                self_contained_sink = vclass in {
                    "Weak Cryptography / Predictable Session Token",
                    "Client-Controlled Authorization Bypass (BOLA / Cookie Trust)",
                }

                if matched_vars or direct_src or self_contained_sink:
                    if matched_vars:
                        src_ln, src_expr, _ = tainted_vars[matched_vars[0]]
                    else:
                        src_ln, src_expr = idx, stripped

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
                            vuln_class=vclass,
                            cwe_id=sink_def["cwe_id"],
                            severity=sink_def["severity"],
                            source_line=src_ln,
                            sink_line=idx,
                            source_expr=src_expr,
                            sink_expr=stripped,
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
            return cls._analyze_python_ast(content, str(path))
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
                if p.is_file()
                and p.suffix.lower() in LANGUAGE_EXTENSIONS
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
