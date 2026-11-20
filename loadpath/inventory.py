"""Conservative, source-order AST inventory. Source files are never imported."""

from __future__ import annotations

import ast
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .rules import classify


@dataclass
class Finding:
    rule: str
    severity: str
    file: str
    line: int
    col: int
    loader: str
    expression: str
    resolved_artifact: str | None
    args: dict
    message: str
    context: list[str] = field(default_factory=list)
    coverage: str = "unresolved"
    receipts: list[dict] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


@dataclass
class Value:
    literal: object = None
    path: str | None = None
    context: tuple[str, ...] = ()


class Inventory(ast.NodeVisitor):
    def __init__(self, filename):
        self.filename = str(filename)
        self.aliases = {}
        self.values = {}
        self.findings = []

    def name(self, node):
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return f"{self.name(node.value)}.{node.attr}"
        return ""

    def value(self, node):
        if isinstance(node, ast.Constant):
            return Value(node.value, node.value if isinstance(node.value, str) else None)
        if isinstance(node, ast.Name):
            return self.values.get(node.id, Value())
        if isinstance(node, (ast.List, ast.Tuple)):
            vals = [self.value(n).literal for n in node.elts]
            return Value(vals)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Div, ast.Add)):
            left, right = self.value(node.left), self.value(node.right)
            if left.path is not None and right.path is not None:
                path = str(Path(left.path) / right.path) if isinstance(node.op, ast.Div) else left.path + right.path
                return Value(path, path, left.context + right.context)
        if isinstance(node, ast.Call):
            name = self.name(node.func)
            vals = [self.value(n) for n in node.args]
            if name in {"pathlib.Path", "os.path.join"} and vals and all(v.path is not None for v in vals):
                path = str(Path(vals[0].path).joinpath(*(v.path for v in vals[1:])))
                return Value(path, path)
            if name in {"open", "io.open"} and vals:
                return vals[0]
            if name in {"huggingface_hub.hf_hub_download", "huggingface_hub.snapshot_download"}:
                return Value(context=(f"download: {ast.unparse(node)}",))
            if name == "zipfile.ZipFile" and vals:
                return Value(path=vals[0].path, context=(f"archive: {vals[0].path or ast.unparse(node.args[0])}",))
            if isinstance(node.func, ast.Attribute) and node.func.attr in {"read", "open"}:
                base = self.value(node.func.value)
                if base.context and base.context[0].startswith("archive:"):
                    return Value(path=base.path, context=base.context + (f"member: {vals[0].path if vals else '?'}",))
                if node.func.attr == "open":
                    return base
        return Value()

    def visit_Import(self, node):
        for alias in node.names:
            self.aliases[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]

    def visit_ImportFrom(self, node):
        for alias in node.names:
            if alias.name != "*":
                self.aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    def visit_Assign(self, node):
        self.visit(node.value)
        value = self.value(node.value)
        for target in node.targets:
            for name in ast.walk(target):
                if isinstance(name, ast.Name):
                    self.values[name.id] = value if isinstance(target, ast.Name) else Value()
                    self.aliases.pop(name.id, None)

    def visit_AnnAssign(self, node):
        if node.value:
            replacement = ast.Assign(targets=[node.target], value=node.value)
            self.visit_Assign(replacement)

    def visit_AugAssign(self, node):
        self.generic_visit(node)
        if isinstance(node.target, ast.Name):
            self.values.pop(node.target.id, None)

    def visit_With(self, node):
        for item in node.items:
            self.visit(item.context_expr)
            if isinstance(item.optional_vars, ast.Name):
                self.values[item.optional_vars.id] = self.value(item.context_expr)
        for statement in node.body:
            self.visit(statement)

    def visit_FunctionDef(self, node):
        old_values, old_aliases = self.values.copy(), self.aliases.copy()
        local_names = {n.id for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
        local_names |= {a.arg for a in ast.walk(node.args) if isinstance(a, ast.arg)}
        for name in local_names:
            self.values.pop(name, None)
            self.aliases.pop(name, None)
        for statement in node.body:
            self.visit(statement)
        self.values, self.aliases = old_values, old_aliases

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        values, aliases = self.values.copy(), self.aliases.copy()
        for statement in node.body:
            self.visit(statement)
        self.values, self.aliases = values, aliases

    def uncertain_block(self, node):
        changed = {n.id for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
        for name in changed:
            self.values.pop(name, None)
            self.aliases.pop(name, None)
        self.generic_visit(node)
        for name in changed:
            self.values.pop(name, None)
            self.aliases.pop(name, None)

    visit_For = uncertain_block
    visit_AsyncFor = uncertain_block
    visit_While = uncertain_block
    visit_Try = uncertain_block

    def visit_If(self, node):
        self.visit(node.test)
        before_values, before_aliases = self.values.copy(), self.aliases.copy()
        for statement in node.body:
            self.visit(statement)
        body_values, body_aliases = self.values.copy(), self.aliases.copy()
        self.values, self.aliases = before_values.copy(), before_aliases.copy()
        for statement in node.orelse:
            self.visit(statement)
        self.values = {k: v for k, v in self.values.items() if body_values.get(k) == v}
        self.aliases = {k: v for k, v in self.aliases.items() if body_aliases.get(k) == v}

    def visit_Call(self, node):
        loader = self.name(node.func)
        keywords = {k.arg: self.value(k.value).literal if self.value(k.value).literal is not None else ast.unparse(k.value) for k in node.keywords if k.arg}
        keyword_nodes = {k.arg: k.value for k in node.keywords}
        if any(k.arg is None for k in node.keywords):
            keywords["**kwargs"] = "unresolved"
        if loader == "numpy.load" and len(node.args) > 2:
            keywords["allow_pickle"] = self.value(node.args[2]).literal
        if loader == "skops.io.load" and len(node.args) > 1:
            keywords["trusted"] = self.value(node.args[1]).literal
        if loader in {"keras.models.load_model", "tensorflow.keras.models.load_model", "keras.saving.load_model"} and len(node.args) > 3:
            keywords["safe_mode"] = self.value(node.args[3]).literal
        artifact_node = (
            node.args[0]
            if node.args
            else next(
                (
                    keyword_nodes[k]
                    for k in ("file", "filename", "filepath", "f", "file_name", "pretrained_model_name_or_path", "path", "repo_id")
                    if k in keyword_nodes
                ),
                None,
            )
        )
        val = self.value(artifact_node)
        result = classify(loader, keywords, val.path)
        if result:
            rule, severity, message = result
            path = val.path
            if loader.endswith(".loads"):
                path = val.path if val.context and val.context[0].startswith("archive:") else None
            if rule == "LP011":
                path = None
            self.findings.append(
                Finding(
                    rule,
                    severity,
                    self.filename,
                    node.lineno,
                    node.col_offset + 1,
                    loader,
                    ast.unparse(artifact_node) if artifact_node else "<missing>",
                    path,
                    keywords,
                    message,
                    list(val.context),
                )
            )
        self.generic_visit(node)


def scan(target):
    target = Path(target)
    files = [target] if target.is_file() else sorted(p for p in target.rglob("*.py") if not any(part in {".venv", ".git", "__pycache__"} for part in p.parts))
    if not target.exists():
        raise ValueError(f"Target does not exist: {target}")
    findings, errors = [], []
    for path in files:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            visitor = Inventory(path)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except (SyntaxError, UnicodeError, OSError) as exc:
            errors.append(f"{path}: {exc}")
    return sorted(findings, key=lambda f: (f.file, f.line, f.col)), errors
