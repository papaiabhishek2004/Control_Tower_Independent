"""Load Runtime Intelligence render functions without executing page top-level code."""

from __future__ import annotations

import ast
from pathlib import Path
from types import ModuleType


def load_runtime_intelligence_ui() -> ModuleType:
    page_path = Path(__file__).resolve().parents[1] / "pages1" / "05_Runtime_Intelligence.py"
    source = page_path.read_text(encoding="utf-8-sig")
    tree = ast.parse(source, filename=str(page_path))
    kept = []
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.ClassDef)):
            kept.append(node)
        elif isinstance(node, ast.Assign):
            names = {target.id for target in node.targets if isinstance(target, ast.Name)}
            if names & {"_streamlit_dataframe", "_streamlit_info"}:
                kept.append(node)
    module_ast = ast.Module(body=kept, type_ignores=[])
    ast.fix_missing_locations(module_ast)
    module = ModuleType("aegis_runtime_intelligence_ui")
    module.__dict__["__file__"] = str(page_path)
    exec(compile(module_ast, str(page_path), "exec"), module.__dict__)
    return module
