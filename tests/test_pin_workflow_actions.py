from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]


def load_pinner() -> ModuleType:
    path = ROOT / "scripts/pin_workflow_actions.py"
    spec = importlib.util.spec_from_file_location("pin_workflow_actions", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_pins_tags_and_preserves_existing_comments() -> None:
    module = load_pinner()
    calls: list[tuple[str, str]] = []

    def resolver(repository: str, ref: str) -> str:
        calls.append((repository, ref))
        return "a" * 40

    source = """steps:
  - uses: actions/checkout@v4
  - uses: owner/action/subpath@main # keep-ref
  - uses: actions/setup-node@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  - uses: ./local-action
"""
    rewritten = module.rewrite(source, resolver)
    assert "actions/checkout@" + "a" * 40 + " # v4" in rewritten
    assert "owner/action/subpath@" + "a" * 40 + " # keep-ref" in rewritten
    assert "actions/setup-node@" + "b" * 40 in rewritten
    assert "uses: ./local-action" in rewritten
    assert calls == [("actions/checkout", "v4"), ("owner/action", "main")]
