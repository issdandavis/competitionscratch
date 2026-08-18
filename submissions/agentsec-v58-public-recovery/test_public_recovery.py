from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
ATTACK = HERE / "attack.py"
NOTEBOOK = HERE / "agentsec-v58-public-recovery.ipynb"
EXPECTED_SHA256 = "614176A339E71B80A71C9CF5035C6BAB486B5C5A82C4F14D9E8A1E1417424F9F"


def _load_attack():
    spec = importlib.util.spec_from_file_location("agentsec_v58_attack", ATTACK)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _embedded_attack() -> str:
    notebook = json.loads(NOTEBOOK.read_text(encoding="utf-8"))
    source = "\n".join(
        "".join(cell.get("source", []))
        for cell in notebook["cells"]
        if cell.get("cell_type") == "code"
    )
    tree = ast.parse(source)
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        names = {target.id for target in node.targets if isinstance(target, ast.Name)}
        if "attack_code" in names:
            value = ast.literal_eval(node.value)
            assert isinstance(value, str)
            return value
    raise AssertionError("notebook has no embedded attack_code")


def test_exact_public_parent_bytes() -> None:
    assert hashlib.sha256(ATTACK.read_bytes()).hexdigest().upper() == EXPECTED_SHA256
    assert _embedded_attack().encode("utf-8") == ATTACK.read_bytes()


def test_static_candidate_contract() -> None:
    attack = _load_attack()
    algorithm = attack.AttackAlgorithm({"n_candidates": 25})
    candidates = algorithm.run(
        None,
        attack.AttackRunConfig(time_budget_s=1.0, max_steps=100, max_tool_hops=8),
    )

    assert len(candidates) == 25
    messages = [candidate.user_messages for candidate in candidates]
    assert len(set(messages)) == 25
    assert all(len(chain) == 1 for chain in messages)
    assert all("SECRET_MARKER" in chain[0] for chain in messages)
    assert all("http.post" in chain[0] for chain in messages)
    assert attack.BURST_K == 1
    assert attack.SLOW_MULTIPOST_N == 1
    assert attack.REPLAY_SAFE_FRAC == 0.98
