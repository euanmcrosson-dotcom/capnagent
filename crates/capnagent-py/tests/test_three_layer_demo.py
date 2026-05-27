"""Smoke test for the canonical Find -> Bind -> Guard demo.

Runs `examples/three-layer-demo/demo.py` end-to-end — capnagent (Bind) +
mcp-guardrails (Guard) against the REAL `mcp-recon/v0.1/caveats` artifact (Find)
— and asserts the two independent denial paths both fire. Skips if
mcp-guardrails isn't installed (it's a separate PyPI package; CI installs it).
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

import pytest

pytest.importorskip("mcp_guard", reason="three-layer demo needs mcp-guardrails")

DEMO = (
    pathlib.Path(__file__).resolve().parents[3]
    / "examples"
    / "three-layer-demo"
    / "demo.py"
)


def test_three_layer_demo_runs_and_both_gates_fire():
    assert DEMO.exists(), f"demo not found at {DEMO}"
    proc = subprocess.run(
        [sys.executable, str(DEMO)], capture_output=True, text=True, check=False
    )
    assert proc.returncode == 0, f"demo exited {proc.returncode}\nstderr:\n{proc.stderr}"
    out = proc.stdout
    # The whole point of the demo: the two layers catch failure modes the other
    # can't — one denial at each gate, two calls authorized end-to-end.
    assert "2 call(s) authorized end-to-end" in out, out
    assert "1 denied at the authority layer (capnagent)" in out, out
    assert "1 denied at the runtime-policy layer (mcp-guardrails)" in out, out
    # And it consumed the real mcp-recon artifact format (schema/plans), not a
    # hand-rolled shape — load_caveats would have sys.exit'd on a bad schema.
    assert "mcp-recon issuance plan(s)" in out, out
