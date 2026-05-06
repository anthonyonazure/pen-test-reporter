"""End-to-end: parse + dedup + render PDF for a multi-scanner input."""

from __future__ import annotations

from pathlib import Path

import pytest

from pentest.graph import build_graph
from pentest.state import PState

REPO = Path(__file__).resolve().parents[1]


@pytest.mark.asyncio
async def test_full_run(tmp_path, monkeypatch):
    monkeypatch.setenv("PENTEST_OUT_DIR", str(tmp_path))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    g = build_graph().compile()
    initial: PState = {
        "run_id": "test-run",
        "inputs": [str(REPO / "samples" / "nuclei.jsonl"), str(REPO / "samples" / "nmap.xml")],
        "engagement_name": "Test Engagement",
        "target_org": "Example Corp",
        "events": [],
    }
    final = await g.ainvoke(initial)

    # Raw count from the two inputs:
    #   nuclei: 12 lines
    #   nmap: 4 risky/outdated services + 3 outdated products = 7 (counts vary by heuristic)
    assert len(final["findings_raw"]) >= 15

    # Dedup collapses
    grouped = final["findings_grouped"]
    assert len(grouped) < len(final["findings_raw"])
    # The xz-utils CRITICAL must survive
    assert any("xz-utils" in g["title"].lower() and g["severity"] == "critical" for g in grouped)

    # PDF + sidecar
    pdf = tmp_path / "test-run-pentest-report.pdf"
    sidecar = tmp_path / "test-run-pentest-report.sha256"
    assert pdf.exists() and pdf.read_bytes()[:4] == b"%PDF"
    assert sidecar.exists() and len(sidecar.read_text().split()[0]) == 64

    # Every group has a remediation
    rmap = final["remediations"]
    assert all(g["id"] in rmap for g in grouped)
    assert all(rmap[g["id"]] for g in grouped)
