import json
from pathlib import Path

import pytest

from huntbrief.agent import run_hunt
from huntbrief.data import generate
from huntbrief.extract import extract_iocs, extract_ttps
from huntbrief.llm import Scripted
from huntbrief.report import ioc_baseline_hosts, score
from huntbrief.tools import HuntTools

ROOT = Path(__file__).resolve().parent.parent
REPORT = (ROOT / "reports" / "glass_heron.md").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def world():
    events, truth = generate(seed=7)
    return events, truth, extract_iocs(REPORT)


def act(action, args):
    return f"Thought: x\nAction: {action}\nInput:\n```\n{json.dumps(args)}\n```"


def test_ground_truth_shape(world):
    events, truth, _ = world
    assert truth["hosts"] == sorted([truth["patient_zero"], "SRV-FILE01"])
    assert len(truth["malicious_event_ids"]) == 14


def test_ioc_sweep_alone_misses_the_file_server(world):
    events, truth, iocs = world
    assert ioc_baseline_hosts(events, iocs) == {truth["patient_zero"]}


def test_demo_script_finds_everything(world):
    events, truth, iocs = world
    llm = Scripted.from_file(ROOT / "examples" / "demo_script.json")
    ext = extract_ttps(llm, REPORT)
    tools = HuntTools(events, iocs)
    res = run_hunt(llm, tools, ext["accepted"], n_hosts=33)
    s = score(res.findings, truth, {e["id"]: e for e in events})
    assert res.stop_reason == "finished"
    assert s["host_recall"] == 1.0 and s["host_precision"] == 1.0
    assert s["technique_recall"] == 1.0 and s["evidence_precision"] == 1.0


def test_finding_must_cite_real_events_on_that_host(world):
    events, truth, iocs = world
    t = HuntTools(events, iocs)
    p0 = truth["patient_zero"]
    other = next(e["id"] for e in events if e["Computer"] != p0)
    assert "REFUSED" in t.record_finding(p0, "T1059.001", ["e99999"])
    assert "REFUSED" in t.record_finding(p0, "T1059.001", [other])
    assert "REFUSED" in t.record_finding(p0, "T9999", [truth["malicious_event_ids"][0]])
    assert "REFUSED" in t.record_finding(p0, "T1059.001", [])
    assert t.findings == []


def test_tools_never_reveal_ground_truth(world):
    events, _, iocs = world
    out = HuntTools(events, iocs).search_logs("ProgramData", field="CommandLine", limit=15)
    assert "_technique" not in out and "<untrusted_log>" in out


def test_disallowed_tool_hits_strike_limit(world):
    events, _, iocs = world
    llm = Scripted([act("run_shell", {"cmd": "whoami"})] * 5)
    res = run_hunt(llm, HuntTools(events, iocs), [], n_hosts=33, max_steps=10)
    assert res.stop_reason == "too_many_strikes" and len(res.steps) == 3


def test_planted_injection_exists(world):
    events, _, _ = world
    assert any("NOTE TO AI THREAT HUNTER" in e.get("CommandLine", "") for e in events)


def test_step_budget(world):
    events, _, iocs = world
    llm = Scripted([act("ioc_sweep", {})] * 10)
    res = run_hunt(llm, HuntTools(events, iocs), [], n_hosts=33, max_steps=4)
    assert res.stop_reason == "step_budget_exhausted" and len(res.steps) == 4
