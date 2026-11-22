"""Command line.

  python -m huntbrief iocs                                   # regex IOC extraction only
  python -m huntbrief baseline                               # plain IOC sweep, no agent
  python -m huntbrief hunt --backend ollama --model qwen2.5:7b
  python -m huntbrief hunt --backend scripted --script examples/demo_script.json
"""
from __future__ import annotations

import argparse
import json
import time
from dataclasses import asdict
from pathlib import Path

from .agent import run_hunt
from .data import HOSTS, ensure
from .extract import extract_iocs, extract_ttps
from .llm import make_llm
from .report import build_report, ioc_baseline_hosts, score
from .tools import HuntTools

ROOT = Path(__file__).resolve().parent.parent
REPORT = ROOT / "reports" / "glass_heron.md"
DATA_DIR = ROOT / "data"
RUNS_DIR = ROOT / "runs"


def cmd_iocs(args):
    print(json.dumps(extract_iocs(Path(args.report).read_text(encoding="utf-8")), indent=2))


def cmd_baseline(args):
    events, truth = ensure(DATA_DIR, args.seed)
    iocs = extract_iocs(Path(args.report).read_text(encoding="utf-8"))
    hosts = ioc_baseline_hosts(events, iocs)
    gt = set(truth["hosts"])
    print(f"IOC sweep flags {sorted(hosts)}; compromised hosts are {sorted(gt)} "
          f"-> host recall {len(hosts & gt) / len(gt):.2f}")


def cmd_hunt(args):
    events, truth = ensure(DATA_DIR, args.seed)
    report = Path(args.report).read_text(encoding="utf-8")
    llm = make_llm(args.backend, args.model, args.script)
    t0 = time.time()
    iocs = extract_iocs(report)
    extraction = extract_ttps(llm, report)
    print(f"Extraction: {len(extraction['accepted'])} techniques accepted, "
          f"{len(extraction['rejected'])} rejected")
    tools = HuntTools(events, iocs)
    res = run_hunt(llm, tools, extraction["accepted"], n_hosts=len(HOSTS), max_steps=args.max_steps)
    by_id = {e["id"]: e for e in events}
    s = score(res.findings, truth, by_id)
    run_dir = RUNS_DIR / f"{time.strftime('%Y%m%d-%H%M%S')}_{args.backend}_{(args.model or 'script').replace(':', '-')}"
    run_dir.mkdir(parents=True)
    (run_dir / "hunt_report.md").write_text(build_report(res.findings, by_id, res.summary, extraction), encoding="utf-8")
    (run_dir / "transcript.json").write_text(json.dumps(
        {"extraction": extraction, "steps": [asdict(x) for x in res.steps]}, indent=2), encoding="utf-8")
    (run_dir / "score.json").write_text(json.dumps(
        dict(stop_reason=res.stop_reason, steps=len(res.steps), seconds=round(time.time() - t0, 1), **s), indent=2),
        encoding="utf-8")
    print(f"Hunt {res.stop_reason} after {len(res.steps)} steps")
    print(json.dumps(s, indent=2))
    print(f"Report: {run_dir / 'hunt_report.md'}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="huntbrief", description="Intelligence-driven threat hunting agent")
    p.add_argument("--report", default=str(REPORT))
    p.add_argument("--seed", type=int, default=7, help="dataset seed (changes which host is patient zero)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("iocs").set_defaults(fn=cmd_iocs)
    sub.add_parser("baseline").set_defaults(fn=cmd_baseline)
    h = sub.add_parser("hunt")
    h.add_argument("--backend", choices=["ollama", "openai", "anthropic", "scripted"], default="ollama")
    h.add_argument("--model")
    h.add_argument("--script")
    h.add_argument("--max-steps", type=int, default=30)
    h.set_defaults(fn=cmd_hunt)
    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
