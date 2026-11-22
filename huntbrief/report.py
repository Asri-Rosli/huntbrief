"""Turn findings into a hunt report, and score them against ground truth."""
from __future__ import annotations

from . import attack


def build_report(findings: list[dict], events_by_id: dict, summary: str, extraction: dict) -> str:
    lines = ["# Hunt report: GLASS HERON", ""]
    hosts = sorted({f["host"] for f in findings})
    lines += [f"**Hosts with confirmed activity:** {', '.join(hosts) if hosts else 'none'}", ""]
    if summary:
        lines += ["## Analyst summary", "", summary, ""]
    stage_rank = {s: i for i, s in enumerate(attack.KILL_CHAIN)}
    for host in hosts:
        lines += [f"## {host}", "", "| Kill chain stage | ATT&CK | Evidence |", "|---|---|---|"]
        fs = sorted((f for f in findings if f["host"] == host),
                    key=lambda f: (stage_rank[attack.kill_chain_stage(f["technique_id"])],
                                   min(events_by_id[i]["UtcTime"] for i in f["event_ids"])))
        for f in fs:
            ev = events_by_id[f["event_ids"][0]]
            detail = ev.get("CommandLine") or ev.get("QueryName") or ev.get("DestinationIp", "")
            detail = str(detail).replace("|", "\\|")[:140]
            lines.append(f"| {attack.kill_chain_stage(f['technique_id'])} | {f['technique_id']} "
                         f"{attack.name(f['technique_id'])} | `{ev['UtcTime']}` {', '.join(f['event_ids'])}: `{detail}` |")
        lines.append("")
    rej = extraction.get("rejected", [])
    if rej:
        lines += ["## Rejected LLM extractions", ""]
        lines += [f"- `{r['item']}`: {r['reason']}" for r in rej]
    return "\n".join(lines) + "\n"


def ioc_baseline_hosts(events: list[dict], iocs: dict) -> set[str]:
    """What a plain IOC sweep finds, with no behaviour hunting."""
    needles = [x.lower() for k in ("domains", "ips", "sha256", "md5") for x in iocs.get(k, [])]
    return {e["Computer"] for e in events
            if any(n in str(v).lower() for k, v in e.items() if not k.startswith("_") for n in needles)}


def score(findings: list[dict], truth: dict, events_by_id: dict) -> dict:
    gt_hosts = set(truth["hosts"])
    found_hosts = {f["host"] for f in findings}
    gt_pairs = {(h, attack.canonical(t)) for h, ts in truth["techniques"].items() for t in ts}
    found_pairs = {(f["host"], attack.canonical(f["technique_id"])) for f in findings}
    cited = [i for f in findings for i in f["event_ids"]]
    mal = set(truth["malicious_event_ids"])
    return {
        "host_recall": round(len(found_hosts & gt_hosts) / len(gt_hosts), 3) if gt_hosts else 0.0,
        "host_precision": round(len(found_hosts & gt_hosts) / len(found_hosts), 3) if found_hosts else 0.0,
        "false_positive_hosts": sorted(found_hosts - gt_hosts),
        "technique_recall": round(len(found_pairs & gt_pairs) / len(gt_pairs), 3) if gt_pairs else 0.0,
        "techniques_found": len(found_pairs & gt_pairs),
        "techniques_total": len(gt_pairs),
        "evidence_precision": round(sum(i in mal for i in cited) / len(cited), 3) if cited else 0.0,
    }
