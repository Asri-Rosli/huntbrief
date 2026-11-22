"""Stage 1: turn a threat-intelligence report into hunt hypotheses.

IOCs (domains, IPs, hashes) are pulled out with regular expressions, because
exact strings are where an LLM adds nothing and can only add errors.

Techniques (TTPs) need reading comprehension, so the LLM maps the report to
MITRE ATT&CK. Its answer is treated as untrusted:
  * the technique ID must exist in our ATT&CK catalogue, and
  * it must quote the sentence of the report that supports it, and that quote
    must really appear in the report (grounding check).
Anything that fails is rejected and listed, never silently used.
"""
from __future__ import annotations

import json
import re

from . import attack
from .llm import LLM

_FILE_EXT = {"dll", "exe", "docm", "doc", "ps1", "md", "7z", "zip", "conf", "dmp", "bat", "txt", "msi"}
_RE_IP = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")
_RE_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
_RE_SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.I)
_RE_MD5 = re.compile(r"\b[a-f0-9]{32}\b", re.I)
MIN_QUOTE_CHARS = 12


def refang(text: str) -> str:
    return (text.replace("[.]", ".").replace("(.)", ".").replace("hxxp", "http")
                .replace("[:]", ":"))


def extract_iocs(report: str) -> dict[str, list[str]]:
    text = refang(report)
    ips = sorted(set(_RE_IP.findall(text)))
    hashes = sorted(set(h.lower() for h in _RE_SHA256.findall(text)))
    md5 = sorted(set(h.lower() for h in _RE_MD5.findall(text)) - {h[:32] for h in hashes})
    domains = set()
    for d in _RE_DOMAIN.findall(text):
        d = d.lower()
        if d.rsplit(".", 1)[-1] in _FILE_EXT or _RE_IP.fullmatch(d):
            continue
        domains.add(d)
    return {"domains": sorted(domains), "ips": ips, "sha256": hashes, "md5": md5}


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", refang(s).replace("`", "").replace("*", "")).strip().lower()


EXTRACT_PROMPT = """You are a cyber threat intelligence analyst. Map the threat report below to
MITRE ATT&CK techniques that a defender could hunt for in endpoint logs.

Return ONLY a JSON list inside a ``` block. Each item:
  {{"technique_id": "T1234.001", "quote": "<exact sentence or phrase copied from the report>"}}
The quote must be copied word for word from the report; it is checked.

Report:
<report>
{report}
</report>"""


def parse_json_block(reply: str):
    m = re.search(r"```(?:json)?\s*(.*?)```", reply, re.S)
    return json.loads(m.group(1) if m else reply)


def extract_ttps(llm: LLM, report: str) -> dict:
    reply = llm.chat([{"role": "user", "content": EXTRACT_PROMPT.format(report=report)}])
    accepted, rejected = [], []
    try:
        items = parse_json_block(reply)
        if not isinstance(items, list):
            raise ValueError("expected a JSON list")
    except (ValueError, json.JSONDecodeError) as e:
        return {"accepted": [], "rejected": [{"item": reply[:200], "reason": f"unparseable: {e}"}], "raw": reply}
    norm_report = _norm(report)
    seen = set()
    for it in items:
        tid = str(it.get("technique_id", "")).strip() if isinstance(it, dict) else ""
        quote = str(it.get("quote", "")) if isinstance(it, dict) else ""
        if not attack.is_known(tid):
            rejected.append({"item": it, "reason": "technique ID not in ATT&CK catalogue (possible hallucination)"})
        elif len(quote.strip()) < MIN_QUOTE_CHARS or _norm(quote) not in norm_report:
            rejected.append({"item": it, "reason": "quote not found in report (ungrounded)"})
        elif tid in seen:
            continue
        else:
            seen.add(tid)
            accepted.append({"technique_id": tid, "name": attack.name(tid),
                             "kill_chain": attack.kill_chain_stage(tid), "quote": quote.strip()})
    return {"accepted": accepted, "rejected": rejected, "raw": reply}
