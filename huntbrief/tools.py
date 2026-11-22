"""Stage 2 tools. All are read-only: the agent can look at logs but cannot change
anything, contact any host, or run commands.

Findings must cite real event IDs on the named host, so every claim in the
final report can be traced back to log evidence.
"""
from __future__ import annotations

import json
from collections import Counter

from . import attack
from .data import public_view

MAX_RESULTS = 15
MAX_FIELD_CHARS = 260
MAX_FINDINGS = 60
SEARCH_FIELDS = ["CommandLine", "Image", "ParentImage", "User", "Computer", "QueryName",
                 "DestinationIp", "DestinationHostname", "*"]


def show(e: dict) -> str:
    v = {k: (x[:MAX_FIELD_CHARS] if isinstance(x, str) else x) for k, x in public_view(e).items() if x not in ("", None)}
    return "<untrusted_log>" + json.dumps(v) + "</untrusted_log>"


class HuntTools:
    def __init__(self, events: list[dict], iocs: dict[str, list[str]]):
        self.events = events
        self.by_id = {e["id"]: e for e in events}
        self.iocs = iocs
        self.findings: list[dict] = []
        self.finished = False
        self.summary = ""

    def _match(self, e, field, q):
        if field == "*":
            return any(q in str(v).lower() for k, v in e.items() if not k.startswith("_"))
        return q in str(e.get(field, "")).lower()

    def search_logs(self, query: str = "", field: str = "CommandLine", host: str | None = None,
                    event_id: int | None = None, limit: int = 10) -> str:
        if field not in SEARCH_FIELDS:
            return f"ERROR: field must be one of {SEARCH_FIELDS}"
        if not isinstance(query, str) or not query.strip():
            return "ERROR: query must be a non-empty string"
        q = query.lower()
        hits = [e for e in self.events if self._match(e, field, q)
                and (host is None or e["Computer"] == host)
                and (event_id is None or e["EventID"] == int(event_id))]
        limit = max(1, min(int(limit), MAX_RESULTS))
        out = [f"{len(hits)} events match {field} contains {query!r}"
               + (f" on {host}" if host else "") + f". Showing {min(limit, len(hits))}:"]
        return "\n".join(out + [show(e) for e in hits[:limit]])

    def count_by(self, field: str = "Computer", query: str = "", query_field: str = "CommandLine") -> str:
        """Stacking: count events per value, the classic way to spot rare outliers."""
        if field not in SEARCH_FIELDS[:-1] or query_field not in SEARCH_FIELDS:
            return f"ERROR: fields must be in {SEARCH_FIELDS[:-1]}"
        q = query.lower()
        c = Counter(str(e.get(field, "")) for e in self.events if not q or self._match(e, query_field, q))
        rows = c.most_common()
        lines = [f"{n:>6}  {v[:MAX_FIELD_CHARS]}" for v, n in (rows if len(rows) <= 20 else rows[:10])]
        if len(rows) > 20:
            lines.append("   ...")
            lines += [f"{n:>6}  {v[:MAX_FIELD_CHARS]}" for v, n in rows[-10:]]
        return f"{len(rows)} distinct {field} values (most common first, rarest last):\n" + "\n".join(lines)

    def ioc_sweep(self) -> str:
        """Search every event for the report's domains, IPs and hashes."""
        needles = [x.lower() for k in ("domains", "ips", "sha256", "md5") for x in self.iocs.get(k, [])]
        hits = [(n, e) for e in self.events for n in needles
                if any(n in str(v).lower() for k, v in e.items() if not k.startswith("_"))]
        if not hits:
            return "IOC sweep: no matches."
        lines = [f"IOC sweep: {len(hits)} matches on hosts {sorted({e['Computer'] for _, e in hits})}"]
        lines += [f"[{n}] " + show(e) for n, e in hits[:MAX_RESULTS]]
        return "\n".join(lines)

    def get_event(self, id: str = "") -> str:
        e = self.by_id.get(id)
        return show(e) if e else f"ERROR: no event {id!r}"

    def record_finding(self, host: str = "", technique_id: str = "", event_ids=None, note: str = "") -> str:
        event_ids = event_ids or []
        if len(self.findings) >= MAX_FINDINGS:
            return "REFUSED: finding limit reached."
        if not attack.is_known(technique_id):
            return f"REFUSED: {technique_id!r} is not in the ATT&CK catalogue."
        if not isinstance(event_ids, list) or not event_ids:
            return "REFUSED: cite at least one event ID as evidence."
        missing = [i for i in event_ids if i not in self.by_id]
        if missing:
            return f"REFUSED: event IDs do not exist: {missing}"
        wrong = [i for i in event_ids if self.by_id[i]["Computer"] != host]
        if wrong:
            return f"REFUSED: events {wrong} are not on host {host}."
        self.findings.append({"host": host, "technique_id": technique_id, "event_ids": event_ids,
                              "note": str(note)[:300]})
        return f"Recorded: {host} {technique_id} ({attack.name(technique_id)}) with {len(event_ids)} evidence event(s)."

    def finish(self, summary: str = "") -> str:
        self.finished = True
        self.summary = str(summary)[:1500]
        return "Hunt finished."


TOOL_SPECS = {
    "search_logs": 'search_logs {"query": str, "field": one of CommandLine|Image|ParentImage|User|Computer|'
                   'QueryName|DestinationIp|DestinationHostname|*, "host": optional, "event_id": optional 1|3|22, '
                   '"limit": optional} - substring search',
    "count_by": 'count_by {"field": str, "query": optional, "query_field": optional} - stack counts per value '
                'to find rare outliers',
    "ioc_sweep": "ioc_sweep {} - search all logs for the report's domains, IPs and hashes",
    "get_event": 'get_event {"id": "e01234"}',
    "record_finding": 'record_finding {"host": str, "technique_id": "T....", "event_ids": [ids], "note": str} '
                      '- record a confirmed malicious behaviour with log evidence',
    "finish": 'finish {"summary": str} - end the hunt',
}
