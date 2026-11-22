from pathlib import Path

from huntbrief.extract import extract_iocs, extract_ttps
from huntbrief.llm import Scripted

REPORT = (Path(__file__).resolve().parent.parent / "reports" / "glass_heron.md").read_text(encoding="utf-8")


def test_iocs_are_refanged_and_file_names_ignored():
    iocs = extract_iocs(REPORT)
    assert iocs["domains"] == ["cdn-invoice-sync.com", "update-msofficecdn.net"]
    assert iocs["ips"] == ["192.0.2.200", "203.0.113.47"]
    assert len(iocs["sha256"]) == 2
    assert not any(d.endswith((".dll", ".exe", ".docm")) for d in iocs["domains"])


def reply(items):
    import json
    return "```json\n" + json.dumps(items) + "\n```"


def test_grounded_known_technique_is_accepted():
    r = extract_ttps(Scripted([reply([{"technique_id": "T1003.001",
                                       "quote": "The actor dumps LSASS memory using the `MiniDump` export"}])]), REPORT)
    assert [a["technique_id"] for a in r["accepted"]] == ["T1003.001"]
    assert r["accepted"][0]["kill_chain"] == "Actions on Objectives"


def test_hallucinated_technique_is_rejected():
    r = extract_ttps(Scripted([reply([{"technique_id": "T1059.999", "quote": "runs a download cradle that pulls"}])]), REPORT)
    assert not r["accepted"] and "catalogue" in r["rejected"][0]["reason"]


def test_ungrounded_quote_is_rejected():
    r = extract_ttps(Scripted([reply([{"technique_id": "T1486", "quote": "The actor encrypts file servers for ransom."}])]), REPORT)
    assert not r["accepted"] and "ungrounded" in r["rejected"][0]["reason"]


def test_unparseable_reply_is_rejected_not_crashing():
    r = extract_ttps(Scripted(["sure! here are some techniques"]), REPORT)
    assert r["accepted"] == [] and "unparseable" in r["rejected"][0]["reason"]
