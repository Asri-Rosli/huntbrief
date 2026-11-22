"""A small offline slice of MITRE ATT&CK, mapped to the Lockheed Martin Cyber Kill Chain.

Only techniques listed here are accepted from the LLM, so a hallucinated
technique ID (a common LLM failure) is rejected instead of reaching the report.
"""

# technique id -> (name, ATT&CK tactic)
TECHNIQUES = {
    "T1566.001": ("Phishing: Spearphishing Attachment", "initial-access"),
    "T1566.002": ("Phishing: Spearphishing Link", "initial-access"),
    "T1190": ("Exploit Public-Facing Application", "initial-access"),
    "T1078": ("Valid Accounts", "initial-access"),
    "T1204.002": ("User Execution: Malicious File", "execution"),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", "execution"),
    "T1059.003": ("Command and Scripting Interpreter: Windows Command Shell", "execution"),
    "T1047": ("Windows Management Instrumentation", "execution"),
    "T1053.005": ("Scheduled Task/Job: Scheduled Task", "persistence"),
    "T1547.001": ("Boot or Logon Autostart Execution: Registry Run Keys", "persistence"),
    "T1218.011": ("System Binary Proxy Execution: Rundll32", "defense-evasion"),
    "T1027": ("Obfuscated Files or Information", "defense-evasion"),
    "T1070.004": ("Indicator Removal: File Deletion", "defense-evasion"),
    "T1003.001": ("OS Credential Dumping: LSASS Memory", "credential-access"),
    "T1110": ("Brute Force", "credential-access"),
    "T1087.002": ("Account Discovery: Domain Account", "discovery"),
    "T1018": ("Remote System Discovery", "discovery"),
    "T1082": ("System Information Discovery", "discovery"),
    "T1046": ("Network Service Discovery", "discovery"),
    "T1021.001": ("Remote Services: Remote Desktop Protocol", "lateral-movement"),
    "T1021.002": ("Remote Services: SMB/Windows Admin Shares", "lateral-movement"),
    "T1560.001": ("Archive Collected Data: Archive via Utility", "collection"),
    "T1005": ("Data from Local System", "collection"),
    "T1071.001": ("Application Layer Protocol: Web Protocols", "command-and-control"),
    "T1105": ("Ingress Tool Transfer", "command-and-control"),
    "T1041": ("Exfiltration Over C2 Channel", "exfiltration"),
    "T1567.002": ("Exfiltration Over Web Service: Exfiltration to Cloud Storage", "exfiltration"),
    "T1486": ("Data Encrypted for Impact", "impact"),
    "T1490": ("Inhibit System Recovery", "impact"),
}

# Techniques that describe the same observed behaviour; either ID is accepted when scoring.
ALIASES = {"T1566.001": "T1204.002"}

KILL_CHAIN = ["Reconnaissance", "Weaponization", "Delivery", "Exploitation",
              "Installation", "Command and Control", "Actions on Objectives"]

TACTIC_TO_KILL_CHAIN = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Weaponization",
    "initial-access": "Delivery",
    "execution": "Exploitation",
    "persistence": "Installation",
    "privilege-escalation": "Installation",
    "defense-evasion": "Installation",
    "command-and-control": "Command and Control",
    "credential-access": "Actions on Objectives",
    "discovery": "Actions on Objectives",
    "lateral-movement": "Actions on Objectives",
    "collection": "Actions on Objectives",
    "exfiltration": "Actions on Objectives",
    "impact": "Actions on Objectives",
}


def canonical(tid: str) -> str:
    return ALIASES.get(tid, tid)


def is_known(tid: str) -> bool:
    return tid in TECHNIQUES


def name(tid: str) -> str:
    return TECHNIQUES[tid][0]


def tactic(tid: str) -> str:
    return TECHNIQUES[tid][1]


def kill_chain_stage(tid: str) -> str:
    return TACTIC_TO_KILL_CHAIN[tactic(tid)]
