# Threat Intelligence Report: GLASS HERON

*Fictional threat actor written for this project. All infrastructure uses reserved documentation addresses.*

**Classification:** TLP:CLEAR · **Sector:** Finance and accounting teams · **Confidence:** Moderate

## Summary

GLASS HERON is a financially motivated intrusion set that targets finance departments with invoice-themed lures. After initial access it moves quickly to steal credentials, reaches file servers that hold finance data, and exfiltrates password-protected archives to cloud storage. Dwell time before exfiltration is often under two hours.

## Observed tradecraft

1. **Delivery.** Victims receive emails with macro-enabled Word attachments named like `Invoice_Q3_<number>.docm`. The user opens the document and enables content.
2. **Execution.** The macro starts PowerShell with a hidden window and runs a download cradle that pulls a second-stage script from `cdn-invoice-sync[.]com` and executes it in memory with `IEX`.
3. **Command and control.** The second stage beacons over HTTPS to `203.0.113[.]47`.
4. **Tool transfer.** The actor uses the built-in `certutil` utility with `-urlcache` to download a DLL payload, typically `svc.dll`, into `C:\ProgramData`.
5. **Persistence.** A scheduled task named to look like a OneDrive component runs the DLL through `rundll32` at logon.
6. **Credential access.** The actor dumps LSASS memory using the `MiniDump` export of `comsvcs.dll`.
7. **Discovery.** The actor enumerates privileged domain groups with `net group "domain admins" /domain`.
8. **Lateral movement.** Using stolen administrator credentials, the actor copies the DLL to other hosts over admin shares (`C$`) and starts it remotely with `wmic /node:`.
9. **Collection.** On file servers the actor stages data in password-protected archives created with a standalone `7za.exe` dropped into `C:\ProgramData`.
10. **Exfiltration.** Archives are uploaded to cloud storage with `rclone`. The actor rotates exfiltration infrastructure often, so IP addresses used for exfiltration age out quickly.

## Indicators of compromise

| Type | Value | Note |
|---|---|---|
| Domain | `cdn-invoice-sync[.]com` | Second-stage download, C2 |
| Domain | `update-msofficecdn[.]net` | Older C2, seen in earlier campaigns |
| IPv4 | `203.0.113[.]47` | C2 and payload hosting |
| IPv4 | `192.0.2[.]200` | Older exfiltration server |
| SHA256 | `9f2b4c6d8e0a1b3c5d7e9f1a2b4c6d8e0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c` | svc.dll |
| SHA256 | `1a3c5e7f9b2d4f6a8c0e2b4d6f8a1c3e5f7b9d1a3c5e7f9b2d4f6a8c0e2b4d6f` | 7za.exe (renamed copy) |

## Hunting guidance

Atomic indicators for this actor change quickly. Defenders should hunt for the behaviours above, especially Office applications spawning PowerShell, `certutil` with URL cache flags, `comsvcs.dll` MiniDump, remote `wmic` process creation, and archive or sync utilities running from `C:\ProgramData`.
