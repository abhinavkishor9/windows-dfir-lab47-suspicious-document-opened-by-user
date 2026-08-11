# Timeline — Suspicious Document Opened by User Investigation

---

# Investigation Timeline

| Sequence | Activity | Evidence / Observation |
| -------- | -------- | ---------------------- |
| 1 | Investigation directory created | `C:\SuspiciousDocumentLab` |
| 2 | Simulated invoice document created | `Invoice_June2026.rtf` |
| 3 | Initial document metadata recorded | File name, size and timestamps |
| 4 | SHA-256 calculated | Baseline file identification |
| 5 | Sysmon service checked | Sysmon availability verified |
| 6 | Sysmon Event ID 1 checked | Process creation telemetry available |
| 7 | Recent Items baseline examined | Pre-execution user activity state |
| 8 | User opened document | `Invoice_June2026.rtf` launched |
| 9 | Document closed | Controlled user activity completed |
| 10 | Recent Items examined again | Post-execution user activity state |
| 11 | Recent Items compared | New or modified entries investigated |
| 12 | Sysmon Event ID 1 investigated | Document-handling application searched |
| 13 | Security Event ID 4688 investigated | Process creation corroboration |
| 14 | Parent process investigated | Application launch context examined |
| 15 | Prefetch investigated | Application execution artifacts searched |
| 16 | UserAssist investigated | GUI application activity examined |

---

