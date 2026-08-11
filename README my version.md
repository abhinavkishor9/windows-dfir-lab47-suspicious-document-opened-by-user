# windows-dfir-lab47-suspicious-document-opened-by-user
## Overview

A Windows endpoint is suspected of being involved in a document-based security incident after a user opened an invoice received through an untrusted source.
The user says:

“I opened the invoice, and shortly afterward the security team noticed unusual activity.”

The SOC needs to answer:

Did the document actually exist on the machine?
Was it opened?
Which application opened it?
When was it opened?
Which user opened it?
Was the application launched through Explorer?
Did opening the document result in another process being created?
Are there multiple artifacts supporting the activity?

This is a host-based DFIR investigation.
The investigation focuses on reconstructing the user's activity around the document and determining whether Windows generated evidence of file interaction, application execution, or subsequent process activity. Multiple host artifacts are examined to establish a reliable sequence of events and distinguish normal document access from potentially suspicious behavior.

---

# Executive Summary

The investigation examined a controlled scenario involving the opening of a suspicious invoice document on a Windows workstation. The analysis focused on determining whether the document was accessed by the user, identifying the application responsible for opening it, and examining the endpoint for supporting execution and user-activity evidence. The investigation demonstrated that document-based incidents should be reconstructed through correlation of multiple artifacts rather than relying on a single indicator, allowing investigators to build a more defensible timeline of the user's actions and the system activity that followed.

---

# Investigation Objectives

- Determine whether the suspicious invoice was actually accessed by the user.
- Establish the approximate time at which the document was opened.
- Identify the application responsible for opening the document.
- Determine how the application was launched and identify its parent process.
- Identify Windows artifacts that can support evidence of user interaction with the file.
- Examine process creation telemetry generated around the document-opening event.
- Determine whether any additional process activity occurred immediately after the document was opened.
- Correlate independent artifacts to distinguish confirmed activity from inconclusive evidence.
- Reconstruct the sequence of events surrounding the suspicious document.
- Assess whether the observed activity is consistent with normal user behavior or requires further investigation.

---

# Tools Used

- Windows 10
- PowerShell
- Command Prompt
- Windows Event Viewer
- Sysmon
- Windows Security Logs
- Registry Editor
- Windows Prefetch
- Windows Recent Items
- Windows UserAssist

---

# Lab Environment

| Component          | Details |
| ------------------ | ------- |
| Operating System   | Windows 10 |
| Investigation Type | Host-Based DFIR |
| Primary Artifact   | Suspicious Document Activity |
| Test Document      | `Invoice_June2026.rtf` |
| Investigation Path | `C:\SuspiciousDocumentLab` |
| Analysis Method    | Native Windows Tools |

---

# Investigation Scenario

A user receives an email containing an invoice named Invoice_June2026.rtf.
The user opens the document believing it is a legitimate business invoice.
Shortly afterward, the SOC notices unusual activity associated with the user's workstation.
The original document is still present on the system.

Investigators need to determine:
- Did the user actually open the document?
- When was it opened?
- Which application opened it?
- Was the application launched through normal user activity?
- Did Windows record the document in Recent Items or other user-activity artifacts?
- Did the document-handling application create any suspicious child processes?
- Can process creation logs confirm the activity?
- Are there additional artifacts supporting the user's interaction with the document?


---

# Investigation Workflow

1. Create the investigation workspace.
2. Create the simulated invoice document.
3. Record the document's original metadata.
4. Calculate the document's SHA-256 hash.
5. Verify Sysmon availability.
6. Verify Sysmon Event ID 1 logging.
7. Record the baseline Recent Items state.
8. Open the document as the user.
9. Close the document.
10. Examine Recent Items after opening the document.
11. Compare Recent Items before and after the activity.
12. Investigate Sysmon Event ID 1.
13. Investigate Security Event ID 4688.
14. Identify the document-handling application.
15. Examine the parent process.
16. Investigate Prefetch.
17. Investigate UserAssist.

---

# Investigation Directory

The controlled investigation workspace was:

`C:\SuspiciousDocumentLab`

The simulated suspicious document was:

`C:\SuspiciousDocumentLab\Invoice_June2026.rtf`

The directory was used to separate the test activity from normal Windows files.

---


# Evidence Correlation

The investigation correlated several independent evidence sources.

| Artifact | Investigation Purpose |
| -------- | ---------------------- |
| Document | Establish file existence |
| Filesystem metadata | Establish file timeline |
| SHA-256 | Identify the specific document |
| Recent Items | Support user interaction |
| LNK | Support document access and target path |
| Sysmon Event ID 1 | Establish process creation |
| Security Event ID 4688 | Corroborate process creation |
| Prefetch | Support application execution |
| UserAssist | Support GUI application activity |
| Parent process | Establish application launch context |

---



# Limitations

No single artifact should be treated as definitive proof that a user opened a document.

Recent Items and LNK artifacts provide supporting user-activity evidence but can vary depending on Windows configuration and application behavior.

UserAssist records GUI application activity but does not necessarily provide direct proof that a specific document was opened.

Prefetch provides application execution evidence but does not necessarily identify the specific document opened by that application.

Sysmon Event ID 1 and Security Event ID 4688 depend on logging and auditing being enabled.

Therefore, conclusions should be based on correlation between multiple independent artifacts.

---



# MITRE ATT&CK Mapping

| Technique | Description |
| --------- | ----------- |
| T1204.002 | User Execution: Malicious File |
| T1059.001 | PowerShell |
| T1083 | File and Directory Discovery |

`T1204.002` is particularly relevant to the scenario because the investigation simulates a user opening a potentially suspicious document.

The lab itself used a benign document and did not execute malicious code.

---

