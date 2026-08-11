# Timeline — Suspicious Document Opened by User Investigation

## Lab 47

**Investigation:** Suspicious Document Opened by User

**Test Document:** `Invoice_June2026.rtf`

**Investigation Directory:** `C:\SuspiciousDocumentLab`

---

# Timeline Overview

This timeline reconstructs the controlled activity performed during the suspicious-document investigation.

The investigation began with creation and baseline documentation of the document and continued through user interaction and examination of Windows activity artifacts.

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
| 17 | Document metadata rechecked | File state after opening examined |
| 18 | Evidence correlated | Activity reconstructed |
| 19 | Investigation documented | Findings recorded |

---

# Document Timeline

## Document Creation

The controlled document was created at:

`C:\SuspiciousDocumentLab\Invoice_June2026.rtf`

The initial metadata was recorded before opening the document.

---

# User Interaction

The document was opened using:

`Start-Process "C:\SuspiciousDocumentLab\Invoice_June2026.rtf"`

This simulated the user opening a suspicious invoice document.

The exact execution timestamp should be taken from the actual process creation logs generated during the lab.

---

# Process Creation Timeline

## Sysmon Event ID 1

Sysmon Event ID 1 was used to investigate process creation associated with the document-opening application.

Relevant fields:

- UtcTime
- Image
- CommandLine
- ParentImage
- ProcessId
- ParentProcessId
- User

The actual process timestamp should be taken from the Event ID 1 record observed during the investigation.

---

# Security Event Timeline

## Event ID 4688

Windows Security Event ID 4688 was examined as an additional source of process creation evidence.

The investigation searched for document-handling applications including:

`write.exe`

and:

`winword.exe`

The exact timestamp should be taken from the relevant Security Event 4688 record.

---

# Recent Items Timeline

## Before Opening

The user's Recent Items directory was examined before the document was opened.

This established the baseline state.

## After Opening

The Recent Items directory was examined again after the document was opened and closed.

The investigation searched for:

`Invoice_June2026`

The before-and-after comparison was used to identify possible new user-activity artifacts.

---

# Prefetch Timeline

The Windows Prefetch directory was examined after document activity.

The investigation searched for application artifacts associated with the program used to open the RTF file.

Potential examples:

`WRITE.EXE-*.pf`

`WINWORD.EXE-*.pf`

Prefetch timestamps can provide supporting information for application execution.

---

# UserAssist Timeline

UserAssist was examined after the document-opening activity.

Registry location:

`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`

UserAssist was used as supporting evidence for GUI application activity.

---

# Evidence Correlation Timeline

The investigation followed this sequence:

```text
Invoice_June2026.rtf created
        ↓
Initial metadata recorded
        ↓
SHA-256 calculated
        ↓
Recent Items baseline recorded
        ↓
User opens Invoice_June2026.rtf
        ↓
Document-handling application executes
        ↓
Sysmon Event ID 1 records process creation
        ↓
Security Event ID 4688 may record process creation
        ↓
Document closed
        ↓
Recent Items examined again
        ↓
Prefetch examined
        ↓
UserAssist examined
        ↓
Document metadata rechecked
        ↓
Evidence correlated
        ↓
Investigation conclusion
