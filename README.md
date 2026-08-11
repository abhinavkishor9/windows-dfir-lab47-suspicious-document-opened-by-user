# windows-dfir-lab47-suspicious-document-opened-by-user

## Overview

Opening a suspicious document is a common initial event in phishing and malware investigations. A user may receive an invoice, report, resume, or other document and open it without realizing that the file may be associated with suspicious activity.

From a DFIR perspective, the important question is not simply whether the document existed on the endpoint. Investigators need to determine whether the document was opened, which application opened it, which user was involved, and what evidence Windows generated around the activity.

In this hands-on DFIR lab, a controlled `Invoice_June2026.rtf` document was created and opened by the user. Windows filesystem metadata, Recent Items, Sysmon Event ID 1, Windows Security Event ID 4688, Prefetch, and UserAssist were then examined to reconstruct the document-opening activity.

The document used in the lab was benign and was created only to simulate a suspicious document investigation.

---

# Executive Summary

This investigation simulated a scenario in which a user opens a suspicious invoice document on a Windows endpoint.

A controlled `Invoice_June2026.rtf` document was created inside `C:\SuspiciousDocumentLab` and opened using the system's default application. Following the document-opening activity, Windows artifacts were examined to determine whether the document and its associated application left forensic traces.

Filesystem metadata was recorded for the document, Recent Items were examined for user interaction evidence, Sysmon Event ID 1 was investigated for process creation, Security Event ID 4688 was examined as an additional process creation source, Prefetch was checked for application execution evidence, and UserAssist was examined for GUI application activity.

The investigation demonstrated that suspicious document investigations require correlation between file, user activity, application execution, and process creation artifacts rather than relying on a single artifact.

---

# Investigation Objectives

- Understand how Windows records document-opening activity.
- Create a controlled suspicious-document scenario.
- Create a simulated invoice document.
- Record the document's original filesystem metadata.
- Calculate the document's SHA-256 hash.
- Open the document using the normal Windows user workflow.
- Examine Recent Items.
- Investigate LNK-related user activity evidence.
- Examine Sysmon Event ID 1.
- Examine Windows Security Event ID 4688.
- Investigate Prefetch.
- Examine UserAssist.
- Identify the application associated with opening the document.
- Examine parent-child process relationships.
- Correlate multiple Windows artifacts.
- Understand the limitations of individual artifacts.

---

# Skills Demonstrated

- Windows DFIR
- Suspicious Document Investigation
- User Activity Investigation
- Document Activity Reconstruction
- Windows Filesystem Forensics
- Recent Items Analysis
- LNK Artifact Analysis
- Sysmon Analysis
- Windows Security Log Analysis
- Event ID 1 Investigation
- Event ID 4688 Investigation
- Prefetch Analysis
- UserAssist Analysis
- Process Parent-Child Analysis
- Evidence Correlation
- Timeline Reconstruction
- Forensic Documentation

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

Suppose a user reports receiving an invoice document and opening it on their Windows computer.

The SOC receives an alert indicating that a potentially suspicious document was opened.

Investigators need to determine:

- Did the document exist on the endpoint?
- Where was it located?
- When was it created?
- When was it accessed?
- Did the user actually open it?
- Which application opened the document?
- Which user was involved?
- Did Windows create a Recent Item or LNK artifact?
- Did the associated application execute?
- Was the execution recorded by Sysmon?
- Was the execution recorded by Windows Security logging?
- Did Prefetch contain evidence of application execution?
- Did UserAssist record related GUI activity?
- Did the document-opening application create any child processes?

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
18. Examine the document metadata again.
19. Check for changes to the document.
20. Correlate the evidence.
21. Document the investigation findings.

---

# Investigation Directory

The controlled investigation workspace was:

`C:\SuspiciousDocumentLab`

The simulated suspicious document was:

`C:\SuspiciousDocumentLab\Invoice_June2026.rtf`

The directory was used to separate the test activity from normal Windows files.

---

# Suspicious Document

A benign RTF document was created to simulate a suspicious invoice.

The document contained simulated invoice information such as:

- Invoice number
- Customer information
- Amount due
- Due date
- Review instructions

The document was not malicious.

The purpose of the document was to generate realistic Windows user-activity and application-execution artifacts in a controlled environment.

---

# Document Creation

The document was created using PowerShell.

The resulting file was:

`Invoice_June2026.rtf`

The file was stored at:

`C:\SuspiciousDocumentLab\Invoice_June2026.rtf`

---

# Initial File Metadata

Before opening the document, filesystem metadata was collected.

The following information was examined:

- File name
- File size
- Full path
- Creation time
- Last write time
- Last access time

This established the baseline state of the document before user interaction.

---

# SHA-256 Hash

A SHA-256 hash was calculated for the document before opening it.

The hash provides a unique identifier for the specific document used during the investigation.

The hash can be compared with a later hash to determine whether the document changed during the investigation.

---

# User Activity Simulation

The document was opened using the normal Windows user workflow:

`Start-Process "C:\SuspiciousDocumentLab\Invoice_June2026.rtf"`

The system opened the RTF document using the application's registered file association.

The document was then closed normally.

This simulated the user opening a suspicious invoice document received through a potential phishing scenario.

---

# Recent Items Investigation

The user's Recent Items directory was examined:

`C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent`

The baseline Recent Items state was examined before opening the document.

The Recent Items directory was then examined again after the document was opened.

The purpose was to determine whether Windows created or modified a Recent Item associated with:

`Invoice_June2026.rtf`

Recent Items can provide supporting evidence of user interaction with files.

---

# LNK Investigation

Recent Items commonly contain `.lnk` shortcut artifacts.

LNK artifacts can contain information such as:

- Target path
- Target filename
- Volume information
- File metadata
- User activity context

A matching Recent Item or LNK artifact can strengthen the conclusion that a user interacted with the document.

However, absence of a Recent Item or LNK should not automatically be interpreted as proof that the document was never opened.

---

# Sysmon Event ID 1 Investigation

Sysmon Event ID 1 represents:

`Process Create`

The Sysmon Operational log was checked to confirm that Event ID 1 records were available.

The investigation focused on identifying the process associated with opening the RTF document.

Potential document-handling applications included:

- `write.exe`
- `WINWORD.EXE`
- Other applications registered to handle RTF files

Relevant Sysmon fields include:

- Image
- CommandLine
- ParentImage
- ProcessId
- ParentProcessId
- User
- UtcTime

---

# Parent-Child Process Investigation

Parent-child relationships were examined using Sysmon Event ID 1.

The objective was to determine how the document-handling application was launched.

A possible relationship could look like:

`explorer.exe`

↓

`write.exe`

↓

`Invoice_June2026.rtf`

The exact process relationship should be based on the actual Event ID 1 data observed during the investigation.

Parent-child analysis is important because it helps distinguish normal user activity from suspicious process execution chains.

---

# Windows Security Event ID 4688

Windows Security Event ID 4688 represents:

`A new process has been created`

The Security log was examined for Event ID 4688.

The investigation attempted to identify the document-handling application by searching the event messages for:

- `write.exe`
- `winword.exe`

Event 4688 provides another source of process creation evidence that can be correlated with Sysmon Event ID 1.

---

# Prefetch Investigation

The Windows Prefetch directory was examined for application execution artifacts.

The investigation searched for application names associated with the RTF document.

Potential artifacts included:

`WRITE.EXE-*.pf`

or:

`WINWORD.EXE-*.pf`

Prefetch can provide supporting evidence that an application executed on the endpoint.

However, Prefetch evidence should not automatically be interpreted as proof that a particular document was opened.

The Prefetch result should be correlated with:

- Recent Items
- LNK artifacts
- Sysmon Event ID 1
- Security Event ID 4688
- UserAssist

---

# UserAssist Investigation

UserAssist was examined as an additional source of GUI application activity.

The primary Registry location is:

`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`

The UserAssist structure was verified and its subkeys were examined.

UserAssist values are encoded and may not directly display application names in plain text.

UserAssist can provide supporting evidence for applications launched through the Windows graphical user interface.

---

# Document Integrity Check

The document's metadata was examined again after the user opened and closed it.

The following attributes were checked:

- Creation time
- Last access time
- Last write time
- File size
- SHA-256 hash

The purpose was to determine whether the document itself changed during the investigation.

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

# Investigation Findings

The investigation successfully created and opened the controlled `Invoice_June2026.rtf` document.

Filesystem metadata and SHA-256 information were collected before user interaction.

The document was opened using the Windows file association mechanism and then closed normally.

Recent Items were examined before and after the document-opening activity to identify changes associated with the document.

Sysmon Event ID 1 was examined as the primary process creation source, while Security Event ID 4688 was examined as an additional process creation source.

Prefetch was investigated for execution evidence associated with the application used to open the document.

UserAssist was also examined as a supporting source of GUI application activity.

---

# Forensic Interpretation

The key principle demonstrated by this investigation is:

`Document exists ≠ Document was opened`

A stronger conclusion requires correlation between:

`Document`

↓

`User Activity`

↓

`Application Execution`

↓

`Process Creation`

↓

`Supporting Artifacts`

For example, if a matching Recent Item exists, the document-handling application executed at the corresponding time, and Sysmon/Event 4688 show the process creation, the combined evidence provides substantially stronger support for the document-opening activity.

---

# Limitations

No single artifact should be treated as definitive proof that a user opened a document.

Recent Items and LNK artifacts provide supporting user-activity evidence but can vary depending on Windows configuration and application behavior.

UserAssist records GUI application activity but does not necessarily provide direct proof that a specific document was opened.

Prefetch provides application execution evidence but does not necessarily identify the specific document opened by that application.

Sysmon Event ID 1 and Security Event ID 4688 depend on logging and auditing being enabled.

Therefore, conclusions should be based on correlation between multiple independent artifacts.

---

# Evidence Collected

The investigation examined:

- `Invoice_June2026.rtf`
- Filesystem metadata
- SHA-256 hash
- Recent Items
- LNK activity
- Sysmon Event ID 1
- Security Event ID 4688
- Prefetch
- UserAssist
- Parent-child process relationships
- Investigation screenshots

The final evidence-export step was not performed during this lab session.

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

# Key Takeaway

A suspicious document investigation is not simply a file investigation.

The investigator must reconstruct the complete activity:

`What file?`

↓

`Where was it?`

↓

`Who interacted with it?`

↓

`When was it opened?`

↓

`Which application opened it?`

↓

`What process launched that application?`

↓

`Did any child processes appear?`

↓

`What other Windows artifacts support the activity?`

Reliable DFIR conclusions come from correlating multiple artifacts rather than relying on one Registry key, one event log, or one timestamp.
