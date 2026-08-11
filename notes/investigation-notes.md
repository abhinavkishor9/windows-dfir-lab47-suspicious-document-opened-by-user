# Investigation Notes — Suspicious Document Opened by User Investigation

## Case Information

| Field | Details |
| ----- | ------- |
| Lab | Lab 47 |
| Investigation | Suspicious Document Opened by User |
| Host | Windows 10 |
| Test Document | `Invoice_June2026.rtf` |
| Investigation Directory | `C:\SuspiciousDocumentLab` |
| Investigation Type | Host-Based DFIR |

---

# Investigation Scenario

A user is suspected of opening a suspicious invoice document on a Windows endpoint.

The SOC needs to determine whether the document was opened, which application handled the document, whether process creation telemetry was generated, and whether additional Windows artifacts support the user's interaction with the document.

---

# Investigation Objective

The objective was to reconstruct the activity surrounding a suspicious document opening by correlating filesystem, user-activity, application-execution, and process-creation artifacts.

---

# Step 1 — Create Investigation Workspace

The investigation workspace was created at:

`C:\SuspiciousDocumentLab`

This directory was used to isolate the controlled test activity.

---

# Step 2 — Create Simulated Suspicious Document

A benign RTF document was created and named:

`Invoice_June2026.rtf`

Full path:

`C:\SuspiciousDocumentLab\Invoice_June2026.rtf`

The document simulated an invoice that could be received through email or another delivery mechanism.

No malicious content was used.

---

# Step 3 — Record Initial Metadata

Before opening the document, the following information was examined:

- Name
- Length
- Creation time
- Last write time
- Last access time
- Full path

This established the document's baseline state.

---

# Step 4 — Calculate SHA-256

A SHA-256 hash was calculated for the document.

The hash serves as an identifier for the exact file used during the investigation.

The hash can later be compared against a second hash to determine whether the document changed.

---

# Step 5 — Verify Sysmon

The Sysmon service was checked to confirm that Sysmon was available.

The Sysmon Operational event log was also checked.

The investigation required Event ID 1 because:

`Event ID 1 = Process Creation`

---

# Step 6 — Verify Event ID 1

Sysmon Event ID 1 events were queried from:

`Microsoft-Windows-Sysmon/Operational`

The objective was to confirm that process creation telemetry was available before performing the controlled document-opening activity.

---

# Step 7 — Record Recent Items Baseline

The user's Recent Items directory was examined:

`C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent`

A baseline was taken before opening the document.

This allowed the investigator to compare the Recent Items state before and after the activity.

---

# Step 8 — Open the Document

The simulated document was opened using:

`Start-Process "C:\SuspiciousDocumentLab\Invoice_June2026.rtf"`

Windows opened the document using the registered application for the RTF file type.

The document was then closed normally.

The exact application used to open the document was noted during the investigation.

---

# Step 9 — Examine Recent Items

The Recent Items directory was examined after the document was opened.

The investigation searched for entries associated with:

`Invoice_June2026`

The objective was to determine whether Windows created a Recent Item or LNK artifact associated with the document.

---

# Step 10 — Compare Before and After

The Recent Items baseline was compared with the state after the document-opening activity.

The comparison was used to identify new or modified entries.

A matching Recent Item would provide supporting evidence of user interaction.

---

# Step 11 — Investigate Sysmon Event ID 1

Sysmon Event ID 1 was queried from:

`Microsoft-Windows-Sysmon/Operational`

The investigation searched for processes associated with the document-opening application.

Potential applications included:

- `write.exe`
- `WINWORD.EXE`
- Other RTF-associated applications

Relevant fields included:

- TimeCreated
- Image
- ParentImage
- CommandLine
- ProcessId
- ParentProcessId
- User

---

# Step 12 — Investigate Security Event ID 4688

Windows Security Event ID 4688 was investigated.

The event represents:

`A new process has been created`

The investigation searched for document-handling applications such as:

`write.exe`

and:

`winword.exe`

Security Event 4688 was treated as an additional source for corroborating process creation.

---

# Step 13 — Analyze Parent Process

The Sysmon process creation data was examined for parent-child relationships.

The investigation looked for relationships such as:

`explorer.exe`

↓

`write.exe`

The actual parent process was determined from the observed Event ID 1 data.

Parent-child relationships are important because they provide context around how the document-handling application was launched.

---

# Step 14 — Investigate Prefetch

The Windows Prefetch directory was examined.

The investigation searched for Prefetch artifacts associated with the application used to open the RTF document.

Potential examples:

`WRITE.EXE-*.pf`

or:

`WINWORD.EXE-*.pf`

Prefetch was treated as supporting application execution evidence.

---

# Step 15 — Investigate UserAssist

UserAssist was examined under:

`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`

The Registry structure and subkeys were examined.

UserAssist values are encoded and therefore may not display application names directly.

UserAssist was treated as supporting evidence for GUI application activity.

---

# Step 16 — Recheck Document Metadata

The document metadata was examined again after the opening activity.

The following fields were checked:

- CreationTime
- LastWriteTime
- LastAccessTime
- Length

The SHA-256 hash could also be recalculated to determine whether the document changed.

---

# Evidence Correlation

The investigation correlated:

`Invoice_June2026.rtf`

with:

- Filesystem metadata
- SHA-256
- Recent Items
- LNK activity
- Sysmon Event ID 1
- Security Event ID 4688
- Prefetch
- UserAssist
- Parent process information

The goal was to determine whether these artifacts supported the same sequence of activity.

---

# Investigation Assessment

The controlled document was successfully created and opened.

The investigation demonstrated how user interaction with a document can generate evidence across multiple Windows components.

Process creation telemetry was particularly important because it allowed the document-handling application to be identified and examined in the context of its parent process.

Recent Items, Prefetch, and UserAssist were treated as supporting artifacts rather than standalone proof.

---

# Forensic Interpretation

The investigation follows the principle:

`File existence alone does not prove user interaction.`

A stronger conclusion is obtained when:

`Document exists`

+

`Recent/LNK evidence`

+

`Application execution`

+

`Sysmon/Security process creation`

+

`Supporting execution artifacts`

all point toward the same activity.

---

# Conclusion

The investigation demonstrated a practical methodology for investigating a suspicious document opened by a Windows user.

The activity was reconstructed using filesystem evidence, Recent Items, process creation logs, Prefetch, and UserAssist.

The investigation reinforced the importance of evidence correlation and demonstrated that individual Windows artifacts should be interpreted within the context of the complete activity timeline.
