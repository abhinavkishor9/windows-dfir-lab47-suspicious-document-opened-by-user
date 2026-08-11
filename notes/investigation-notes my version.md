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

# Investigation Objective

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

# Step 1 — Create Investigation Workspace

Create workspace:
`C:\SuspiciousDocumentLab`

This directory was used to isolate the controlled test activity.

---

# Step 2 — Create Simulated Suspicious Document


`Invoice_June2026.rtf`

Full path:

`C:\SuspiciousDocumentLab\Invoice_June2026.rtf`


No malicious content was used.

---

# Step 3 — Record Initial Metadata

Before opening the document, we examine the following metadata of the document:

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


