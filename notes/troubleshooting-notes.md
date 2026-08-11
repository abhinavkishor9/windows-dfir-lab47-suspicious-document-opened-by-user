# Troubleshooting Notes — Suspicious Document Opened by User Investigation

## Lab

**Lab 47 — Suspicious Document Opened by User**

---

# Issue 1 — Security Event 4688 PowerShell Parser Error

## Problem

An initial PowerShell query for Security Event ID 4688 produced a parser error.

The problematic structure was similar to:

`$_.Message -match "write|winword.exe"`

being placed directly into the pipeline.

PowerShell reported:

`Expressions are only allowed as the first element of a pipeline.`

It also reported:

`Unexpected token '}' in expression or statement.`

---

## Cause

The `$_` automatic variable can only be used inside an appropriate script block, such as the block passed to `Where-Object`.

It should not be placed directly into the pipeline.

---

## Resolution

The query was corrected to:

`Get-WinEvent -FilterHashtable @{ LogName="Security"; Id=4688 } -MaxEvents 100 | Where-Object { $_.Message -match "write|winword.exe" } | Select-Object TimeCreated, Message`

The important structure is:

`Get-WinEvent`

↓

`Where-Object`

↓

`$_.Message`

↓

`Select-Object`

---

# Issue 2 — Expected Application Name May Differ

## Problem

The investigation initially searched for:

`write.exe`

and:

`winword.exe`

However, the application associated with `.rtf` files depends on the Windows file association configured on the system.

---

## Resolution

The actual application used to open the document should be identified from the observed process creation events rather than assumed beforehand.

Possible applications include:

- WordPad
- Microsoft Word
- Other RTF-compatible applications

---

# Issue 3 — No Matching Security Event 4688

## Problem

The filtered Security Event 4688 query may return no results.

---

## Possible Causes

- The application name was different.
- The relevant event was older than the queried event range.
- Process creation auditing configuration may differ.
- The application may not have generated the expected event in the queried range.
- The query searched only the most recent events.

---

## Resolution

Use a broader query:

`Get-WinEvent -FilterHashtable @{ LogName="Security"; Id=4688 } -MaxEvents 100 | Select-Object TimeCreated, Message`

Then identify the document-handling application from the results.

---

# Issue 4 — Recent Item Not Created

## Problem

`Invoice_June2026.rtf` may not appear in the Recent Items directory.

---

## Interpretation

This does not automatically mean that the document was not opened.

Recent Item generation depends on Windows behavior, application behavior, file associations, and other system conditions.

---

## Resolution

Correlate other artifacts:

- Sysmon Event ID 1
- Security Event ID 4688
- Prefetch
- UserAssist
- Filesystem metadata
- LNK artifacts

---

# Issue 5 — UserAssist Does Not Display Plaintext Application Names

## Problem

UserAssist Registry values are encoded.

Therefore, the investigator may not immediately see:

`write.exe`

or:

`Invoice_June2026.rtf`

in plaintext.

---

## Resolution

Use a UserAssist-aware parser or decode the UserAssist values during offline analysis.

For this lab, UserAssist was treated as a supporting artifact rather than relying on manual plaintext inspection alone.

---

# Issue 6 — Prefetch Artifact Not Found

## Problem

No Prefetch artifact may be visible for the document-handling application.

---

## Possible Causes

- Prefetch behavior varies by Windows configuration.
- The application may not generate the expected artifact.
- The Prefetch directory may have been cleaned.
- The application name may have been different.
- The system may not have generated Prefetch for the particular application.

---

## Resolution

Do not conclude that the document was never opened.

Use:

- Sysmon
- Security 4688
- Recent Items
- LNK
- UserAssist
- Filesystem timestamps

for correlation.

---

# Issue 7 — Sysmon Event ID 1 Contains Many Events

## Problem

Sysmon Event ID 1 can generate a large number of process creation events.

This makes manual investigation difficult.

---

## Resolution

Filter the events by:

- Time
- Application name
- User
- Image
- ParentImage
- CommandLine

For example:

`Where-Object { $_.Message -match "write|winword" }`

This reduces unrelated process activity.

---

# Issue 8 — Security Log Contains Large Number of Events

## Problem

The Windows Security log can contain thousands of events.

Searching all events manually is inefficient.

---

## Resolution

Use the Event ID filter:

`Id = 4688`

and then narrow the results using:

- Application name
- Timestamp
- User
- Command line

This provides a more focused investigation.

---

# Issue 9 — Document Hash Changes

## Problem

The document's SHA-256 hash may differ if the file is modified after opening.

---

## Resolution

Calculate the hash before and after the investigation.

If:

`Hash Before ≠ Hash After`

investigate whether the document was modified.

If:

`Hash Before = Hash After`

the file content remained unchanged during the test.

---

# Issue 10 — Document Metadata Changes

## Problem

Opening a document may affect filesystem timestamps depending on application and Windows behavior.

---

## Resolution

Record:

- CreationTime
- LastWriteTime
- LastAccessTime

both before and after opening.

Do not interpret a single timestamp as definitive proof of user interaction.

---

# General Troubleshooting Guidance

When investigating suspicious documents:

1. Verify the document path.
2. Record metadata before opening.
3. Calculate the SHA-256 hash.
4. Verify Sysmon is running.
5. Verify Event ID 1 exists.
6. Record Recent Items before activity.
7. Open the document normally.
8. Close the document.
9. Check Recent Items again.
10. Identify the actual application used to open the file.
11. Examine Sysmon Event ID 1.
12. Examine Security Event ID 4688.
13. Identify the parent process.
14. Check Prefetch.
15. Check UserAssist.
16. Compare document metadata.
17. Correlate all artifacts.
18. Document missing or inconclusive evidence.

---

# Key Lesson

A missing artifact is not necessarily evidence that an activity did not occur.

For example:

`No Recent Item`

does not automatically mean:

`Document was never opened.`

Likewise:

`No Prefetch`

does not automatically mean:

`Application never executed.`

DFIR investigations should distinguish between:

`Evidence of activity`

`Supporting evidence`

`Inconclusive evidence`

and:

`Absence of evidence`

This prevents unsupported conclusions.
