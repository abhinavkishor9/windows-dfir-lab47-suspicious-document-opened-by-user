# Troubleshooting Notes — Suspicious Document Opened by User Investigation


# Issue 1 — Security Event 4688 PowerShell Parser Error

## Problem

An initial PowerShell query for Security Event ID 4688 produced a parser error.


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
