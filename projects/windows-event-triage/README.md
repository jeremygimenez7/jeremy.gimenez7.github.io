# Windows Security Event Log Triage Tool

An educational, browser-based SOC triage tool for Windows Event Viewer CSV exports.

Export security events from Windows Event Viewer, upload the CSV, and get a plain-English,
SOC-style triage report that explains **what happened, why it might deserve investigation, what
could legitimately explain it, and what to check next.**

> **Privacy:** Your Windows security logs are analysed locally in your browser. Files are not
> uploaded or transmitted anywhere.

> **Disclaimer:** Educational SOC triage tool. Findings indicate activity that may deserve
> investigation and do not prove malicious behaviour.
>
> Only analyse logs from systems you own or are authorised to investigate.

---

## Table of contents

1. [What this project is](#1-what-this-project-is)
2. [What Windows Event Logs are](#2-what-windows-event-logs-are)
3. [What SOC triage means](#3-what-soc-triage-means)
4. [Quick start on Windows](#4-quick-start-on-windows)
5. [How to export suitable Windows event data](#5-how-to-export-suitable-windows-event-data)
6. [Supported Event IDs](#6-supported-event-ids)
7. [Detection and correlation rules](#7-detection-and-correlation-rules)
8. [Explainable scoring](#8-explainable-scoring)
9. [Default thresholds and settings](#9-default-thresholds-and-settings)
10. [Sample datasets and a demo script](#10-sample-datasets-and-a-demo-script)
11. [Project structure](#11-project-structure)
12. [Privacy architecture, and how to verify it yourself](#12-privacy-architecture-and-how-to-verify-it-yourself)
13. [Security of the application](#13-security-of-the-application)
14. [Accessibility](#14-accessibility)
15. [False positives](#15-false-positives)
16. [Limitations](#16-limitations)
17. [Educational use](#17-educational-use)
18. [Testing that was performed](#18-testing-that-was-performed)
19. [Ideas for future improvement](#19-ideas-for-future-improvement)

---

## 1. What this project is

A single-page static web application written in **HTML, CSS and vanilla JavaScript**.

It exists to teach four things:

1. **How Windows security events work.** What event 4624 actually records, why "Logon Type"
   matters, and why the same event can mean different things on a workstation and a server.
2. **How SOC analysts correlate events.** Why `4625 → 4625 → 4625 → 4624` is a more interesting
   object than four separate events.
3. **How false positives happen.** Every finding lists the ordinary explanations, because most
   alerts in a real SOC have an ordinary explanation.
4. **How analysts decide what deserves further investigation.** Using a transparent score where
   every point is shown together with the reason it was awarded.

What it deliberately is **not**: a fake "AI detects hackers" product. There is no probability of
compromise, no severity of "Critical", and no claim that any single event proves an intrusion.

**Technology:** plain HTML, CSS and JavaScript. No React, no Next.js, no Node backend, no Python
backend, no database, no cloud service, no external AI API, no API keys, no build step, and no
dependencies of any kind.

---

## 2. What Windows Event Logs are

Windows records what happens on the computer in a set of logs. The **Security** log is the one that
matters for authentication and account activity. Each entry contains:

- an **Event ID** — a number identifying what kind of event it is (for example `4624`, `4625`),
- a **timestamp**,
- a **source**, usually `Microsoft-Windows-Security-Auditing`,
- the **computer** it happened on, and
- a **Message** — a block of human-readable text explaining the event, containing labelled fields
  such as `Account Name:`, `Logon Type:` and `Source Network Address:`.

Other logs also matter:

- **System** — where service installation events (`7045`) appear.
- **Applications and Services Logs → Microsoft → Windows → PowerShell → Operational** — where
  PowerShell script block logging (`4104`) appears. This has to be enabled before the activity you
  want to see happens, otherwise those events simply do not exist.

---

## 3. What SOC triage means

A **SOC** (Security Operations Centre) is the team that monitors for and responds to security
events. **Triage** is the first stage: looking at an alert or an event and deciding

- what it actually is,
- whether it is expected in this environment,
- how urgent it is,
- and what to do next.

Triage is not "decide whether you have been hacked". Triage is "decide whether this deserves more
of somebody's time, and pass it on with the evidence collected so far."

A **detection rule** is a pattern that is worth looking at. A **correlation** joins several events
into a story. Remember: a detection is a reason to investigate, not proof that an attacker is
present.

---

## 4. Quick start on Windows

### You do not need to install anything

No Node.js, no Python, no npm, no compiler, and no internet connection.

### Run it

1. Open the folder containing this project.
2. **Double-click `index.html`.** It opens in Edge or Chrome.
3. Click a **Load ... Sample** button to try it immediately, or upload your own CSV.

Closing the tab discards everything. Nothing is saved, because the application never writes
anything to disk or to browser storage.

### Optional: run it from a tiny local web server

This is not required, but if you prefer an `http://` address (or want to test from another device
on your network), any static server works:

```powershell
# In the project folder, if you already have Python installed:
python -m http.server 8000
# then browse to http://127.0.0.1:8000/
```

### Hosting it later as a static website

Because it is three static files, you can publish this folder to any static host — GitHub Pages,
Cloudflare Pages, Netlify, or an internal web server. Upload `index.html`, `styles.css`, `script.js`
and the `samples/` folder. No server-side code and no configuration is needed.

### An important note about the sample buttons

The **Load ... Sample** buttons do **not** download the files from `samples/`. The demo data is
embedded inside `script.js` so that the buttons work even when the page is opened directly from
disk, where browsers block `file://` downloads for security reasons (this is the same reason the
application contains no `fetch()` call).

The `samples/*.csv` files are separate copies of **exactly the same data**, provided so you can
practise the real upload and drag-and-drop path by hand. A test in this project verifies that each
file on disk produces findings identical to the embedded demo data.

### A console hook for curious students

The application exposes its pure functions on `window.TriageTool`, so you can experiment from the
browser developer console (<kbd>F12</kbd>):

```js
TriageTool.samples.password.build()          // the raw demo CSV, as text
TriageTool.parseCsvText('a,b\n1,2', ',')     // the CSV parser on its own
TriageTool.buildDataset(csvText, {})         // parse a CSV into normalised events
TriageTool.looksEncodedOrObfuscated(text)    // the encoding heuristic
TriageTool.defaults                          // the default thresholds
```

Nothing exposed there performs network access, and nothing is persisted.

---

## 5. How to export suitable Windows event data

### Method A — Windows Event Viewer (the beginner route)

1. Press <kbd>Win</kbd> + <kbd>R</kbd>, type `eventvwr.msc`, and press Enter.
2. In the left pane, expand **Windows Logs** and click **Security**.
3. Optionally click **Filter Current Log…** and enter the Event IDs you want, for example
   `4624,4625,4720,4726,4728,4732,1102`.
4. With the log or filter selected, choose **Action → Save All Events As…**, and set
   **Save as type** to **CSV**.
5. Upload that CSV in this tool.

Then read the caveats below, because Event Viewer's own export has real limitations.

### Method B — PowerShell (the more reliable route)

PowerShell's export produces consistent column names. Run an elevated PowerShell window and adapt
the time range and Event IDs to suit your investigation:

```powershell
# Security events
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    ID        = 4624,4625,4672,4688,4720,4726,4728,4732,1102
    StartTime = (Get-Date).AddDays(-1)
} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, MachineName, UserId, Message |
  Export-Csv -NoTypeInformation -Encoding UTF8 -Path .\security-events.csv
```

PowerShell script block logging (`4104`) and service installation (`7045`) live in other logs, so
export them separately:

```powershell
# PowerShell Operational (only contains 4104 if script block logging is enabled)
Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-PowerShell/Operational'
    ID        = 4104
    StartTime = (Get-Date).AddDays(-1)
} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, MachineName, UserId, Message |
  Export-Csv -NoTypeInformation -Encoding UTF8 -Path .\powershell-events.csv

# System log (service installation)
Get-WinEvent -FilterHashtable @{
    LogName   = 'System'
    ID        = 7045
    StartTime = (Get-Date).AddDays(-1)
} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, MachineName, UserId, Message |
  Export-Csv -NoTypeInformation -Encoding UTF8 -Path .\system-events.csv
```

Both column layouts are recognised, so either method works. See
[§13 Security of the application](#13-security-of-the-application) for the full list of accepted
column names.

### Honest caveats about the export

- **Event Viewer's CSV export can be slow on large log sets**, and its **column headers are
  translated on non-English Windows installations** (for example `Ereignis-ID` on German Windows).
  This tool recognises several localised headers and warns you clearly when it cannot read the
  message text, but a localised export will still be less useful.
- **One log at a time.** Event Viewer's Save dialog exports a single log per file.
- **The interesting detail lives inside the `Message` column**, not in separate columns. The tool
  reads it by field label, which is why it survives layout differences between Windows versions, but
  it also means a truncated `Message` column loses the detail.
- **A real environment uses a real tool.** The CSV format is a convenient, lossy format for
  learning. For genuine incident response you would collect the `.evtx` files themselves or use a
  SIEM. See [§16 Limitations](#16-limitations).

---

## 6. Supported Event IDs

Ten Event IDs, learned properly, are worth more than a thousand skimmed. These are the ones this
tool recognises and explains.

| Event ID | Meaning | Default severity | What the tool tries to extract |
|---|---|---|---|
| **4624** | Successful logon | Informational | Account, logon type, source IP, workstation, process, elevated token |
| **4625** | Failed logon | Informational *(Low/Medium once correlated)* | Account, logon type, source IP, workstation, failure reason |
| **4672** | Special privileges assigned to new logon | Informational | Account |
| **4688** | Process created *(requires process creation auditing)* | Informational | Process, command line, parent process, account |
| **4104** | PowerShell script block logging | Informational *(Medium if encoded)* | Script text, path |
| **4720** | User account created | Medium | New account, who created it |
| **4726** | User account deleted | Low | Deleted account, who deleted it |
| **4728** | Member added to a **global** security group | Medium *(High if privileged)* | Member, group, who added them |
| **4732** | Member added to a **local** security group | Medium *(High if privileged)* | Member, group, who added them |
| **1102** | Security audit log cleared | **High** | Who cleared it |

Deliberately **not** analysed in Version 1: 4673, 4698 (scheduled tasks), Sysmon events, Defender
events, and anything requiring raw `.evtx` parsing. See
[§19 Ideas for future improvement](#19-ideas-for-future-improvement).

### Logon types, because they matter a lot

Events 4624 and 4625 record a **logon type**, and the type changes what the event means.

| Type | Meaning | Why an analyst cares |
|---|---|---|
| 2 | Interactive — a person at the keyboard or console | Normal human activity |
| 3 | Network — shared folder, printer, remote access | Extremely common background noise |
| 4 | Batch — a scheduled task | Automation, often a service account |
| 5 | Service — a Windows service starting | Very common, usually `SYSTEM` or a machine account |
| 7 | Unlock | The workstation was unlocked |
| 8 | NetworkCleartext — credentials sent unencrypted | Worth noticing |
| 9 | NewCredentials — `RunAs` with stored credentials | Worth noticing |
| 10 | RemoteInteractive — Remote Desktop / RDP | Remote access; context is everything |
| 11 | CachedInteractive — cached credentials, no domain contact | Laptop off the corporate network |

The tool displays the number *and* its meaning, so you do not have to memorise the table.

---

## 7. Detection and correlation rules

### Single-event detections

| Finding | Triggered by | Default severity |
|---|---|---|
| User account created | any `4720` | Medium |
| User account deleted | any `4726` | Low |
| Group membership change | any `4728` / `4732` not already part of Rule 3 | Medium, or High if the group looks privileged |
| Security audit log cleared | any `1102` | **High** |
| Service installed | any `7045` | Medium, or High if the binary runs from a temporary, user-writable or data folder |
| Encoded or obfuscated PowerShell | a `4104` whose script text matches a simple encoding pattern, plus related `4688` events | Medium |
| PowerShell script block activity (context) | a `4104` with nothing suspicious in it | Informational |
| Authentication activity below threshold | `4625` counts that did **not** reach the threshold | Informational |

### Rule 1 — Repeated failed logons

- **Trigger:** at least *N* failed logons (`4625`) for the **same account** (default *N* = 5) and,
  when timestamps are usable, all within a **time window** (default 10 minutes).
- **Severity:** Low when the count is at least the threshold but below twice it; Medium at or above
  twice the threshold. The reason for the chosen severity is printed in the finding.
- **Benign explanations listed:** mistyped passwords, a device with a stale saved credential, a
  mapped drive or mail client retrying in a loop, a service account whose password was rotated
  without updating the service.

### Rule 2 — Failed logons followed by a success

- **Trigger:** an account that met Rule 1 also has a successful logon (`4624`) afterwards.
- **Evidence shown:** the event chain (`4625 → 4625 → … → 4624`), the failure count, the successful
  logon time, whether the **source IP matched** the failures, whether the success fell **inside the
  time window**, and the logon type of the successful logon.
- **Severity:** High when the evidence is strong — same source IP **and** inside the window, or the
  same source IP when timestamps are unavailable. Otherwise Medium, with a note stating explicitly
  that the evidence is not strong.
- **Benign explanation listed first:** the legitimate user mistyped their password several times and
  then got it right. This is the most common explanation by far.

### Rule 3 — Account created, then privileges granted

- **Trigger:** a `4720` for an account followed by a `4728` or `4732` for **the same account**.
- **Evidence shown:** the sequence, who created the account, which groups were added, whether any of
  those groups look privileged, and the **elapsed time** between creation and the privilege change.
- **Severity:** High if a privileged group is involved, otherwise Medium.

### Rule 4 — Security audit log cleared

- **Trigger:** any `1102`. Always High, on its own, with no supporting event required.
- The finding explains that clearing logs can be legitimate maintenance, that attackers clear logs
  to remove evidence, and that the events immediately before the clear are no longer available.

### Rule 5 — Administrative / Privilege Activity summary

Collects `4720`, `4726`, `4728`, `4732`, `7045` and `1102` from the whole dataset into a dedicated
section, **bucketed by the account that made the change**. Accounts that touched privilege-related
activity are listed first. Unrelated accounts are kept in **separate groups**, deliberately: the
tool does not blend unrelated users into one story.

### What the tool does *not* do

- It does not attempt malware detection.
- It does not map anything to MITRE ATT&CK.
- It does not claim that any event proves compromise.

---

## 8. Explainable scoring

No fake percentages appear anywhere in this project. There is no "93% malicious". Instead there is
an **investigation priority score** where every contribution is printed next to its reason.

| Contribution | Points |
|---|---|
| Repeated failed logons (an account above the threshold) | +10 |
| Successful logon followed the failures | +20 |
| Privileged group membership change | +25 |
| Security audit log cleared | +30 |
| User account created | +15 |
| User account deleted | +10 |
| New service installed | +15 |
| Encoded or obfuscated PowerShell content detected | +15 |
| Account created and then granted group membership | +10 |

The score is capped at **100**, and when the cap is reached the tool says so and shows the uncapped
total. The interface states plainly that this is *an educational prioritisation mechanism, not a
mathematical probability of compromise*. The weights live in one clearly-labelled block
(`var SCORE = { ... }`) at the top of `script.js`, so you can change them and watch the effect.

---

## 9. Default thresholds and settings

| Setting | Default | Notes |
|---|---|---|
| Failed login threshold | **5** | Failed logons for the same account before an alert is raised. Minimum 2, capped at 1000. |
| Failed login time window | **10 minutes** | Failures must fall inside this window to count as one burst. Minimum 1 minute, capped at 10080 (one week). |

- Both values are **editable in the interface**, and changing either one re-runs the analysis
  immediately so you can watch the effect.
- **Reset Defaults** restores 5 and 10.
- **Security thresholds vary by environment. These values are educational defaults rather than
  universal SOC detection rules.**

What happens when a threshold is *not* met is deliberately visible rather than silent: the tool
produces an Informational finding explaining which accounts failed, how many times, and why no
alert was raised. This is the behaviour that teaches tuning.

**If your export has no usable timestamps**, the time window cannot be applied. Rather than
pretending, the tool falls back to grouping failures across the whole dataset and states in the
finding that it did so and that the failures may have been spread over a long period.

---

## 10. Sample datasets and a demo script

All demo data is **entirely fictional**. Usernames, computer names and IP addresses are invented,
and every address comes from a reserved or private range (RFC 1918 `10.0.0.0/8`, `192.168.0.0/16`,
or the RFC 5737 documentation ranges `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), so none
of them can be routed on the internet.

| File | Scenario | Events | Expected result |
|---|---|---|---|
| `samples/normal-windows-events.csv` | Ordinary activity — successful logons, normal administration, normal process creation, two isolated typos | 15 | Informational only. **No** findings above Informational. |
| `samples/password-guessing.csv` | 8 failed logons for one account from one address in ~3 minutes, then a success from the same address | 12 | **Repeated Failed Logons** (Low), and **Possible Password Guessing Followed By Success** (High) |
| `samples/account-persistence.csv` | Administrator creates `temp-admin`, then adds it to local Administrators 4 minutes later | 6 | **New Account Granted Privileges** (High) |
| `samples/suspicious-admin-activity.csv` | Failures then success, encoded PowerShell, account created and privileged, service installed from `C:\ProgramData`, audit log cleared, account deleted | 18 | Seven findings, four at High, score capped at 100 |

The same four datasets are also built into the interface behind the *Load ... Sample* buttons, so
they work even when the page is opened directly from disk. Each button label shows the expected
result, and the status panel repeats it after loading.

### A five-step demo script

This sequence is designed for demonstrating the project, and each step makes one teaching point.

1. **Load Normal Sample.** Point out that a normal day produces no high-priority alerts, and that
   the two failed logons are *still visible* as an Informational note rather than being hidden.
   *Teaching point: a tool that alerts on everything is as useless as one that alerts on nothing.*
2. **Load Password Guessing Sample.** Point out the **Repeated Failed Logons** finding, its failure
   count, and the source IP.
   *Teaching point: volume matters, and a single failure means nothing.*
3. Look at the second finding from the same dataset: **Possible Password Guessing Followed By
   Success**, at High, with the chain `4625 → … → 4624`.
   *Teaching point: correlation. The same events mean more together than apart.*
4. **Load Privilege Escalation Sample.** Point out **New Account Granted Privileges**, the elapsed
   time between the two events, and the fact that severity rose to High because the group is
   privileged.
   *Teaching point: naming heuristics raise priority; they do not prove intent.*
5. **Load Mixed SOC Sample.** Point out the **Security Audit Log Cleared** finding at High, the
   capped score with its itemised ledger, the Administrative / Privilege Activity section grouped
   by actor, and the filters.

To finish, open the **Detections** panel and change the failed-login threshold from 5 to 20, or the
time window from 10 minutes to 1 minute, and watch the Repeated Failed Logons alert disappear while
the Informational explanation of *why* it disappeared appears instead.

> "The individual events matter, but the real value comes from understanding how they relate to one
> another."

---

## 11. Project structure

```
Windows-Events/
├── index.html      The page: semantic HTML, the upload area, the report, the learning sections
├── styles.css      The dark theme, severity colours, responsive layout, print styles
├── script.js       All the logic, in labelled sections (see the map below)
├── README.md       This document
└── samples/
    ├── normal-windows-events.csv
    ├── password-guessing.csv
    ├── account-persistence.csv
    └── suspicious-admin-activity.csv
```

There is no build step and no `node_modules`. `script.js` is a single file for simplicity, but it is
divided into 22 clearly-labelled sections so it can be read top to bottom:

| Section | Contents |
|---|---|
| 1 | Configuration and constants (thresholds, score weights, column aliases, logon types) |
| 2 | The Event ID knowledge base — one source of truth for detection *and* the learning content |
| 3 | The honest limitations list |
| 4 | Demo dataset builders (the fictional events) |
| 5 | DOM helpers, including the single `esc()` escaping function |
| 6 | The RFC 4180 CSV parser |
| 7 | Column mapping and header normalisation |
| 8 | Timestamp parsing |
| 9 | Message field extraction (sections and labels) |
| 10 | Event normalisation |
| 11 | The parse pipeline |
| 12 | Time helpers |
| 13 | Detection and correlation rules |
| 14 | Scoring, statistics and the timeline |
| 15 | The analysis orchestrator |
| 16 | Rendering |
| 17 | The report pipeline |
| 18 | File input and drag and drop |
| 19 | Settings |
| 20 | Event wiring |
| 21 | Initialisation |
| 22 | The `window.TriageTool` test hook |

---

## 12. Privacy architecture, and how to verify it yourself

**Your Windows security logs are analysed locally in your browser. Files are not uploaded or
transmitted anywhere.**

The uploaded CSV is **not** uploaded to a server, **not** sent to an AI provider, **not** sent to an
analytics platform, **not** stored remotely, and **not** transmitted to external APIs. There are no
analytics, no tracking, no cookies, no advertising, no telemetry and no external data collection.

How that guarantee is built, structurally rather than by promise:

- **There is no server.** The application is three static files. There is no backend to send data to.
- **The file never leaves the page.** It is read with the browser's `FileReader` API into a string in
  memory, parsed in that same tab, and rendered. Nothing else happens to it.
- **Nothing is persisted.** No `localStorage`, no `sessionStorage`, no cookies, no IndexedDB, no
  service worker. Close the tab and everything is gone.
- **There is no network code at all.** `script.js` contains no `fetch()`, no `XMLHttpRequest`, no
  `sendBeacon`, no `WebSocket` and no `EventSource`.
- **Nothing is loaded from the internet.** No CDN, no web fonts, no icon packs, no remote images.
  `styles.css` contains no `url()` and no `@import`. `index.html` references only `styles.css` and
  `script.js`.
- **No AI provider is used**, because there is no code that could call one.

### How to verify all of that in 60 seconds

1. **Search the source.** Open `script.js` in a text editor and search for `fetch`, `XMLHttpRequest`,
   `sendBeacon`, `WebSocket`, `localStorage` and `cookie`. Every occurrence is inside the explanatory
   comment block at the top of the file. There are no calls.
2. **Watch the network tab.** Open the application, press <kbd>F12</kbd>, go to the **Network** tab,
   click **Load Mixed SOC Sample**, and look. There will be no requests beyond the initial load of
   `index.html`, `styles.css` and `script.js`.
3. **Disconnect.** Turn off Wi-Fi, or use your browser's offline mode, then load a sample. Everything
   still works, which is only possible because nothing is fetched.
4. **Upload your own file while offline.** It still works, because parsing happens in the tab.

### One thing that is not about this tool

If you keep your CSV files in a folder that is synced to a cloud service — OneDrive, Dropbox,
Google Drive — then *that service* copies your files to its own servers. That has nothing to do with
this application, but it does mean the location you save exports in is worth a moment's thought. If
you are triaging real logs, keep them somewhere deliberate.

---

## 13. Security of the application

Uploaded CSV content is treated as **untrusted input**. Any file can contain anything, including
text designed to attack the tool that reads it.

| Control | How it is implemented |
|---|---|
| Uploaded values cannot execute JavaScript | Every value taken from the file is inserted into the page through `textContent`, or through a single `esc()` function that escapes `&`, `<`, `>`, `"` and `'` before it is placed in an HTML template. Values are never inserted as raw HTML. |
| No raw HTML from user data | The eight `innerHTML` assignments in `script.js` are limited to static markup, numbers, severity badges built through `esc()`, and warning strings whose file-derived parts are escaped. This is verified by an automated test. |
| Malformed CSV fails safely | The parser reports an unclosed quotation mark and carries on; if the Event ID column is missing or contains no numbers, the tool stops and explains both what it looked for and what your file actually contained. |
| Pathological input cannot hang the page | A 60 MB file-size guard and a 200,000-row cap, both reported to the user when they take effect. |
| Over-long values cannot break the layout | Long process paths, command lines and script text are truncated in the event table, and the stylesheet uses `word-break`. |
| No external requests | See [§12](#12-privacy-architecture-and-how-to-verify-it-yourself). |
| Files are not retained | Nothing is written to disk or to storage; closing the tab discards everything. |

Automated tests cover the escaping behaviour and malformed input, including a CSV whose account
name, computer name and source IP all contain `<img src=x onerror=...>` and
`</td><script>...</script>`. The test asserts that no `<img>` or `<script>` element is created, that
the handler never runs, and that the payload is displayed as harmless text. See
[§18](#18-testing-that-was-performed).

### Accepted column names

Headers are normalised first — lowercased, with every character other than `a`–`z` and `0`–`9`
removed — so `Event ID`, `EventID`, `event_id`, `Event  Id` and `EVENT-ID` all collapse to `eventid`.

| Field | Accepted header names |
|---|---|
| Event ID | `Event ID`, `EventID`, `event_id`, `Id`, `EventCode`, `EventNumber`, `Event` |
| Date and time | `Date and Time`, `TimeCreated`, `Timestamp`, `DateTime`, `Date`, `SystemTime`, `Time`, `Logged` |
| Source | `Source`, `ProviderName`, `Provider`, `SourceName` |
| Level | `Level`, `LevelDisplayName`, `Severity`, `LogLevel` |
| User | `User`, `Username`, `UserId`, `Account`, `AccountName` |
| Computer | `Computer`, `ComputerName`, `MachineName`, `Machine`, `HostName`, `Host` |
| Message | `Message`, `Description`, `Msg`, `Details` |
| Extra | `Task Category`, `Keywords`, `Opcode`, `RecordId`, `LogName`, `Channel` |

A few localised headers are also recognised (for example `EreignisID`, `DatumUndUhrzeit`,
`Beschreibung` on German Windows), but a fully localised export still loses the field detail,
because the **labels inside the message text** are localised too. The tool warns you clearly when
that happens rather than silently returning empty results.

### Delimiters

Comma, semicolon, tab and pipe separators are all detected automatically, because European Excel
exports commonly use semicolons.

---

## 14. Accessibility

- **Semantic HTML**: `header`, `nav`, `main`, `section`, `article`, `footer`, headings in order,
  definition lists for finding facts, and real `<table>` elements with `<caption>` and
  `<th scope="col">` for tabular data.
- **Keyboard accessible**: every control is reachable with <kbd>Tab</kbd>; the drag-and-drop zone is
  a focusable `role="button"` that opens the file dialog on <kbd>Enter</kbd> or <kbd>Space</kbd>;
  nothing depends on a mouse.
- **Visible focus**: a high-contrast outline on `:focus-visible` for every interactive element.
- **Labelled controls**: every input and select has a visible `<label>`; supplementary explanations
  are linked with `aria-describedby`.
- **Live regions**: parse results use `role="status"` with `aria-live="polite"`; errors use
  `role="alert"`; the event count is announced.
- **Contrast**: text and severity colours are chosen for contrast on the dark background. Severity is
  never communicated by colour alone — every severity appears as a text badge *and* as a row accent.
- **Reduced motion**: `prefers-reduced-motion` disables transitions and smooth scrolling.
- **Skip link** to the main content, a labelled `<nav>`, and a print stylesheet that hides the
  controls and prints the report.

---

## 15. False positives

A **false positive** is a detection that fires on legitimate activity. They are normal, expected and
unavoidable. This tool is designed to make them *visible and discussable* rather than to pretend they
do not exist.

| Finding | Common legitimate cause |
|---|---|
| Repeated failed logons | A person mistyping a password, or a phone, mail client or mapped drive using an old saved password in a retry loop |
| Failed logons then success | The same person eventually typing the password correctly |
| User account created | A new starter, a new service account, a test account |
| User account deleted | A leaver, a contractor finishing, a duplicate account being tidied up |
| Privilege change | A promotion, cover for a colleague on leave, a helpdesk task, an installer |
| Security audit log cleared | A maintenance task, or a log-size limit being reached and an administrator clearing it manually |
| Service installed | Almost every software installer, plus backup, monitoring and update agents |
| Encoded PowerShell | Software deployment tooling, configuration management, and remote administration products, which routinely encode commands |
| Process creation | Everything. This event is context, not a detection. |

Every finding contains a **Possible benign explanation** section stating the ordinary causes, placed
before the suggested investigation steps, on purpose.

Try it yourself: with the Normal Sample loaded, set the failed-login threshold to 2. The tool will
now flag two unrelated mistyped passwords as a low-priority finding. That is a live demonstration of
tuning changing outcomes, and of why a threshold is a choice rather than a fact.

---

## 16. Limitations

Documented honestly, because a tool that oversells itself teaches the wrong lesson.

**Parsing and data quality**

- CSV exports differ between Windows configurations, versions and languages. Column names and the
  internal layout of the event message are not guaranteed to match the tool's expectations.
- The detail an analyst wants lives inside the `Message` column. If your export omitted or truncated
  it, Event ID level analysis still works, but the account, source IP and group name are missing.
- On a localised (non-English) Windows installation the labels inside the message text are
  localised. The tool warns you, but the field detail is then unavailable.
- Not every event contains network information. Many events have no source IP at all, and the tool
  shows "unknown" rather than inventing a value.
- Timestamps are usually local time with no timezone offset. They are displayed exactly as written
  and are never converted between timezones.
- Month/day order in an ambiguous date such as `3/4/2026` cannot be determined. The tool assumes
  month-first when an AM/PM marker is present, records the ambiguity, and warns you that ordering and
  time windows for those rows may be wrong.
- Re-saving a CSV in Excel can mangle quoted multi-line fields. The parser reports structural
  inconsistency rather than producing confident nonsense.

**Coverage**

- Event logging configuration affects available telemetry. `4688` only exists if process creation
  auditing was enabled, and `4104` only exists if PowerShell script block logging was enabled,
  *before* the activity happened.
- The **absence of an event does not prove that activity did not occur.** It may have been logged
  elsewhere, overwritten, or never audited.
- Only ten Event IDs are analysed. Scheduled tasks, Sysmon, Defender and many others are not.

**Analysis depth**

- This tool does not replace an EDR, SIEM or professional SOC platform. It performs a small,
  transparent subset of what those systems do.
- Static analysis inside one browser tab provides limited correlation. It cannot join across multiple
  machines, other log sources, identity providers, or historical data.
- There is no baseline of "normal for this user", no watchlist, and no memory of previous uploads —
  deliberately, because remembering would require storage.
- Detecting malicious behaviour requires context. The same event is routine in one environment and
  alarming in another, and only people who know the environment can tell the difference.
- **Windows Event IDs alone cannot determine intent.** An event tells you what happened, not why.
- The PowerShell encoding heuristic is a set of simple string checks, not de-obfuscation. It is
  documented in `looksEncodedOrObfuscated()` so you can read exactly what it does and does not catch.

**Process**

- Version 1 does not parse raw `.evtx` files, does not support Sysmon, and does not perform malware
  detection or MITRE ATT&CK mapping.

---

## 17. Educational use

The most important message in this project:

> **One security event rarely tells the entire story. Analysts build context by correlating multiple
> events.**

and its companion:

> **A detection is a reason to investigate, not proof that an attacker is present.**

The interface contains a **How to think like a SOC analyst** section describing the eight-step
workflow: identify the event; understand what happened; identify the affected user or system;
determine whether the activity is expected; look for related events; correlate authentication and
privilege activity; gather additional evidence; decide whether escalation is required.

It also contains a short **Event ID reference** in plain English, an explanation of detection,
correlation and false positives, and concise Event Viewer collection instructions.

Intended audience: cybersecurity students, people studying for SOC and blue-team roles, and anyone
who wants to understand what a Windows security log actually looks like before they meet one at work.

Suggested exercises:

1. Load the Normal Sample and explain why nothing was escalated.
2. Load the Password Guessing Sample, then set the threshold to 20 and explain what changed and why.
3. Set the time window to 1 minute and explain why the alert disappears even though the failures are
   still in the data.
4. Load the Mixed SOC Sample, pick the highest-priority finding, and argue the *case against* it
   being malicious.
5. Export the Security log from your own Windows machine (one that you own) and compare how noisy a
   real environment is with the tidy samples.

---

## 18. Testing that was performed

The logic was exercised with automated tests run in headless Edge against the real files, plus an
end-to-end test of the real `index.html` interface.

| Area | What was checked | Result |
|---|---|---|
| CSV parsing | Quoted commas, embedded newlines, doubled quotes, `\r\n` vs `\n`, semicolon/tab/pipe detection, unclosed quotes | Pass |
| Encoding | A UTF-8 BOM does not hide the Event ID column | Pass |
| Column mapping | `Event ID` / `EventID` / `event_id` / `Id`; the PowerShell `TimeCreated,Id,ProviderName,LevelDisplayName,Message` layout | Pass |
| Missing columns | No Event ID column: fails safely and lists the headers it actually found. No Message column: parses with a warning. Empty file: clear error. Numeric-free Event ID column: clear error. Junk rows: skipped and counted. | Pass |
| Timestamps | Month-first with AM/PM, day-first when the first number exceeds 12, ISO with `Z`, junk values return null rather than throwing | Pass |
| Message extraction | 4624 account taken from `New Logon` rather than `Subject`; logon type from `Logon Information`; source IP from `Network Information`; 4732 member vs group; 4720 unaffected by `SAM Account Name`; 7045 service name and path; 4104 script text | Pass |
| Rule 1 | 8 failures gives Repeated Failed Logons at Low with the reason stated; 12 failures gives Medium; threshold 20 suppresses it; a 1-minute window correctly finds only 4 of the 8 failures and does not alert | Pass |
| Rule 2 | Failures then success from the same IP inside the window gives High; a success from a different IP an hour later gives Medium with a "not strong" note | Pass |
| Rule 3 | 4720 then 4732 for the same account gives High, shows the sequence and elapsed time, and absorbs the standalone "account created" finding so nothing is double-counted | Pass |
| Rule 4 | 1102 always gives a High finding | Pass |
| Rule 5 | Admin/privilege groups are produced, and unrelated actors land in separate groups | Pass |
| 4104 | Encoded PowerShell is detected and the related `4688` is attached as supporting evidence | Pass |
| Scoring | Contributions are itemised; the mixed sample caps at 100 with the cap disclosed | Pass |
| Normal sample | No High findings; nothing above Informational; the two isolated failures are explained rather than hidden | Pass |
| No timestamps | The rule still fires by counting, the finding says the window could not be applied, and the timeline states that ordering is by file position | Pass |
| Localised messages | A German-style message parses, and the tool warns that the labels could not be read | Pass |
| **XSS** | A CSV whose account, computer and IP contain `<img src=x onerror=...>` and `</td><script>...</script>`: no `<img>` or `<script>` element is created, the handler never runs, and the payload renders as text in the table, the findings and the filter options | Pass |
| **Network isolation** | All analysis was re-run with `fetch`, `XMLHttpRequest` and `sendBeacon` replaced by functions that fail loudly. No call was ever made. | Pass |
| Sample files | All four `samples/*.csv` files parsed by a second, independent CSV reader written in PowerShell: correct header, correct record count, no malformed rows, balanced quoting | Pass |
| Sample files ≡ demo data | Each file on disk produces a finding signature identical to the embedded demo data | Pass |
| Real interface | The real `index.html` was driven headlessly: each demo button rendered the expected findings, statistic cards, timeline entries, filter options, reference items and limitation items; the filters and the search box returned the expected row counts | Pass |

### Bugs found during testing, and fixed

1. **The suspicious-service-path check never matched anything.** The regular expression was written
   with doubled backslashes (`\\\\`), which in a regular expression literal means *two* literal
   backslashes, so it could never match a real Windows path such as `C:\ProgramData\...`. A service
   installed from a user-writable folder was therefore never escalated to High. **Fixed** by
   normalising the path separators first and then testing a separator-independent pattern, which is
   also far easier to read.
2. **The timeline could imply a chronology it could not support.** When an export contained no usable
   timestamps, noteworthy events were still listed under a "Timeline" heading in file order, which
   could be misread as a time sequence. **Fixed:** the timeline now detects that no event has a usable
   timestamp and prepends an explicit note that the order is the file's, not time's.

Two early test failures were **errors in the tests, not in the application**: an incorrect expected
count of successful logons, and an assumed severity threshold that the documented rule does not use.
Both were corrected in the tests rather than by changing working behaviour. (Rule 1 is `Low` at the
threshold and `Medium` at twice it, and the finding states which applied and why.)

### Known remaining limitations found while testing

- On a real machine, logon types 3 and 5 (`SYSTEM` and machine accounts) are extremely common. They
  are counted, shown, and disclosed as background/noise, but the tool does not yet filter the event
  table by them automatically.
- The `esc()`-based escaping strategy is the single control protecting the HTML templates. It is
  tested, but it is a convention that must be maintained: any future code that inserts file-derived
  values must go through `esc()` or `textContent`.

---

## 19. Ideas for future improvement

Deliberately **not** implemented in Version 1, because each one either needs a real backend, adds a
dependency, or would need far more validation than a small educational tool can honestly provide.

- Raw `.evtx` parsing in the browser
- Sysmon event support
- Deeper PowerShell `4104` analysis, including real de-obfuscation and display of decoded commands
- Process-tree visualisation built from `4688`
- MITRE ATT&CK technique mapping for each finding
- Proper timeline analysis: gaps, clustering, per-host activity charts
- Login-time baselining, so "unusual for this user" becomes computable within a dataset
- Scheduled task monitoring (`4698`, `4702`)
- Windows Defender event analysis
- Exportable incident report (print-ready or a downloadable HTML summary)
- Multiple CSV uploads with cross-file correlation
- Optional SIEM integration for people who have one

None of these should be attempted before the corresponding detection logic has been validated against
real data, and none of them should ever turn "this deserves investigation" into "this is malicious".

---

## Licence and attribution

No licence has been applied to this project yet. If you intend to publish it — for example on GitHub
Pages — add a `LICENSE` file first. The MIT licence is the usual choice for small educational tools
and permits reuse with attribution, but that is your decision to make.

All demo data in `samples/` is fictional and uses reserved or private IP address ranges.
