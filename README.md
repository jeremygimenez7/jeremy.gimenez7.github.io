# Jeremy Gimenez — Cybersecurity Portfolio

A simple, static portfolio website built with **HTML, CSS and vanilla JavaScript** — no frameworks, no build step, no backend, no API keys.

It is designed to help a recruiter or hiring manager understand within about 30 seconds:

- who I am and what I am aiming for,
- which areas of cybersecurity interest me,
- what technologies I have actually used,
- what hands-on projects I have completed,
- what I did in those projects and what concepts I understand,
- where they can see evidence of the work.

> **Accuracy note:** every claim on this site comes from my resume or from project details I supplied myself. Nothing (employers, certifications, tools, metrics or achievements) has been invented. Items that still need real detail use clearly-marked placeholders. The AI service used in the featured home lab is confirmed as **OpenAI**; the specific model, API implementation and any automated response are deliberately left as placeholders until verified.

---

## Project structure

```
Porfolio/
├── index.html                     ← main page (all main sections)
├── projects/
│   ├── wazuh-soc-lab.html                  ← featured project case study (Wazuh SIEM)
│   ├── phishing-email-analyser.html        ← case study: local phishing email triage tool
│   ├── network-traffic-triage.html         ← case study: Wireshark CSV triage tool
│   ├── windows-event-triage.html           ← case study: Windows event log triage tool
│   ├── phishing-email-analyser/            ← the working tool visitors actually open
│   ├── network-traffic-triage/             ← the working tool visitors actually open
│   └── windows-event-triage/               ← the working tool visitors actually open
├── css/
│   └── styles.css                 ← all styling (colours, layout, responsive)
├── js/
│   └── script.js                  ← mobile menu, active nav, image lightbox
├── add-screenshots.ps1            ← resizes your lab screenshots and wires them into the project page
├── build-resume.ps1               ← rebuilds assets/resume.pdf from assets/resume-source.txt
├── fix-encoding.ps1                ← repairs garbled characters (· — ' ←) in the HTML files
├── sync-projects.ps1               ← re-copies the three project tools into projects/
├── assets/
│   ├── favicon.svg                ← browser-tab icon
│   ├── wazuh-architecture.svg     ← lab architecture diagram
│   ├── resume.pdf                 ← ADD THIS (your redacted resume)
│   └── screenshots/
│       ├── shot-wazuh-dashboard.jpg        ← real, redacted screenshots
│       ├── shot-windows-endpoint.jpg
│       ├── shot-fim-events.jpg
│       ├── shot-fim-alert-detail.jpg
│       ├── shot-ubuntu-wazuh-install.jpg
│       ├── shot-ai-soc-workflow.jpg
│       ├── shot-openai-soc.jpg
│       └── shot-secure-reports.jpg
│       (_incoming/  = raw captures and original files, never publish this folder)
└── README.md                      ← this file
```

---

## How to run it locally

You do **not** need any special software installed.

1. Open the folder `C:\Users\Jeremy\OneDrive\Documents\Porfolio`.
2. **Double-click `index.html`** — it opens in your web browser.
3. That's it. Click around the site exactly as a visitor would.

> **Tip:** if images or CSS ever look wrong when double-clicking, run a tiny local server instead. From this folder in a terminal, run `python -m http.server 8000` (if you have Python) and visit `http://localhost:8000`. Either method works; double-clicking is fine for this site.

---

## How to edit the content

Everything you normally need to change is in **`index.html`** and the two files in **`projects/`**. Open them in any plain-text editor (Notepad, VS Code, Notepad++). Look for the comment banners — they mark each part:

```
=== MY NAME ===
=== ABOUT ME ===
=== PROJECTS ===
=== SKILLS ===
=== CERTIFICATIONS ===
=== SOCIAL LINKS ===
=== CONTACT DETAILS ===
```

Search the file for the word **EDIT** to find every spot you might want to change.

### Update your name

In `index.html`, search for `=== MY NAME ===`. There are two places:

1. The header brand (top-left corner) — change `Jeremy Gimenez` if needed.
2. The hero heading — `<h1>Jeremy Gimenez</h1>`.

### Update the About section

1. In `index.html`, find `=== ABOUT ME ===`.
2. Edit the paragraphs inside `<section id="about">`.
3. Keep it short — a few sentences per paragraph reads best.

### Add another cybersecurity project

1. In `index.html`, find the `=== PROJECTS ===` section.
2. Copy one whole `<article class="card project-card"> ... </article>` block.
3. Paste it directly after the block you copied and edit:
   - the `<h3>` project title,
   - the `<p class="meta-line">` security domain line,
   - the `<p>` short description,
   - the `<span class="badge">` technology tags,
   - the link in `<a class="btn ...">`.
4. For a detailed write-up, **copy the file `projects/wazuh-soc-lab.html`** to a new file (e.g. `projects/my-new-lab.html`), rename it, then replace the text inside it. Point your new project card's button at that file.

> Add `featured` to the class list — `class="card project-card featured"` — to give a project the highlighted style (only use this for your strongest one or two).

### Update skills

1. In `index.html`, find `=== SKILLS ===`.
2. Each grey box is a `<div class="card skill-card">`.
3. Add or remove `<span class="badge">Your skill</span>` lines inside.
4. To add a whole new category, copy a whole skill-card block.

### Add or change certifications

1. In `index.html`, find `=== CERTIFICATIONS ===`.
2. **Earned** certifications go in the top grid. Copy a `<div class="cert"> ... </div>` block.
3. **In progress** certifications must be labelled honestly. Use the same block but change the status line to:
   ```html
   <span class="cert-status progress">In progress</span>
   ```
   Never mark an unearned certification as "Earned".

### Replace the images (screenshots)

**Easiest way — use the helper script.** It resizes your screenshots to a web-friendly size and
updates the page for you, so you do not have to edit any HTML.

1. **Redact first.** Open each screenshot in an image editor and black out IP addresses, hostnames
   and computer names, usernames, account names, Windows Security IDs (SIDs), email addresses and
   anything else identifying.
2. Save the redacted images into `assets/screenshots/_incoming/`.
3. The file name decides which slot each image fills — it just has to contain the right word:

   | File name must contain | Fills the slot |
   | --- | --- |
   | `dashboard` | Wazuh SIEM Dashboard |
   | `endpoint` | Windows Endpoint Security Event |
   | `fim` **and** `events` | File Integrity Monitoring — Events |
   | `details` | FIM Alert Detail |
   | `ubuntu` | Ubuntu Server & Wazuh Installation |
   | `workflow` | AI-Assisted SOC Workflow |
   | `openai` | AI-Assisted SOC Triage Report |
   | `reports` | Secure AI SOC Report Handling |

   `01 wazuh dashboard overview.png`, `wazuh-dashboard.png` and `shot-wazuh-dashboard.png` all work.
4. From the portfolio folder, run:
   ```
   powershell -ExecutionPolicy Bypass -File add-screenshots.ps1
   ```
5. It prints what it used and what it skipped. Unmatched slots are left untouched.

The script scales images down to 1600px wide (it never enlarges them) and saves them as JPEGs named
`shot-*.jpg`. `_incoming/` is listed in `.gitignore` so your raw captures never get published.

**Doing it by hand instead.** Save your image into `assets/screenshots/`, then in
`projects/wazuh-soc-lab.html` find `=== 8. SCREENSHOTS ===` (search for `Screenshots & evidence`)
and change both the `src` and `data-full` values for that slot:

```html
<button type="button" class="thumb"
        data-full="../assets/screenshots/shot-wazuh-dashboard.jpg"
        data-caption="My Wazuh dashboard showing the enrolled Windows agent.">
  <img src="../assets/screenshots/shot-wazuh-dashboard.jpg"
       alt="Wazuh dashboard showing one enrolled Windows endpoint.">
</button>
```

`alt` text is read aloud by screen readers — describe what the screenshot shows.

> **Redact before you publish.** Screenshots of a real lab often contain sensitive detail. Black out
> IP addresses, hostnames and computer names, usernames, email addresses, Windows Security IDs
> (SIDs), account / domain names, and anything else identifying (for example a real name in a
> Windows event or a personal folder path) before saving the image into `assets/screenshots/`.
> Once an image is uploaded to a public site it can be copied and archived — treat every screenshot
> as permanent.

All eight gallery frames on `projects/wazuh-soc-lab.html` are now real screenshots, and the
original placeholder `.svg` files have been deleted.

| File | Caption shown |
| --- | --- |
| `shot-wazuh-dashboard.jpg` | Wazuh SIEM Dashboard |
| `shot-windows-endpoint.jpg` | Windows Endpoint Security Event |
| `shot-fim-events.jpg` | File Integrity Monitoring — Events |
| `shot-fim-alert-detail.jpg` | FIM Alert Detail |
| `shot-ubuntu-wazuh-install.jpg` | Ubuntu Server &amp; Wazuh Installation |
| `shot-ai-soc-workflow.jpg` | AI-Assisted SOC Workflow |
| `shot-openai-soc.jpg` | AI-Assisted SOC Triage Report |
| `shot-secure-reports.jpg` | Secure AI SOC Report Handling |

> **Not captured yet.** There is no screenshot of the File Integrity Monitoring *configuration*
> block itself, and no shot of the agent showing as connected on its own. If you add either
> later, save it into `_incoming/`, add a matching slot rule to the top of `add-screenshots.ps1`,
> then copy an existing `<figure>` block in the gallery.

### Replace the architecture diagram

Open `assets/wazuh-architecture.svg` and edit the text labels, or simply drop in your own image and update the `<img src="...">` in the **Lab architecture** section of `projects/wazuh-soc-lab.html`. Always update the `alt` text to match your diagram.

### Update your social links (LinkedIn, GitHub)

These appear in a few places. Search `index.html` for:

- `linkedin.com/in/jeremy-gimenez-74589b134`
- `github.com/jeremygimenez7`

Replace them with your real profile URLs. Do the same in the case-study pages in `projects/`
(`wazuh-soc-lab.html`, `phishing-email-analyser.html`, `network-traffic-triage.html` and
`windows-event-triage.html`) — they contain the same links in the header and footer.

Keep `target="_blank" rel="noopener noreferrer"` on external links — this is a small security practice.

### Update contact details

In `index.html`, find `=== CONTACT / SOCIAL LINKS ===`:

- **Email:** change both `mailto:` and the visible text.
- Only publish contact details you are happy for the whole internet to see.

> **Privacy:** the site deliberately does **not** include a phone number, ID numbers or a home address. Keep it that way unless you consciously decide otherwise.

### Edit your resume (the one on the website)

The site links to `assets/resume.pdf`. **Do not edit that PDF directly** — instead edit the plain-text source and rebuild it:

1. Open **`assets/resume-source.txt`** in any text editor.
2. Change whatever you like. Each line looks like this: `STYLE|Your text`
   - `TITLE|` = big bold heading (your name)
   - `SUB|` = bold subtitle
   - `META|` = small text (your contact line)
   - `H|` = section heading
   - `B|` = bold line
   - `T|` = normal line
   - a blank line = a small gap
   - lines starting with `//` are ignored
3. Save the file.
4. In PowerShell, from the portfolio folder, run:
   ```
   powershell -ExecutionPolicy Bypass -File build-resume.ps1
   ```
5. `assets/resume.pdf` is rebuilt automatically. Refresh the website to check it.

**Fix the two typos from your original resume while you're here** (they have already been corrected in the current version): "Cyber Securty Role" → "Cybersecurity Role", and "nation wide" → "nationwide".

> **Never put your phone number, ID numbers or address in `resume-source.txt`** — this file and the PDF it produces are published with the website.

> **Your original resume** (`Copy of Jeremy Gimenez (1).pdf`) is your master copy and is editable in **Canva**. A `.gitignore` rule keeps that file out of version control, but delete or move it before uploading the folder to a hosting service — it contains your phone number and certification ID.


### Education

Nothing left to fill in — `index.html` shows your **High School Diploma (Olympic High School,
2016)** followed by Self-Directed Cybersecurity Study. If you would rather not include education at
all, delete the whole `<section id="education"> ... </section>` block and its
`<li><a href="#education">` nav link.

> If you later decide to mention the four years of college coursework at Central Piedmont Community
> College, add it back as a **coursework** entry — describe it as coursework only, never as a degree
> or qualification you were awarded.

### The three tool projects (Phishing Analyser, Network Triage, Windows Events)

These three are complete, working browser applications, not just write-ups. Each one has:

- a **case-study page** in `projects/` (the write-up you link to), and
- a **copy of the working tool** in its own folder under `projects/` (what visitors actually open).

The portfolio has to contain its own copy, because a website cannot reach folders outside
itself. That means there are two copies of each tool on your computer:

| Original project (you edit this) | Copy the site serves | Refresh with |
|---|---|---|
| `Documents\Phishing-Analyser` | `projects\phishing-email-analyser\` | `sync-projects.ps1` |
| `Documents\Network-Tool` | `projects\network-traffic-triage\` | `sync-projects.ps1` |
| `Documents\Windows-Events` | `projects\windows-event-triage\` | `sync-projects.ps1` |

**If you change a project, run `sync-projects.ps1` before you publish**, or the site will keep
serving the older copy. Right-click the file and choose "Run with PowerShell", or run:

```
powershell -ExecutionPolicy Bypass -File sync-projects.ps1
```

The script only refreshes the tool folders. It never touches your case-study pages.

### Where the second project went

The old `projects/cysa-plus-home-lab.html` placeholder has been removed and replaced by the
three tool projects above. If you ever want a CySA+ entry back, create a new page in
`projects/` and copy the structure of `wazuh-soc-lab.html`.


---

## How to publish it later (free static hosting)

Any free static host works. **GitHub Pages** is a good default:

1. Create a repository on GitHub (e.g. `portfolio`).
2. Upload everything in this folder to that repository (keep the folder structure).
3. In the repository, go to **Settings → Pages**.
4. Under **Source**, choose the `main` branch and the `/ (root)` folder, then save.
5. After a minute, GitHub gives you a URL like `https://jeremygimenez7.github.io/portfolio/`.

Other free options that work the same way: **Netlify** and **Cloudflare Pages** — drag the folder in, or connect the GitHub repo.

**Before publishing, check:**

- [ ] `assets/resume.pdf` exists (redacted) — or the Resume button is removed.
- [ ] The OpenAI technical placeholders in the Wazuh case study (model / API integration / automated response) are filled in (or the callout is removed).
- [x] Screenshot placeholders are replaced with real screenshots — all eight gallery frames are real captures, **redacted** of IPs, hostnames, usernames, SIDs and account names.
- [ ] The `wazuh-ai-soc-homelab` repository is only linked from `projects/wazuh-soc-lab.html` **after** it has actually been published.
- [ ] Social links point to your live profiles.
- [ ] No garbled characters where punctuation should be — run `fix-encoding.ps1` to check and repair.

---

## Troubleshooting: garbled characters

If a section label shows an accented "A" with a stray dot instead of the single middle dot, if em dashes
or apostrophes appear as a short run of accented characters, or if the arrow links at the top of a case
study page render as a stray accented letter, the HTML file has been through a PowerShell round-trip
that misread its UTF-8 encoding. This used to be caused by `add-screenshots.ps1` — now fixed, it reads
the page with `-Encoding UTF8`.

To repair an affected file, from the portfolio folder run:

```
powershell -ExecutionPolicy Bypass -File fix-encoding.ps1
```

It scans `index.html`, `README.md` and the case-study pages in `projects/`, only replaces the exact damaged
character sequences, and tells you which files it repaired. It is safe to run repeatedly.

---

## Notes on accessibility & security

- Semantic HTML, skip link, visible keyboard focus, and `prefers-reduced-motion` support are built in.
- Text colours were chosen for good contrast on the dark background.
- No trackers, no advertising, no cookies, no external scripts, no backend, no API keys.

## Editing the colours

Open `css/styles.css` and look at the top — the `:root` block holds every colour. Change `--accent` to re-theme the whole site in one place.

