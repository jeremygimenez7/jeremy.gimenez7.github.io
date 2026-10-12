# Phishing Email Analyser

A small, self-contained web application that looks at the text of a suspicious email and
explains, in plain English, which phishing warning signs it contains and how much each one
contributed to an overall risk score.

**Everything happens inside your browser.** There is no server, no database, no account, no
AI service, no API key, no analytics and no tracking. The email text you paste is never
uploaded anywhere, because there is nowhere for it to go. Once the page has loaded you can
disconnect from the internet and it will still work.

---

## 1. How to open it

Double-click **`index.html`**. It opens in your normal web browser. That is the whole
installation process. Nothing needs to be downloaded or installed.

Optional: if your browser refuses to run something when opening a file directly, you can run
a tiny local web server instead, but that is not normally necessary.

---

## 2. How to use it

1. Paste the suspicious email (including its subject line) into the big box.
2. Optionally expand **"Advanced (optional): paste raw email headers"** and paste the full
   message headers there. In most mail clients this is under *Show original*, *View source*
   or *Show message headers*. Copy everything above the first blank line.
3. Select **Analyse Email** (or press Ctrl+Enter).
4. Read the result:
   - a risk score from 0 to 100,
   - a classification of **Low Risk**, **Suspicious** or **High Risk**,
   - every warning sign that contributed, with its points and the evidence,
   - a table showing exactly how the total was reached,
   - practical recommendations for what to do next.

There are six made-up demonstration emails built in. Every one of them uses reserved example
domains (`example.com`, `example.net`) and the documentation-only IP range `192.0.2.x`, so
none of them can lead to a real server.

---

## 3. The score, and why it is not a verdict

Each warning sign is a **rule** with a fixed weight. The weights of the rules that fire are
added together and the result is capped at 100. The interface always lists which rules fired
and how many points each one added, so the number can never be a mystery.

| Band | Score | Meaning |
|---|---|---|
| Low Risk | 0 - 24 | Hardly any warning signs were found |
| Suspicious | 25 - 59 | Several warning signs; verify independently before acting |
| High Risk | 60 - 100 | Many strong warning signs; treat the message as hostile |

**This tool can never prove that an email is malicious, and it can never prove that an email
is safe.** A low score simply means the text did not contain the patterns the analyser knows
about. Attackers can write messages that contain none of them.

**Never click a link or open an attachment just to find out whether it is dangerous.**
Clicking is how the attack succeeds. If a message matters, verify it out of band: open the
organisation's official app or website by typing the address yourself, or telephone a number
you already hold (from a statement, card or contract) - never a number or link supplied by
the suspicious email.

---

## 4. What it checks

**In the email body**

- urgency and pressure language, and very short deadlines
- threats of account suspension, closure or other consequences
- requests for a password
- requests for MFA / one-time verification codes
- gift-card, payment and cryptocurrency requests
- requests to change bank details, and "keep this secret" requests
- the "quick favour from the boss" business email compromise pattern
- unexpected invoice and remittance wording
- prize, reward and refund bait
- generic greetings and impersonation wording ("we have detected...", "IT support", ...)
- instructions to enable macros or editing
- unusual or over-formal phrasing, and shouting

**In links**

- shortened links that hide their destination
- raw IP addresses instead of domain names
- domains ending in heavily abused top-level domains (.tk, .xyz, ...)
- punycode ("xn--") look-alike domains
- an "@" in the URL used to hide the real destination
- a brand name in the link that does not match the real registered domain
- deliberate misspellings of a brand ("micro5oft", "rnicrosoft")
- long chains of subdomains
- unencrypted `http://` links
- link text that claims one address while the link goes somewhere else

**In attachment names**

- executables and scripts (.exe, .scr, .js, .ps1, .lnk, ...)
- macro-enabled Office documents (.docm, .xlsm, .pptm, ...)
- compressed archives (.zip, .rar, .7z, ...)
- double extensions such as `invoice.pdf.exe`
- unusual types for email (.html, .svg, .xml, ...)

**In raw headers (optional)**

- SPF failure and soft fail
- DKIM failure
- DMARC failure
- Reply-To on a different domain from the From address
- Return-Path (envelope sender) mismatch
- a display name claiming a brand that does not match the sending domain
- replies directed to a free webmail account
- no passing SPF, DKIM or DMARC result at all

If you do not paste headers, the header checks are shown as **"not checked"** rather than as
passes, so a body-only result never gives false reassurance.

---

## 5. The files

```
index.html            the page
css/styles.css        all of the visual design (colours are variables at the top)
js/rules.js           the body-text rules and their fixed point weights
js/headers.js         raw header parsing + the header rules
js/analyser.js        the engine: context, scoring, bands, advice
js/samples.js         the six fictional demonstration emails
js/selftest.js        the built-in regression tests
js/app.js             the user-interface wiring (the only file that touches the page)
tests/tests.html      run the self-tests in a browser
tools/run-selftest.js runs the self-tests from a command prompt
tools/run-tests.cmd   double-click wrapper for the above
README.md             this document
```

No frameworks, no build step, no package manager and no dependencies. The JavaScript files are
written in deliberately old-fashioned syntax so they can also be executed outside a browser by
the test harness.

---

## 6. Running the tests

The engine ships with **103 automated checks**: domain parsing, link classification,
attachment classification, header parsing, the arithmetic of the score, and an expectation for
each of the six demonstration emails.

**Using the JavaScript engine built into Windows** (nothing to install): double-click
`tools\run-tests.cmd`, or open a Command Prompt in this folder and run:

```
cscript //nologo tools\run-selftest.js
```

**In a browser:** open `tests/tests.html` and read the table.

**In the browser console** on the main page you can also simply type `PA.runSelfTest()`.

---

## 7. Hosting it for free

Because the site is completely static you can publish it on any free static host, for example
GitHub Pages, Cloudflare Pages or Netlify. Upload the folder and point the host at
`index.html`. Visitors get the analyser with no server, no cost and no sign-up, and their
email text never leaves their own machine.

The `tools/` and `tests/` folders are only useful to you, not to visitors. You can leave them
in place or exclude them from the upload.

---

## 8. Adding or changing a rule

Open `js/rules.js`. Every rule looks like this:

```js
PA.rules[PA.rules.length] = PA.util.keywordRule({
  id: 'urgency_language',
  category: 'Urgency & pressure',
  title: 'Urgency and pressure language',
  points: 12,
  why: 'Attackers push you to act fast so that you do not pause to check the message.',
  tags: ['urgency'],
  label: 'Pressure wording',
  phrases: ['urgent', 'immediately', 'act now']
});
```

- `points` is the fixed weight added to the score when the rule fires.
- `phrases` is the plain list of lower-case phrases to look for.
- `title` and `why` are what the user reads, so keep them in plain English.
- `tags` decides which "what to do next" advice appears: `credentials`, `payment`,
  `attachment`, `links`, `headers`, `urgency`, `threat` or `impersonation`.

After an edit, re-run `tools\run-tests.cmd` to confirm nothing broke, then add an expectation
for the rule to a sample in `js/samples.js` so that it stays tested.

---

## 9. Honest limitations

- It is a **pattern matcher**, not an intelligence service. It looks nothing up online and it
  does not know whether a domain is currently malicious.
- It only sees what you paste. If the body is a single image, or an attachment name does not
  appear in the text, it has nothing to work with.
- Link-text comparison works best when you paste the email's HTML source; in plain text there
  is often no separate "visible text" to compare against.
- It has no idea whether a message you were expecting is genuine. Context is yours to supply.
- It is an educational tool and is not a substitute for professional security advice or your
  organisation's reporting process.

