/* ==========================================================================
 * rules.js -- the warning signs the analyser looks for, and what each is worth
 * --------------------------------------------------------------------------
 * Every rule is a plain object:
 *
 *   id        a short unique name (also used by the self-tests)
 *   category  how the finding is grouped on the results screen
 *   title     the readable name shown to the user
 *   points    the fixed score contribution (never changes while the page runs)
 *   why       one sentence explaining why this matters
 *   needs     'body' (default), 'links', 'attachments' or 'headers'
 *   tags      used to pick the right "what to do next" advice
 *   test(ctx) returns { matched: true, evidence: [...] } or { matched: false }
 *
 * This file is written in deliberately old-fashioned JavaScript (no arrow
 * functions, no modern syntax) for two reasons:
 *   1. It runs in every browser, however old.
 *   2. The same file can be executed by Windows Script Host for the self-tests.
 * ========================================================================== */

window.PA = window.PA || {};
var PA = window.PA;

/* ============================== helpers ================================= */

PA.util = {};

/* Trim without relying on String.prototype.trim (absent from older engines). */
PA.util.trim = function (s) {
  return String(s == null ? '' : s).replace(/^[\s\u00a0]+|[\s\u00a0]+$/g, '');
};

/* Return every phrase from `list` that appears somewhere in `text`.
   `text` must already be lower-case. No word boundaries -- which is what we
   want for phrases such as "within 24 hours". */
PA.util.findPhrases = function (text, list) {
  var found = [];
  if (!text || !list) { return found; }
  for (var i = 0; i < list.length; i++) {
    if (text.indexOf(list[i]) !== -1) { found[found.length] = list[i]; }
  }
  return found;
};

/* Whole-word search, used for short tokens such as "otp" or "kindly", where a
   plain substring match could fire inside a longer word. */
PA.util.hasWord = function (text, word) {
  if (!text || !word) { return false; }
  var escaped = word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  var re = new RegExp('(^|[^a-z0-9])' + escaped + '([^a-z0-9]|$)', 'i');
  return re.test(text);
};

PA.util.findWords = function (text, list) {
  var found = [];
  if (!text || !list) { return found; }
  for (var i = 0; i < list.length; i++) {
    if (PA.util.hasWord(text, list[i])) { found[found.length] = list[i]; }
  }
  return found;
};

/* Build a standard "these phrases were found" test result. */
PA.util.phraseResult = function (found, label, limit) {
  if (!found || !found.length) { return { matched: false, evidence: [] }; }
  var max = limit || 5;
  var ev = [];
  for (var i = 0; i < found.length && i < max; i++) {
    ev[ev.length] = (label || 'Wording found') + ': "' + found[i] + '"';
  }
  if (found.length > max) {
    ev[ev.length] = '...and ' + (found.length - max) + ' more phrase(s) of the same kind';
  }
  return { matched: true, evidence: ev };
};

/* Shortcut: a test that fired because of one identified fact. */
PA.util.hit = function (evidenceLines) {
  return { matched: true, evidence: evidenceLines };
};

/* Shortcut: a test that did not fire. */
PA.util.miss = function () {
  return { matched: false, evidence: [] };
};

/* Exemption check. Some legitimate security-awareness emails deliberately
   contain words such as "password" (for example "we will never ask for your
   password"). If one of these protective phrases is present we do not treat a
   bare mention as a request. */
PA.util.hasExemption = function (text, list) {
  return PA.util.findPhrases(text, list).length > 0;
};

/* Maker for keyword rules -- saves repeating the same ten lines 30 times. */
PA.util.keywordRule = function (spec) {
  return {
    id: spec.id,
    category: spec.category,
    title: spec.title,
    points: spec.points,
    why: spec.why,
    needs: 'body',
    tags: spec.tags || [],
    test: function (ctx) {
      var found = spec.wholeWords
        ? PA.util.findWords(ctx.lower, spec.phrases)
        : PA.util.findPhrases(ctx.lower, spec.phrases);
      if (spec.exempt && found.length && PA.util.hasExemption(ctx.lower, spec.exempt)) {
        return PA.util.miss();
      }
      return PA.util.phraseResult(found, spec.label);
    }
  };
};

/* =========================================================================
 * THE RULES
 * ====================================================================== */
PA.rules = [];

/* --------------------------------------------------------------------------
 * Group 1: urgency and pressure
 * ----------------------------------------------------------------------- */
PA.rules[PA.rules.length] = PA.util.keywordRule({
  id: 'urgency_language',
  category: 'Urgency & pressure',
  title: 'Urgency and pressure language',
  points: 12,
  why: 'Attackers push you to act fast so that you do not pause to check the message.',
  tags: ['urgency'],
  label: 'Pressure wording',
  phrases: [
    'urgent', 'immediately', 'act now', 'right away', 'as soon as possible',
    'time-sensitive', 'time sensitive', 'final notice', 'last chance',
    'do not delay', "don't delay", 'prompt attention', 'immediate action',
    'act fast', 'without delay'
  ]
});

PA.rules[PA.rules.length] = PA.util.keywordRule({
  id: 'deadline_pressure',
  category: 'Urgency & pressure',
  title: 'A very short deadline',
  points: 10,
  why: 'A countdown is a classic way to rush you past your own good judgement.',
  tags: ['urgency'],
  label: 'Deadline wording',
  phrases: [
    'within 24 hours', 'within 48 hours', 'within 12 hours',
    'within the next 24 hours', 'in the next 24 hours', 'within 1 hour',
    'within one hour', 'within two hours', 'before midnight', 'by end of day',
    'end of business today', 'expires in', 'expires today', 'expires within',
    'last warning'
  ]
});

/* --------------------------------------------------------------------------
 * Group 2: threats and intimidation
 * ----------------------------------------------------------------------- */
PA.rules[PA.rules.length] = PA.util.keywordRule({
  id: 'account_threat',
  category: 'Threats & intimidation',
  title: 'Threat of account suspension or closure',
  points: 20,
  why: 'Fear of losing access is designed to make you click without thinking.',
  tags: ['threat'],
  label: 'Threat wording',
  phrases: [
    'account will be suspended', 'account will be closed',
    'account has been suspended', 'account has been locked',
    'account will be deactivated', 'account will be terminated',
    'suspend your account', 'close your account', 'permanently closed',
    'permanently deleted', 'access will be revoked', 'your account will be',
    'avoid suspension', 'account closure', 'temporarily locked',
    'temporarily suspended', 'limited access to your account',
    'we have locked your account', 'mailbox will be closed',
    'mailbox is full', 'services will be discontinued'
  ]
});

PA.rules[PA.rules.length] = PA.util.keywordRule({
  id: 'consequence_language',
  category: 'Threats & intimidation',
  title: 'Stated consequences for not complying',
  points: 12,
  why: 'Spelling out a punishment is a social-engineering tactic, not normal support wording.',
  tags: ['threat', 'urgency'],
  label: 'Consequence wording',
  phrases: [
    'failure to comply', 'failure to verify', 'failure to confirm',
    'otherwise your account', 'or your account will', 'legal action',
    'further action will be taken', 'loss of access', 'will result in',
    'may result in the closure', 'your data will be deleted'
  ]
});

/* --------------------------------------------------------------------------
 * Group 3: credential theft
 * ----------------------------------------------------------------------- */
PA.rules[PA.rules.length] = PA.util.keywordRule({
  id: 'password_request',
  category: 'Credential theft',
  title: 'Asks you to enter or hand over a password',
  points: 30,
  why: 'No legitimate organisation asks for your password by email, ever.',
  tags: ['credentials'],
  label: 'Password request',
  exempt: [
    'never ask for your password', 'never ask you for your password',
    'never ask for your password by email', 'do not share your password',
    "don't share your password", 'never share your password',
    'we will never ask', 'no one will ever ask'
  ],
  phrases: [
    'enter your password', 'confirm your password', 'verify your password',
    're-enter your password', 'provide your password', 'supply your password',
    'send your password', 'type your password', 'your password is required',
    'update your password now', 'current password', 'your existing password',
    'reset your password below', 'password you use for'
  ]
});

PA.rules[PA.rules.length] = PA.util.keywordRule({
  id: 'mfa_code_request',
  category: 'Credential theft',
  title: 'Asks for an MFA / one-time verification code',
  points: 30,
  why: 'Sharing a one-time code defeats multi-factor authentication -- the code is the key to your account.',
  tags: ['credentials'],
  label: 'Verification-code request',
  phrases: [
    'verification code', 'one-time code', 'one time code',
    'one-time passcode', 'one-time password', '2fa code', 'two-factor code',
    'mfa code', 'authentication code', 'security code', 'code we sent',
    'code we just sent', 'enter the code', 'reply with the code',
    'share the code', '6-digit code', 'six-digit code', 'passcode we sent'
  ]
});

PA.rules[PA.rules.length] = PA.util.keywordRule({
  id: 'otp_token_request',
  category: 'Credential theft',
  title: 'Requests an OTP, token or authenticator value',
  points: 18,
  why: 'Asking for a one-time passcode or authenticator value in an email is a hallmark of account-takeover attempts.',
  tags: ['credentials'],
  label: 'Token wording',
  phrases: [
    'your otp', 'share your otp', 'send your otp', 'provide the otp',
    'enter the otp', 'otp code', 'send the token', 'send us the token',
    'token below', 'your authenticator', 'authenticator code',
    'authenticator app code', 'read the code to me', 'dictate the code',
    'approve the sign-in request', 'approve the login request'
  ]
});

PA.rules[PA.rules.length] = PA.util.keywordRule({
  id: 'credential_harvesting',
  category: 'Credential theft',
  title: 'Classic credential-harvesting wording',
  points: 25,
  why: 'These phrases exist to walk you onto a fake login page that captures whatever you type.',
  tags: ['credentials'],
  label: 'Harvesting wording',
  phrases: [
    'verify your identity', 'confirm your identity', 'validate your account',
    'verify your account', 'confirm your account', 'confirm your details',
    'update your information', 'update your details', 're-authenticate',
    'reauthenticate', 'restore access', 'reactivate your account',
    're-activate your account', 'confirm your information',
    'validate your details', 'keep your account active'
  ]
});

PA.rules[PA.rules.length] = PA.util.keywordRule({
  id: 'login_link_language',
  category: 'Credential theft',
  title: 'Invites you to click through to a sign-in page',
  points: 12,
  why: 'Steering you to a login page by link is how most email credentials are stolen.',
  tags: ['credentials', 'links'],
  label: 'Sign-in wording',
  phrases: [
    'click here to sign in', 'click below to sign in', 'log in to restore',
    'sign in to confirm', 'click the link below', 'click the button below',
    'follow the link below', 'click here to verify', 'login to continue',
    'sign in to continue', 'click here to restore', 'sign in here'
  ]
});

/* --------------------------------------------------------------------------
 * Group 4: money, payments and business email compromise (BEC)
 * ----------------------------------------------------------------------- */
PA.rules[PA.rules.length] = PA.util.keywordRule({
  id: 'gift_card_request',
  category: 'Money & payments',
  title: 'Gift-card payment request',
  points: 30,
  why: 'Gift cards are untraceable and irreversible, which is exactly why criminals ask for them.',
  tags: ['payment'],
  label: 'Gift-card wording',
  phrases: [
    'gift card', 'gift cards', 'itunes card', 'itunes voucher',
    'google play card', 'amazon gift card', 'steam card', 'vanilla card',
    'prepaid card', 'scratch the back', 'scratch off the back',
    'redeem the code', 'itunes gift', 'apple gift card', 'e-gift'
  ]
});

PA.rules[PA.rules.length] = PA.util.keywordRule({
  id: 'payment_request',
  category: 'Money & payments',
  title: 'Requests a payment or transfer',
  points: 18,
  why: 'Payment requests are the payoff for most invoice and BEC scams.',
  tags: ['payment'],
  label: 'Payment wording',
  phrases: [
    'wire transfer', 'bank transfer', 'make a payment', 'pay now',
    'payment of', 'outstanding balance', 'process a payment', 'remit payment',
    'send the funds', 'transfer the funds', 'payment link', 'pay immediately',
    'make the payment'
  ]
});

PA.rules[PA.rules.length] = PA.util.keywordRule({
  id: 'bank_details_change',
  category: 'Money & payments',
  title: 'Asks you to change bank details or pay a new account',
  points: 28,
  why: 'Redirecting a payment to a new account is the core of invoice fraud -- always confirm by phone on a known number.',
  tags: ['payment'],
  label: 'Bank-change wording',
  phrases: [
    'update your bank details', 'change of bank', 'changed our bank account',
    'new bank account details', 'updated bank details',
    'revised payment instructions', 'new payment instructions',
    'updated remittance', 'change our account number',
    'our account details have changed', 'new account number',
    'new bank details', 'use our new account', 'updated banking details',
    'standing order details have changed'
  ]
});

PA.rules[PA.rules.length] = PA.util.keywordRule({
  id: 'crypto_request',
  category: 'Money & payments',
  title: 'Cryptocurrency payment request',
  points: 20,
  why: 'Crypto payments cannot be reversed, so they are heavily favoured by fraudsters.',
  tags: ['payment'],
  label: 'Crypto wording',
  phrases: [
    'bitcoin', 'cryptocurrency', 'crypto wallet', 'wallet address',
    'usdt', 'ethereum', 'btc wallet', 'pay in crypto', 'crypto payment'
  ]
});

PA.rules[PA.rules.length] = PA.util.keywordRule({
  id: 'secrecy_request',
  category: 'Money & payments',
  title: 'Asks you to keep the message secret',
  points: 15,
  why: 'Genuine business requests do not need to be hidden from colleagues or your finance team.',
  tags: ['payment', 'urgency'],
  label: 'Secrecy wording',
  phrases: [
    'keep this confidential', 'keep it confidential', 'do not discuss',
    "don't discuss", 'between us', 'do not inform', "don't tell anyone",
    'keep this between', 'strictly confidential', 'do not mention this',
    'do not call', "don't call me", 'no need to call'
  ]
});

PA.rules[PA.rules.length] = PA.util.keywordRule({
  id: 'bec_quick_favour',
  category: 'Money & payments',
  title: 'The "quick favour from the boss" pattern (BEC)',
  points: 18,
  why: 'Business email compromise usually starts with a short, oddly informal message that claims to come from a senior colleague.',
  tags: ['payment'],
  label: 'BEC wording',
  phrases: [
    'are you available', 'are you at your desk', 'quick favour', 'quick favor',
    'need a favour', 'need a favor', 'i need you to', 'i am in a meeting',
    "i'm in a meeting", 'are you online', 'are you at your computer',
    'can you do something for me', 'i need a small favour'
  ]
});

PA.rules[PA.rules.length] = PA.util.keywordRule({
  id: 'unexpected_invoice',
  category: 'Money & payments',
  title: 'Unexpected invoice or remittance wording',
  points: 18,
  why: 'A surprise invoice is one of the most common ways to trigger a fraudulent payment.',
  tags: ['payment', 'attachment'],
  label: 'Invoice wording',
  phrases: [
    'please find attached invoice', 'attached is the invoice',
    'attached invoice', 'invoice attached', 'outstanding invoice',
    'overdue invoice', 'unpaid invoice', 'invoice is overdue',
    'remittance advice', 'pro forma invoice', 'final demand',
    'your invoice is ready', 'view your invoice', 'payment is due',
    'new invoice attached', 'revised invoice'
  ]
});

/* --------------------------------------------------------------------------
 * Group 5: impersonation and social engineering
 * ----------------------------------------------------------------------- */
PA.rules[PA.rules.length] = PA.util.keywordRule({
  id: 'generic_greeting',
  category: 'Impersonation',
  title: 'Generic greeting instead of your name',
  points: 8,
  why: 'A supplier, bank or employer that knows you will normally use your name, not "Dear Customer".',
  tags: ['impersonation'],
  label: 'Generic greeting',
  phrases: [
    'dear customer', 'dear user', 'dear valued customer', 'dear account holder',
    'dear client', 'dear sir/madam', 'dear sir or madam', 'dear member',
    'dear shopper', 'dear winner', 'dear account user', 'dear email user',
    'dear apple customer', 'dear microsoft customer'
  ]
});

PA.rules[PA.rules.length] = PA.util.keywordRule({
  id: 'impersonation_language',
  category: 'Impersonation',
  title: 'Claims to have spotted a problem on your account',
  points: 15,
  why: 'The "we noticed something suspicious" opening is the standard hook for fake security alerts.',
  tags: ['impersonation'],
  label: 'Alert wording',
  phrases: [
    'we have detected', 'we have noticed', 'unusual sign-in activity',
    'unusual activity on your account', 'unusual login', 'unusual sign in',
    'suspicious activity on your account', 'our records show',
    'we were unable to verify', 'unable to verify your', 'on behalf of',
    'official notification', 'this is an automated message',
    'your account has been flagged', 'we have temporarily limited',
    'security alert', 'we attempted to contact you', 'we detected a login',
    'a new sign-in from', 'unrecognised device', 'unrecognized device'
  ]
});

PA.rules[PA.rules.length] = PA.util.keywordRule({
  id: 'authority_impersonation',
  category: 'Impersonation',
  title: 'Poses as an IT, security, helpdesk or billing team',
  points: 12,
  why: 'Pretending to be "IT support" or "the security team" borrows an authority you are trained to obey.',
  tags: ['impersonation'],
  label: 'Authority wording',
  phrases: [
    'microsoft account team', 'account team', 'security team', 'it support',
    'it department', 'helpdesk', 'help desk', 'service desk', 'support team',
    'billing department', 'paypal security', 'microsoft support',
    'apple support', 'amazon security', 'bank security team',
    'fraud department', 'windows defender team', 'email administrator',
    'system administrator', 'your administrator', 'microsoft 365 team',
    'office 365 team', 'password reset team'
  ]
});

PA.rules[PA.rules.length] = PA.util.keywordRule({
  id: 'prize_bait',
  category: 'Social engineering',
  title: 'Prize, reward or too-good-to-be-true bait',
  points: 20,
  why: 'Offers of an unexpected prize or reward are used to make you click before you think.',
  tags: ['impersonation'],
  label: 'Bait wording',
  phrases: [
    'you have won', 'you have been selected', 'claim your prize',
    'claim your reward', 'you are a winner', 'congratulations you',
    'lottery', 'prize draw', 'free gift', 'exclusive reward', 'claim now',
    'claim your refund', 'you are eligible for a refund',
    'tax refund is ready', 'unclaimed funds'
  ]
});

PA.rules[PA.rules.length] = PA.util.keywordRule({
  id: 'threat_to_contact',
  category: 'Social engineering',
  title: 'Invites you to phone an unverified number',
  points: 15,
  why: 'A phone number inside a suspicious email may connect you to the attacker, not the real organisation.',
  tags: ['impersonation'],
  label: 'Callback wording',
  phrases: [
    'call this number immediately', 'call us on the number below',
    'contact our helpline', 'call the number below',
    'call our support line', 'call us to verify', 'phone us to confirm',
    'helpline number below'
  ]
});

/* --------------------------------------------------------------------------
 * Group 6: document and macro attacks
 * ----------------------------------------------------------------------- */
PA.rules[PA.rules.length] = PA.util.keywordRule({
  id: 'enable_macros',
  category: 'Attachments & macros',
  title: 'Instructs you to enable macros or editing',
  points: 30,
  why: 'Enabling macros lets a document run code, which is how a very large amount of malware starts.',
  tags: ['attachment'],
  label: 'Macro instruction',
  phrases: [
    'enable macros', 'enable editing', 'enable content', 'click enable content',
    'allow macros', 'turn on macros', 'click enable macros',
    'enable the macros', 'click enable editing', 'macro must be enabled',
    'document is protected', 'protected view'
  ]
});

/* --------------------------------------------------------------------------
 * Group 7: writing-style tells (custom tests rather than keyword lists)
 * ----------------------------------------------------------------------- */

PA.rules[PA.rules.length] = {
  id: 'odd_phrasing',
  category: 'Writing style',
  title: 'Unusual or over-formal phrasing',
  points: 8,
  why: 'Phishing messages are often written in a stiff, translated-sounding style that does not match normal business email.',
  needs: 'body',
  tags: ['impersonation'],
  test: function (ctx) {
    var found = PA.util.findPhrases(ctx.lower, [
      'kindly', 'do the needful', 'revert back', 'your earliest convenience',
      'as per your', 'please be informed',
      'we apologize for any inconvenience',
      'we apologise for any inconvenience', 'at your earliest',
      'herewith', 'aforementioned'
    ]);
    return PA.util.phraseResult(found, 'Phrasing', 4);
  }
};

PA.rules[PA.rules.length] = {
  id: 'exclamation_shouting',
  category: 'Writing style',
  title: 'Shouting: repeated exclamation marks or a capitalised subject',
  points: 6,
  why: 'Excessive emphasis is a marketing-style pressure tactic that professional senders rarely use.',
  needs: 'body',
  tags: ['urgency'],
  test: function (ctx) {
    var bangs = (ctx.text.match(/!/g) || []).length;
    var ev = [];
    if (bangs >= 3) { ev[ev.length] = bangs + ' exclamation marks in the message body'; }
    if (ctx.subject && ctx.subject.length > 8 &&
        ctx.subject === ctx.subject.toUpperCase() && /[A-Z]/.test(ctx.subject)) {
      ev[ev.length] = 'The subject line is in block capitals: "' + ctx.subject + '"';
    }
    if (!ev.length) { return PA.util.miss(); }
    return PA.util.hit(ev);
  }
};

PA.rules[PA.rules.length] = {
  id: 'html_password_form',
  category: 'Credential theft',
  title: 'Contains an embedded web form (possible fake login page)',
  points: 25,
  why: 'A login form embedded directly in an email is a strong sign the message is trying to capture what you type.',
  needs: 'body',
  tags: ['credentials'],
  test: function (ctx) {
    var raw = ctx.text;
    var ev = [];
    if (/<input[^>]+type\s*=\s*["']?password/i.test(raw) || /name\s*=\s*["']?password/i.test(raw)) {
      ev[ev.length] = 'The pasted content contains an HTML password entry box';
    }
    if (/<form/i.test(raw)) {
      ev[ev.length] = 'The pasted content contains an HTML <form> element';
    }
    if (!ev.length) { return PA.util.miss(); }
    return PA.util.hit(ev);
  }
};

PA.rules[PA.rules.length] = {
  id: 'hidden_link_target',
  category: 'Suspicious links',
  title: 'Link target is deliberately different from the visible text',
  points: 25,
  why: 'Showing one address and linking to another is deception, and it is one of the most reliable link warning signs.',
  needs: 'links',
  tags: ['links'],
  test: function (ctx) {
    var ev = [];
    for (var i = 0; i < ctx.links.length; i++) {
      var link = ctx.links[i];
      if (!link.text || !link.host) { continue; }
      var textHost = PA.net.domainInText(link.text);
      if (textHost && textHost !== link.host && !PA.net.sameSite(textHost, link.host)) {
        ev[ev.length] = 'Visible text says "' + textHost + '" but the link actually goes to "' + link.host + '"';
      }
    }
    if (!ev.length) { return PA.util.miss(); }
    return PA.util.hit(ev);
  }
};

/* --------------------------------------------------------------------------
 * Group 8: suspicious links
 * The analyser parses every link first and tags it (raw IP, shortener, and so
 * on). These rules simply report those tags, which keeps them easy to read.
 * ----------------------------------------------------------------------- */
PA.rules[PA.rules.length] = {
  id: 'url_raw_ip',
  category: 'Suspicious links',
  title: 'Link uses a raw IP address instead of a domain name',
  points: 20,
  why: 'Reputable organisations publish links using their own domain name, not a bare number such as 192.0.2.1.',
  needs: 'links',
  tags: ['links'],
  test: function (ctx) {
    var ev = [];
    for (var i = 0; i < ctx.links.length; i++) {
      if (ctx.links[i].isIp) {
        ev[ev.length] = 'Link points at the raw IP address ' + ctx.links[i].host;
      }
    }
    return ev.length ? PA.util.hit(ev) : PA.util.miss();
  }
};

PA.rules[PA.rules.length] = {
  id: 'url_shortener',
  category: 'Suspicious links',
  title: 'Link has been shortened to hide its destination',
  points: 18,
  why: 'A shortening service conceals the real destination, so you cannot tell where the link leads.',
  needs: 'links',
  tags: ['links'],
  test: function (ctx) {
    var ev = [];
    for (var i = 0; i < ctx.links.length; i++) {
      if (ctx.links[i].shortener) {
        ev[ev.length] = 'Shortened link: ' + ctx.links[i].host;
      }
    }
    return ev.length ? PA.util.hit(ev) : PA.util.miss();
  }
};

PA.rules[PA.rules.length] = {
  id: 'url_suspicious_tld',
  category: 'Suspicious links',
  title: 'Link uses a domain ending often abused by criminals',
  points: 15,
  why: 'Some low-cost domain endings are heavily over-represented in phishing campaigns.',
  needs: 'links',
  tags: ['links'],
  test: function (ctx) {
    var ev = [];
    for (var i = 0; i < ctx.links.length; i++) {
      if (ctx.links[i].badTld) {
        ev[ev.length] = 'Link domain ' + ctx.links[i].host + ' ends in ".' + ctx.links[i].badTld + '"';
      }
    }
    return ev.length ? PA.util.hit(ev) : PA.util.miss();
  }
};

PA.rules[PA.rules.length] = {
  id: 'url_punycode',
  category: 'Suspicious links',
  title: 'Link uses a punycode (look-alike) domain',
  points: 20,
  why: 'Punycode "xn--" domains can display international characters that closely imitate a real brand in the address bar.',
  needs: 'links',
  tags: ['links'],
  test: function (ctx) {
    var ev = [];
    for (var i = 0; i < ctx.links.length; i++) {
      if (ctx.links[i].punycode) {
        ev[ev.length] = 'Look-alike (punycode) domain: ' + ctx.links[i].host;
      }
    }
    return ev.length ? PA.util.hit(ev) : PA.util.miss();
  }
};

PA.rules[PA.rules.length] = {
  id: 'url_userinfo_trick',
  category: 'Suspicious links',
  title: 'Link hides its real destination with an "@" character',
  points: 18,
  why: 'Everything before the "@" in a URL is ignored by the browser, so the visible part can be a decoy such as a brand name.',
  needs: 'links',
  tags: ['links'],
  test: function (ctx) {
    var ev = [];
    for (var i = 0; i < ctx.links.length; i++) {
      if (ctx.links[i].hasAt) {
        ev[ev.length] = 'Link contains "@" before the host: ' + ctx.links[i].href;
      }
    }
    return ev.length ? PA.util.hit(ev) : PA.util.miss();
  }
};

PA.rules[PA.rules.length] = {
  id: 'url_brand_mismatch',
  category: 'Suspicious links',
  title: 'Brand name appears in the link but the real domain belongs to someone else',
  points: 20,
  why: 'Attackers put a famous name in a subdomain or a hyphenated domain so the link looks official at a glance.',
  needs: 'links',
  tags: ['links', 'impersonation'],
  test: function (ctx) {
    var ev = [];
    for (var i = 0; i < ctx.links.length; i++) {
      var link = ctx.links[i];
      if (link.brandMismatch) {
        ev[ev.length] = 'Link mentions "' + link.brandMismatch + '" but is registered at "' + link.registrable + '"';
      }
    }
    return ev.length ? PA.util.hit(ev) : PA.util.miss();
  }
};

PA.rules[PA.rules.length] = {
  id: 'url_typosquat',
  category: 'Suspicious links',
  title: 'Domain name is a deliberate misspelling of a known brand',
  points: 18,
  why: 'Changing one letter or swapping a letter for a digit ("rn" for "m", "1" for "l") is a classic impersonation trick.',
  needs: 'links',
  tags: ['links', 'impersonation'],
  test: function (ctx) {
    var ev = [];
    for (var i = 0; i < ctx.links.length; i++) {
      if (ctx.links[i].typosquat) {
        ev[ev.length] = 'Domain "' + ctx.links[i].host + '" resembles the brand "' + ctx.links[i].typosquat + '"';
      }
    }
    return ev.length ? PA.util.hit(ev) : PA.util.miss();
  }
};

PA.rules[PA.rules.length] = {
  id: 'url_many_subdomains',
  category: 'Suspicious links',
  title: 'Link uses a long chain of subdomains',
  points: 10,
  why: 'Padding a link with many subdomains is used to hide the real domain at the end of a long address.',
  needs: 'links',
  tags: ['links'],
  test: function (ctx) {
    var ev = [];
    for (var i = 0; i < ctx.links.length; i++) {
      if (ctx.links[i].labelCount >= 4) {
        ev[ev.length] = 'Link host has ' + ctx.links[i].labelCount + ' name parts: ' + ctx.links[i].host;
      }
    }
    return ev.length ? PA.util.hit(ev) : PA.util.miss();
  }
};

PA.rules[PA.rules.length] = {
  id: 'url_insecure_http',
  category: 'Suspicious links',
  title: 'Link uses unencrypted http:// instead of https://',
  points: 8,
  why: 'Traffic to an http:// page is not encrypted and can be modified or captured in transit.',
  needs: 'links',
  tags: ['links'],
  test: function (ctx) {
    var ev = [];
    for (var i = 0; i < ctx.links.length; i++) {
      if (ctx.links[i].insecure) {
        ev[ev.length] = 'Unencrypted link: ' + ctx.links[i].href;
      }
    }
    return ev.length ? PA.util.hit(ev) : PA.util.miss();
  }
};

/* --------------------------------------------------------------------------
 * Group 9: attachments
 * The analyser collects filenames mentioned in the body text and in the
 * Content-Disposition headers, then classifies each extension.
 * ----------------------------------------------------------------------- */
PA.rules[PA.rules.length] = {
  id: 'exec_attachment',
  category: 'Attachments & macros',
  title: 'Executable or script attachment',
  points: 30,
  why: 'Programs and scripts that arrive by email are one of the most common ways to install malware.',
  needs: 'attachments',
  tags: ['attachment'],
  test: function (ctx) {
    var ev = [];
    for (var i = 0; i < ctx.attachments.length; i++) {
      var a = ctx.attachments[i];
      if (a.kind === 'executable') {
        ev[ev.length] = 'Attachment "' + a.name + '" is a ' + a.ext.toUpperCase() + ' file (a program, not a document)';
      }
    }
    return ev.length ? PA.util.hit(ev) : PA.util.miss();
  }
};

PA.rules[PA.rules.length] = {
  id: 'macro_attachment',
  category: 'Attachments & macros',
  title: 'Macro-enabled Office document',
  points: 28,
  why: 'Formats such as .docm, .xlsm and .pptm can carry macros, so they can run code when opened.',
  needs: 'attachments',
  tags: ['attachment'],
  test: function (ctx) {
    var ev = [];
    for (var i = 0; i < ctx.attachments.length; i++) {
      var a = ctx.attachments[i];
      if (a.kind === 'macro-document') {
        ev[ev.length] = 'Attachment "' + a.name + '" is macro-enabled (' + a.ext.toUpperCase() + ')';
      }
    }
    return ev.length ? PA.util.hit(ev) : PA.util.miss();
  }
};

PA.rules[PA.rules.length] = {
  id: 'archive_attachment',
  category: 'Attachments & macros',
  title: 'Compressed archive attachment',
  points: 12,
  why: 'Archives hide their true contents and are often password-protected to slip past email filters.',
  needs: 'attachments',
  tags: ['attachment'],
  test: function (ctx) {
    var ev = [];
    for (var i = 0; i < ctx.attachments.length; i++) {
      var a = ctx.attachments[i];
      if (a.kind === 'archive') {
        ev[ev.length] = 'Attachment "' + a.name + '" is a compressed archive (' + a.ext.toUpperCase() + ')';
      }
    }
    return ev.length ? PA.util.hit(ev) : PA.util.miss();
  }
};

PA.rules[PA.rules.length] = {
  id: 'double_extension',
  category: 'Attachments & macros',
  title: 'Double file extension hides a program behind a document icon',
  points: 28,
  why: 'A name such as "invoice.pdf.exe" looks like a PDF but is really an executable program.',
  needs: 'attachments',
  tags: ['attachment'],
  test: function (ctx) {
    var ev = [];
    for (var i = 0; i < ctx.attachments.length; i++) {
      var a = ctx.attachments[i];
      if (a.doubleExtension) {
        ev[ev.length] = 'Attachment "' + a.name + '" has a double extension';
      }
    }
    return ev.length ? PA.util.hit(ev) : PA.util.miss();
  }
};

PA.rules[PA.rules.length] = {
  id: 'unusual_attachment',
  category: 'Attachments & macros',
  title: 'Unusual attachment type for an email',
  points: 12,
  why: 'Some file types are rarely sent by legitimate businesses because they can be opened as web content instead of as a safe document.',
  needs: 'attachments',
  tags: ['attachment'],
  test: function (ctx) {
    var ev = [];
    for (var i = 0; i < ctx.attachments.length; i++) {
      var a = ctx.attachments[i];
      if (a.kind === 'unusual') {
        ev[ev.length] = 'Attachment "' + a.name + '" is an unusual type for email (' + a.ext.toUpperCase() + ')';
      }
    }
    return ev.length ? PA.util.hit(ev) : PA.util.miss();
  }
};

/* --------------------------------------------------------------------------
 * End of the body rules. Header-based rules live in js/headers.js so that the
 * "headers are optional" logic stays in one place.
 * ----------------------------------------------------------------------- */
