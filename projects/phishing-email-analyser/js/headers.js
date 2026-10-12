/* ==========================================================================
 * headers.js -- optional raw email header parsing plus the header-based rules
 * --------------------------------------------------------------------------
 * Raw headers are entirely optional. If the user pastes only the body, every
 * rule in this file is reported as "not checked" rather than "passed", so the
 * tool never gives false reassurance.
 *
 * Headers are treated as untrusted text: they are only ever read, never
 * executed, and the classic From / Reply-To / SPF / DKIM / DMARC facts are
 * pulled out with simple, readable patterns.
 * ========================================================================== */

window.PA = window.PA || {};
var PA = window.PA;

/* ============================== parsing ================================= */

/* Header names we recognise, used to decide whether the pasted text really
   looks like a header block. */
PA.knownHeaderNames = [
  'from', 'to', 'cc', 'bcc', 'subject', 'date', 'reply-to', 'return-path',
  'received', 'authentication-results', 'arc-authentication-results',
  'received-spf', 'dkim-signature', 'message-id', 'content-type',
  'content-disposition', 'mime-version', 'x-mailer', 'delivered-to',
  'sender', 'envelope-to', 'list-unsubscribe', 'x-originating-ip'
];

/* Turn raw pasted text into a list of { name, value } fields, unfolding any
   continuation lines that some clients insert. */
PA.parseHeaderFields = function (raw) {
  var src = String(raw || '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  var blank = src.indexOf('\n\n');
  if (blank !== -1) { src = src.substring(0, blank); }
  var lines = src.split('\n');
  var fields = [];
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    if (/^[ \t]/.test(line)) {
      if (fields.length) {
        fields[fields.length - 1].value += ' ' + PA.util.trim(line);
      }
      continue;
    }
    var m = line.match(/^([^:\s]{2,60})\s*:\s*([\s\S]*)$/);
    if (m) {
      fields[fields.length] = { name: m[1].toLowerCase(), value: PA.util.trim(m[2]) };
    }
  }
  return fields;
};

/* Pull one e-mail address (plus the display name) out of a header value. */
PA.parseAddress = function (value) {
  var v = PA.util.trim(value);
  var display = '';
  var address = '';
  var lt = v.indexOf('<');
  if (lt !== -1 && v.indexOf('>', lt) !== -1) {
    address = PA.util.trim(v.substring(lt + 1, v.indexOf('>', lt)));
    display = PA.util.trim(v.substring(0, lt));
  } else {
    address = v;
  }
  display = display.replace(/^["']/, '').replace(/["']$/, '');
  var at = address.lastIndexOf('@');
  var domain = '';
  if (at !== -1) { domain = address.substring(at + 1); }
  domain = domain.replace(/[>\s;,)]+$/, '').toLowerCase();
  address = address.replace(/[>\s;,)]+$/, '');
  return {
    raw: v,
    display: display,
    address: address.toLowerCase(),
    domain: domain
  };
};

/* Rank authentication outcomes so that the worst one wins when a message
   passes through several servers. */
PA.authRank = function (value) {
  var ranks = {
    pass: 0, none: 1, unknown: 1, neutral: 2, temperror: 3, temperr: 3,
    softfail: 4, permerror: 5, permerr: 5, fail: 6
  };
  return ranks[value] == null ? 1 : ranks[value];
};

PA.worstAuth = function (a, b) {
  if (!a) { return b; }
  if (!b) { return a; }
  return PA.authRank(b) > PA.authRank(a) ? b : a;
};

/* Find every "spf=..." style token in one Authentication-Results value. */
PA.collectAuthTokens = function (text, name, current) {
  var re = new RegExp('(?:^|[;,\\s(])' + name + '\\s*=\\s*([a-z]+)', 'gi');
  var m;
  var result = current;
  while ((m = re.exec(text)) !== null) {
    result = PA.worstAuth(result, m[1].toLowerCase());
  }
  return result;
};

/* Extract SPF / DKIM / DMARC results and attachment filenames from the
   header fields. */
PA.analyseHeaderFields = function (fields) {
  var out = {
    spf: '', dkim: '', dmarc: '',
    authRaw: [],
    hasDkimSignature: false,
    filenames: []
  };
  for (var i = 0; i < fields.length; i++) {
    var name = fields[i].name;
    var value = fields[i].value;
    if (name === 'authentication-results' ||
        name === 'arc-authentication-results' ||
        name === 'x-authentication-results') {
      out.authRaw[out.authRaw.length] = value;
      out.spf = PA.collectAuthTokens(value, 'spf', out.spf);
      out.dkim = PA.collectAuthTokens(value, 'dkim', out.dkim);
      out.dmarc = PA.collectAuthTokens(value, 'dmarc', out.dmarc);
    } else if (name === 'received-spf') {
      var m = value.match(/^\s*([a-z]+)/i);
      if (m) { out.spf = PA.worstAuth(out.spf, m[1].toLowerCase()); }
    } else if (name === 'dkim-signature') {
      out.hasDkimSignature = true;
    }
    var fn = value.match(/filename\*?=\s*"?([^";\r\n]+)"?/i);
    if (fn) { out.filenames[out.filenames.length] = fn[1]; }
  }
  return out;
};

/* A short, factual summary shown on the results screen even when nothing is
   wrong, so the reader can see what was actually inspected. */
PA.authLabel = function (value) {
  if (!value) { return 'not stated in the headers'; }
  var words = {
    pass: 'pass', fail: 'FAIL', softfail: 'softfail', neutral: 'neutral',
    none: 'none stated', unknown: 'unknown', temperror: 'temporary error',
    permerror: 'permanent error'
  };
  return words[value] || value;
};

/* Top-level entry point. Returns a description of the message headers, or
   { present: false } when the pasted text is not a header block. */
PA.parseHeaders = function (raw) {
  var text = PA.util.trim(raw);
  if (!text) { return { present: false, reason: 'empty' }; }

  var fields = PA.parseHeaderFields(text);
  var i, j, found = 0;
  for (i = 0; i < fields.length; i++) {
    for (j = 0; j < PA.knownHeaderNames.length; j++) {
      if (fields[i].name === PA.knownHeaderNames[j]) { found++; break; }
    }
  }
  if (!found) { return { present: false, reason: 'unrecognised' }; }

  function firstValue(wanted) {
    for (var k = 0; k < fields.length; k++) {
      if (fields[k].name === wanted) { return fields[k].value; }
    }
    return '';
  }

  var receivedCount = 0;
  for (i = 0; i < fields.length; i++) {
    if (fields[i].name === 'received') { receivedCount++; }
  }

  var auth = PA.analyseHeaderFields(fields);

  return {
    present: true,
    fieldCount: fields.length,
    from: PA.parseAddress(firstValue('from')),
    replyTo: PA.parseAddress(firstValue('reply-to')),
    returnPath: PA.parseAddress(firstValue('return-path')),
    sender: PA.parseAddress(firstValue('sender')),
    to: PA.parseAddress(firstValue('to')),
    subject: firstValue('subject'),
    date: firstValue('date'),
    receivedCount: receivedCount,
    spf: auth.spf,
    dkim: auth.dkim,
    dmarc: auth.dmarc,
    authRaw: auth.authRaw,
    hasDkimSignature: auth.hasDkimSignature,
    filenames: auth.filenames
  };
};

/* A plain-language description of the authentication results, used on screen. */
PA.headerSummary = function (h) {
  var rows = [];
  if (h.from && h.from.address) { rows[rows.length] = { label: 'From', value: h.from.raw }; }
  if (h.replyTo && h.replyTo.address) { rows[rows.length] = { label: 'Reply-To', value: h.replyTo.raw }; }
  if (h.returnPath && h.returnPath.address) { rows[rows.length] = { label: 'Return-Path', value: h.returnPath.raw }; }
  rows[rows.length] = { label: 'SPF', value: PA.authLabel(h.spf) };
  rows[rows.length] = { label: 'DKIM', value: PA.authLabel(h.dkim) };
  rows[rows.length] = { label: 'DMARC', value: PA.authLabel(h.dmarc) };
  if (h.receivedCount) {
    rows[rows.length] = { label: 'Received hops', value: String(h.receivedCount) };
  }
  return rows;
};

/* =========================================================================
 * THE HEADER RULES
 * Every rule here has needs: 'headers', so the analyser marks them as
 * "not checked" when no raw headers were pasted.
 * ====================================================================== */
PA.headerRules = [];

PA.headerRules[PA.headerRules.length] = {
  id: 'header_spf_fail',
  category: 'Email authentication (headers)',
  title: 'SPF check failed',
  points: 15,
  why: 'SPF records say which servers may send mail for a domain. A failure means the sending server was not authorised for that domain.',
  needs: 'headers',
  tags: ['headers'],
  test: function (ctx) {
    if (ctx.headers.spf !== 'fail') { return PA.util.miss(); }
    return PA.util.hit(['The Authentication-Results header reports "spf=fail"']);
  }
};

PA.headerRules[PA.headerRules.length] = {
  id: 'header_spf_softfail',
  category: 'Email authentication (headers)',
  title: 'SPF check produced a soft fail',
  points: 8,
  why: 'A soft fail means the sender is probably not authorised, but the receiving server was not certain enough to reject the message.',
  needs: 'headers',
  tags: ['headers'],
  test: function (ctx) {
    if (ctx.headers.spf !== 'softfail') { return PA.util.miss(); }
    return PA.util.hit(['The Authentication-Results header reports "spf=softfail"']);
  }
};

PA.headerRules[PA.headerRules.length] = {
  id: 'header_dkim_fail',
  category: 'Email authentication (headers)',
  title: 'DKIM signature did not verify',
  points: 15,
  why: 'DKIM proves the message body has not been altered in transit. A failure means the signature could not be confirmed.',
  needs: 'headers',
  tags: ['headers'],
  test: function (ctx) {
    if (ctx.headers.dkim !== 'fail') { return PA.util.miss(); }
    return PA.util.hit(['The Authentication-Results header reports "dkim=fail"']);
  }
};

PA.headerRules[PA.headerRules.length] = {
  id: 'header_dmarc_fail',
  category: 'Email authentication (headers)',
  title: 'DMARC check failed',
  points: 18,
  why: 'DMARC ties SPF and DKIM back to the visible From domain. A failure is a strong sign that the visible sender address was not really used by that domain.',
  needs: 'headers',
  tags: ['headers'],
  test: function (ctx) {
    if (ctx.headers.dmarc !== 'fail') { return PA.util.miss(); }
    return PA.util.hit(['The Authentication-Results header reports "dmarc=fail"']);
  }
};

PA.headerRules[PA.headerRules.length] = {
  id: 'header_reply_to_mismatch',
  category: 'Email authentication (headers)',
  title: 'Reply-To address is on a different domain from the From address',
  points: 20,
  why: 'Replies would go somewhere else entirely. This is the standard trick used to hijack a conversation.',
  needs: 'headers',
  tags: ['headers'],
  test: function (ctx) {
    var h = ctx.headers;
    if (!h.from.domain || !h.replyTo.domain) { return PA.util.miss(); }
    var fromSite = PA.net.registrableDomain(h.from.domain);
    var replySite = PA.net.registrableDomain(h.replyTo.domain);
    if (fromSite === replySite) { return PA.util.miss(); }
    return PA.util.hit([
      'From is on "' + fromSite + '" but Reply-To is on "' + replySite + '"'
    ]);
  }
};

PA.headerRules[PA.headerRules.length] = {
  id: 'header_return_path_mismatch',
  category: 'Email authentication (headers)',
  title: 'Return-Path (envelope sender) is on a different domain',
  points: 15,
  why: 'The envelope sender records where bounce messages really go. A mismatch with the From domain often points to a spoofed sender.',
  needs: 'headers',
  tags: ['headers'],
  test: function (ctx) {
    var h = ctx.headers;
    if (!h.from.domain || !h.returnPath.domain) { return PA.util.miss(); }
    var fromSite = PA.net.registrableDomain(h.from.domain);
    var pathSite = PA.net.registrableDomain(h.returnPath.domain);
    if (fromSite === pathSite) { return PA.util.miss(); }
    return PA.util.hit([
      'From is on "' + fromSite + '" but Return-Path is on "' + pathSite + '"'
    ]);
  }
};

PA.headerRules[PA.headerRules.length] = {
  id: 'header_display_name_mismatch',
  category: 'Email authentication (headers)',
  title: 'Display name claims a brand that does not match the sending address',
  points: 18,
  why: 'Your mail app shows the friendly name by default and hides the address, so a false name is an effective disguise.',
  needs: 'headers',
  tags: ['headers', 'impersonation'],
  test: function (ctx) {
    var h = ctx.headers;
    if (!h.from.domain || !h.from.display) { return PA.util.miss(); }
    var brand = PA.net.brandInText(h.from.display);
    if (!brand) { return PA.util.miss(); }
    var official = PA.net.officialDomain(brand);
    var actualSite = PA.net.registrableDomain(h.from.domain);
    var officialSite = official ? PA.net.registrableDomain(official) : '';
    if (officialSite && officialSite === actualSite) { return PA.util.miss(); }
    if (!official && actualSite.indexOf(brand) !== -1) { return PA.util.miss(); }
    return PA.util.hit([
      'The display name contains "' + brand + '" but the message was sent from "'
      + h.from.domain + '" (registered at ' + actualSite + ')'
    ]);
  }
};

PA.headerRules[PA.headerRules.length] = {
  id: 'header_reply_to_freemail',
  category: 'Email authentication (headers)',
  title: 'Replies are directed to a free webmail account',
  points: 10,
  why: 'A corporate message that asks you to reply to a personal webmail address is a common fraud pattern.',
  needs: 'headers',
  tags: ['headers'],
  test: function (ctx) {
    var h = ctx.headers;
    if (!h.replyTo.domain) { return PA.util.miss(); }
    var replySite = PA.net.registrableDomain(h.replyTo.domain);
    if (!PA.net.isFreeMail(replySite)) { return PA.util.miss(); }
    if (h.from.domain && PA.net.isFreeMail(PA.net.registrableDomain(h.from.domain))) {
      return PA.util.miss();
    }
    return PA.util.hit([
      'Reply-To points at the free webmail service "' + replySite + '"'
    ]);
  }
};

PA.headerRules[PA.headerRules.length] = {
  id: 'header_auth_missing',
  category: 'Email authentication (headers)',
  title: 'No passing SPF, DKIM or DMARC result in the headers',
  points: 6,
  why: 'Without a passing authentication result you cannot tell whether the sender was authorised, so treat the message with extra caution.',
  needs: 'headers',
  tags: ['headers'],
  test: function (ctx) {
    var h = ctx.headers;
    var haveAnyPass = h.spf === 'pass' || h.dkim === 'pass' || h.dmarc === 'pass';
    if (haveAnyPass) { return PA.util.miss(); }
    if (!h.spf && !h.dkim && !h.dmarc && !h.hasDkimSignature) {
      return PA.util.hit([
        'No Authentication-Results, Received-SPF or DKIM-Signature header was found'
      ]);
    }
    return PA.util.hit([
      'Authentication results are present but none of them passed (spf='
      + (h.spf || 'none') + ', dkim=' + (h.dkim || 'none')
      + ', dmarc=' + (h.dmarc || 'none') + ')'
    ]);
  }
};
