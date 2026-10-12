/* ==========================================================================
 * analyser.js -- the engine
 * --------------------------------------------------------------------------
 * Responsibilities:
 *   1. Turn the pasted text into a "context" (links, attachments, subject...).
 *   2. Run every rule over that context.
 *   3. Add up the fixed weights, cap at 100 and choose a risk band.
 *   4. Work out the practical "what to do next" advice.
 *
 * Nothing in this file touches the network, the DOM or the file system, which
 * is what makes the privacy claim true and what makes the self-tests possible.
 * ========================================================================== */

window.PA = window.PA || {};
var PA = window.PA;

/* ===================== link and domain helpers =========================== */

PA.net = {};

/* Second-level suffixes, so that "bbc.co.uk" is treated as one site rather
   than two separate labels. */
PA.net.twoPartSuffixes = [
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'net.uk', 'sch.uk',
  'co.nz', 'net.nz', 'org.nz', 'govt.nz', 'ac.nz',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp',
  'co.kr', 'or.kr', 'com.br', 'net.br', 'org.br',
  'com.mx', 'com.ar', 'com.co', 'com.pe', 'com.ve', 'com.ec', 'com.uy',
  'com.tr', 'com.cn', 'com.hk', 'com.sg', 'com.tw', 'com.my', 'com.ph',
  'com.vn', 'com.sa', 'com.eg', 'com.ng', 'com.pk', 'com.bd', 'com.np',
  'co.za', 'org.za', 'co.in', 'net.in', 'org.in', 'gov.in', 'nic.in',
  'co.id', 'or.id', 'go.id', 'ac.id', 'co.th', 'or.th', 'in.th',
  'co.il', 'org.il', 'ac.il', 'gov.il', 'co.ke', 'com.pl', 'com.ua',
  'com.ru', 'co.at', 'or.at', 'ac.at', 'com.es', 'com.pt', 'com.it',
  'co.hu', 'com.hr', 'co.rs', 'com.ro', 'com.gr', 'com.cy', 'com.mt'
];

/* Shortening services. These hide where a link really goes. */
PA.net.shortenerHosts = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
  'rebrand.ly', 'cutt.ly', 'rb.gy', 'shorturl.at', 'tiny.cc', 'lnkd.in',
  't.ly', 'short.gy', 'clck.ru', 'v.gd', 'x.co', 'bit.do', 'qr.ae',
  'bl.ink', 'surl.li', 'shorte.st', 'adf.ly', 'soo.gd', 'urlz.fr'
];

/* Domain endings that appear in phishing campaigns far more often than their
   share of the internet would suggest. */
PA.net.riskyTlds = [
  'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'click', 'link',
  'country', 'kim', 'loan', 'download', 'review', 'stream', 'win', 'bid',
  'date', 'trade', 'racing', 'party', 'men', 'accountant', 'zip', 'mov',
  'buzz', 'cyou', 'monster', 'quest', 'rest', 'sbs', 'support', 'live',
  'icu', 'cam', 'surf', 'bar', 'casa', 'flights', 'host', 'press', 'pw'
];

/* Free webmail providers, used by the Reply-To check. */
PA.net.freeMailDomains = [
  'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com',
  'hotmail.co.uk', 'live.com', 'msn.com', 'yahoo.com', 'yahoo.co.uk',
  'ymail.com', 'aol.com', 'icloud.com', 'me.com', 'mac.com',
  'proton.me', 'protonmail.com', 'gmx.com', 'gmx.de', 'mail.com',
  'zoho.com', 'yandex.com', 'tutanota.com', 'fastmail.com', 'inbox.com'
];

PA.net.collapse = function (word) {
  return String(word).toLowerCase().replace(/[^a-z0-9]/g, '');
};

/* Is this host written as a bare IPv4 address? */
PA.net.isIpv4 = function (host) {
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
};

PA.net.isFreeMail = function (domain) {
  for (var i = 0; i < PA.net.freeMailDomains.length; i++) {
    if (PA.net.freeMailDomains[i] === domain) { return true; }
  }
  return false;
};

/* The "site" (registrable domain) that a hostname really belongs to:
   a.b.example.co.uk -> example.co.uk */
PA.net.registrableDomain = function (host) {
  var h = String(host || '').toLowerCase().replace(/\.$/, '');
  if (!h || PA.net.isIpv4(h)) { return h; }
  var parts = h.split('.');
  if (parts.length <= 2) { return h; }
  var lastTwo = parts[parts.length - 2] + '.' + parts[parts.length - 1];
  for (var i = 0; i < PA.net.twoPartSuffixes.length; i++) {
    if (PA.net.twoPartSuffixes[i] === lastTwo) {
      return parts[parts.length - 3] + '.' + lastTwo;
    }
  }
  return lastTwo;
};

PA.net.sameSite = function (a, b) {
  return PA.net.registrableDomain(a) === PA.net.registrableDomain(b);
};

/* Does the text contain this token as a distinct word?
   "microsoft-login.example.com" -> yes. "microsofts.com" -> no. */
PA.net.hostContainsToken = function (host, token) {
  if (!host || !token) { return false; }
  var escaped = token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp('(^|[^a-z0-9])' + escaped + '([^a-z0-9]|$)', 'i').test(host);
};

/* ===================== brand data ======================================= */
/* Brands that attackers like to imitate, plus the domain that really belongs
   to the brand where that is unambiguous. */

PA.net.brands = [
  { name: 'microsoft', domain: 'microsoft.com' },
  { name: 'office 365', domain: 'office.com', alias: 'office365' },
  { name: 'outlook', domain: 'outlook.com' },
  { name: 'onedrive', domain: 'onedrive.com' },
  { name: 'sharepoint', domain: 'sharepoint.com' },
  { name: 'paypal', domain: 'paypal.com' },
  { name: 'amazon', domain: 'amazon.com' },
  { name: 'apple', domain: 'apple.com' },
  { name: 'icloud', domain: 'icloud.com' },
  { name: 'google', domain: 'google.com' },
  { name: 'gmail', domain: 'gmail.com' },
  { name: 'netflix', domain: 'netflix.com' },
  { name: 'facebook', domain: 'facebook.com' },
  { name: 'instagram', domain: 'instagram.com' },
  { name: 'linkedin', domain: 'linkedin.com' },
  { name: 'dropbox', domain: 'dropbox.com' },
  { name: 'adobe', domain: 'adobe.com' },
  { name: 'docusign', domain: 'docusign.com' },
  { name: 'dhl', domain: 'dhl.com' },
  { name: 'fedex', domain: 'fedex.com' },
  { name: 'ups', domain: 'ups.com' },
  { name: 'royal mail', domain: 'royalmail.com', alias: 'royalmail' },
  { name: 'hermes', domain: 'hermesworld.com' },
  { name: 'evri', domain: 'evri.com' },
  { name: 'hmrc', domain: 'gov.uk' },
  { name: 'coinbase', domain: 'coinbase.com' },
  { name: 'binance', domain: 'binance.com' },
  { name: 'steam', domain: 'steampowered.com' },
  { name: 'spotify', domain: 'spotify.com' },
  { name: 'zoom', domain: 'zoom.us' },
  { name: 'slack', domain: 'slack.com' },
  { name: 'xbox', domain: 'xbox.com' },
  { name: 'whatsapp', domain: 'whatsapp.com' }
];

/* Which known brand appears in this piece of text (a display name, a link's
   visible wording, a subject line)? Returns the brand name or ''. */
PA.net.brandInText = function (text) {
  var lower = String(text || '').toLowerCase();
  if (!lower) { return ''; }
  for (var i = 0; i < PA.net.brands.length; i++) {
    var b = PA.net.brands[i];
    if (PA.net.hostContainsToken(lower, b.name)) { return b.name; }
    if (b.alias && PA.net.hostContainsToken(lower, b.alias)) { return b.name; }
  }
  return '';
};

PA.net.officialDomain = function (brand) {
  for (var i = 0; i < PA.net.brands.length; i++) {
    if (PA.net.brands[i].name === brand) { return PA.net.brands[i].domain; }
  }
  return '';
};

/* Which brand appears inside this hostname?
   "microsoft-verify.example.com" -> "microsoft" */
PA.net.brandInHost = function (host) {
  var h = String(host || '').toLowerCase();
  if (!h) { return ''; }
  for (var i = 0; i < PA.net.brands.length; i++) {
    var token = PA.net.collapse(PA.net.brands[i].name);
    if (token.length < 5) { continue; }
    if (PA.net.hostContainsToken(h, token)) { return PA.net.brands[i].name; }
  }
  return '';
};

/* Single-character substitutions that make a fake domain look almost right:
   l->1, o->0, i->1, e->3, a->4, s->5, g->9, b->6, plus the classic
   "m"->"rn" and "w"->"vv" tricks. Both whole-word and one-character-at-a-time
   variants are produced, so "micros0ft" as well as "micr0s0ft" is caught. */
PA.net.typoVariants = function (brand) {
  var base = PA.net.collapse(brand);
  if (base.length < 5) { return []; }

  var seen = {};
  var out = [];

  function push(v) {
    if (v && v !== base && !seen[v]) { seen[v] = true; out[out.length] = v; }
  }

  var wholeSwaps = [
    [/l/g, '1'], [/o/g, '0'], [/i/g, '1'], [/e/g, '3'], [/a/g, '4'],
    [/s/g, '5'], [/g/g, '9'], [/b/g, '6'], [/m/g, 'rn'], [/w/g, 'vv'],
    [/i/g, 'l'], [/l/g, 'i']
  ];
  var i;
  for (i = 0; i < wholeSwaps.length; i++) {
    push(base.replace(wholeSwaps[i][0], wholeSwaps[i][1]));
  }

  var charSwaps = {
    l: '1', o: '0', i: '1', e: '3', a: '4', s: '5', g: '9', b: '6',
    t: '7', z: '2', q: '9'
  };
  for (i = 0; i < base.length; i++) {
    var sub = charSwaps[base.charAt(i)];
    if (sub) {
      push(base.substring(0, i) + sub + base.substring(i + 1));
    }
  }
  return out;
};

/* Does a domain look like a deliberate misspelling of a brand?
   Returns the real brand name, or ''. */
PA.net.typosquatInHost = function (host) {
  var h = String(host || '').toLowerCase();
  if (!h) { return ''; }
  for (var i = 0; i < PA.net.brands.length; i++) {
    var brand = PA.net.brands[i];
    var official = brand.domain;
    if (official && PA.net.registrableDomain(h) === PA.net.registrableDomain(official)) {
      continue;
    }
    var variants = PA.net.typoVariants(brand.name);
    for (var j = 0; j < variants.length; j++) {
      if (PA.net.hostContainsToken(h, variants[j])) { return brand.name; }
    }
  }
  return '';
};

/* The first hostname-looking thing in a piece of visible link text, so that
   we can compare "what you see" with "where it goes". */
PA.net.domainInText = function (text) {
  var t = String(text || '');
  var m = t.match(/(?:https?:\/\/)?(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}/i);
  if (!m) { return ''; }
  var host = m[0].toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '');
  return host;
};

/* ===================== link extraction ================================== */

PA.stripTags = function (html) {
  return String(html || '')
    .replace(/<[^>]*>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/\s+/g, ' ');
};

/* Break a URL or hostname down into the facts the link rules need. */
PA.parseUrl = function (href) {
  var raw = PA.util.trim(href);
  var out = {
    href: raw,
    host: '',
    registrable: '',
    labelCount: 0,
    scheme: '',
    isIp: false,
    shortener: false,
    badTld: '',
    punycode: false,
    hasAt: false,
    insecure: false,
    brandMismatch: '',
    typosquat: '',
    text: ''
  };
  if (!raw) { return out; }

  var lower = raw.toLowerCase();
  if (lower.indexOf('mailto:') === 0 || lower.indexOf('tel:') === 0) { return out; }

  var m = lower.match(/^([a-z][a-z0-9+.\-]*):/);
  var rest = lower;
  if (m) {
    out.scheme = m[1];
    rest = lower.substring(m[0].length);
  }
  if (rest.indexOf('//') === 0) { rest = rest.substring(2); }

  var cut = rest.length;
  var stops = ['/', '?', '#'];
  for (var s = 0; s < stops.length; s++) {
    var idx = rest.indexOf(stops[s]);
    if (idx !== -1 && idx < cut) { cut = idx; }
  }
  var authority = rest.substring(0, cut);

  var at = authority.indexOf('@');
  if (at !== -1) {
    out.hasAt = true;
    authority = authority.substring(at + 1);
  }
  var colon = authority.indexOf(':');
  if (colon !== -1) { authority = authority.substring(0, colon); }

  var host = authority.replace(/^www\./, '').replace(/\.$/, '');
  out.host = host;
  if (!host) { return out; }

  out.registrable = PA.net.registrableDomain(host);
  out.labelCount = host.split('.').length;
  out.isIp = PA.net.isIpv4(host);
  out.insecure = out.scheme === 'http';
  out.punycode = host.indexOf('xn--') !== -1;

  for (var i = 0; i < PA.net.shortenerHosts.length; i++) {
    if (PA.net.shortenerHosts[i] === out.registrable) { out.shortener = true; break; }
  }

  var tld = host.split('.');
  if (tld.length > 1) {
    var last = tld[tld.length - 1];
    for (var t = 0; t < PA.net.riskyTlds.length; t++) {
      if (PA.net.riskyTlds[t] === last) { out.badTld = last; break; }
    }
  }

  out.typosquat = PA.net.typosquatInHost(host);

  var brand = PA.net.brandInHost(host);
  if (brand) {
    var official = PA.net.officialDomain(brand);
    var officialSite = official ? PA.net.registrableDomain(official) : '';
    if (!officialSite || officialSite !== out.registrable) {
      out.brandMismatch = brand;
    }
  }
  return out;
};

PA.addLink = function (list, seen, href, label) {
  var clean = PA.util.trim(href);
  if (!clean) { return; }
  var lower = clean.toLowerCase();
  if (lower.indexOf('mailto:') === 0 || lower.indexOf('tel:') === 0) { return; }
  if (clean.charAt(0) === '#') { return; }
  clean = clean.replace(/[.,;:]+$/, '');
  var key = lower.replace(/[.,;:]+$/, '');
  if (seen[key]) { return; }
  seen[key] = true;
  var info = PA.parseUrl(clean);
  info.text = PA.util.trim(PA.stripTags(label || ''));
  list[list.length] = info;
};

/* Fresh regex objects each time, because the "g" flag keeps state. */
PA.anchorPattern = function () {
  return /<a\b[^>]*?href\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>([\s\S]*?)<\/a>/gi;
};

PA.bareUrlPattern = function () {
  return /(?:https?:\/\/|www\.)[^\s<>"'`|]+/gi;
};

/* Pull out every link: HTML <a> tags (which carry the visible text) and any
   bare web address typed as plain text. Web addresses inside a <a> tag are
   skipped on the second pass so that one link is never counted twice. */
PA.extractLinks = function (text) {
  var links = [];
  var seen = {};
  var m, href;

  var anchor = PA.anchorPattern();
  while ((m = anchor.exec(text)) !== null) {
    href = m[1] != null ? m[1] : (m[2] != null ? m[2] : m[3]);
    PA.addLink(links, seen, href, m[4]);
  }

  var withoutAnchors = text.replace(PA.anchorPattern(), ' ');
  var bare = PA.bareUrlPattern();
  while ((m = bare.exec(withoutAnchors)) !== null) {
    PA.addLink(links, seen, m[0], '');
  }
  return links;
};

/* ===================== attachments ====================================== */

PA.attachmentKinds = {
  executable: [
    'exe', 'scr', 'bat', 'cmd', 'pif', 'js', 'jse', 'vbs', 'vbe', 'jar',
    'ps1', 'psm1', 'hta', 'msi', 'msp', 'lnk', 'iso', 'img', 'vhd', 'wsf',
    'wsh', 'cpl', 'reg', 'xll', 'inf', 'sct', 'shb', 'gadget', 'application'
  ],
  'macro-document': [
    'docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'xlam', 'potm', 'xlsb', 'docb'
  ],
  archive: [
    'zip', 'rar', '7z', 'gz', 'tar', 'cab', 'tgz', 'bz2', 'xz', 'ace',
    'arj', 'lzh'
  ],
  unusual: ['html', 'htm', 'mht', 'mhtml', 'svg', 'xml', 'chm', 'xsl', 'xslt', 'url']
};

/* Every extension we are willing to notice, longest first so that "xlsx" is
   matched before "xls". */
PA.knownExtensions = [
  'application', 'mhtml', 'xlsb', 'docm', 'xlsm', 'pptm', 'dotm', 'xltm',
  'xlam', 'potm', 'docb', 'psm1', 'gadget', 'html', 'xlsx', 'pptx', 'docx',
  'jpeg', 'scr', 'bat', 'cmd', 'pif', 'vbs', 'vbe', 'jar', 'ps1', 'hta',
  'msi', 'msp', 'lnk', 'iso', 'img', 'vhd', 'wsf', 'wsh', 'cpl', 'reg',
  'xll', 'inf', 'sct', 'shb', 'exe', 'jse', 'js', 'zip', 'rar', '7z', 'gz',
  'tar', 'cab', 'tgz', 'bz2', 'xz', 'ace', 'arj', 'lzh', 'htm', 'mht',
  'svg', 'xml', 'chm', 'xsl', 'xslt', 'url', 'pdf', 'doc', 'xls', 'ppt',
  'rtf', 'txt', 'csv', 'jpg', 'png', 'gif', 'heic', 'text', 'lnk'
];

PA.extensionPattern = new RegExp(
  '(?:^|[^a-z0-9])([a-z0-9][a-z0-9._\\-]{0,60}\\.(' +
  PA.knownExtensions.join('|') + '))(?:[^a-z0-9]|$)',
  'gi'
);

PA.attachmentKind = function (ext) {
  var e = String(ext || '').toLowerCase();
  var groups = ['executable', 'macro-document', 'archive', 'unusual'];
  for (var g = 0; g < groups.length; g++) {
    var list = PA.attachmentKinds[groups[g]];
    for (var i = 0; i < list.length; i++) {
      if (list[i] === e) { return groups[g]; }
    }
  }
  return 'document';
};

PA.doubleExtensionPattern = /\.(pdf|doc|docx|xls|xlsx|ppt|pptx|jpg|jpeg|png|gif|txt|csv|zip|rtf)\.(exe|scr|bat|cmd|pif|js|vbs|jar|ps1|hta|msi|lnk|iso|img|wsf|wsh|com)$/i;

PA.makeAttachment = function (name) {
  var clean = PA.util.trim(String(name || '').replace(/^["']|["']$/g, ''));
  var dot = clean.lastIndexOf('.');
  var ext = dot === -1 ? '' : clean.substring(dot + 1).toLowerCase();
  return {
    name: clean,
    ext: ext,
    kind: PA.attachmentKind(ext),
    doubleExtension: PA.doubleExtensionPattern.test(clean)
  };
};

/* Collect attachment names from the body text and from the parsed headers. */
PA.extractAttachments = function (text, headers) {
  var out = [];
  var seen = {};
  var m;

  function add(name) {
    var a = PA.makeAttachment(name);
    if (!a.name || !a.ext) { return; }
    var key = a.name.toLowerCase();
    if (seen[key]) { return; }
    seen[key] = true;
    out[out.length] = a;
  }

  /* Scan a cleaned copy of the text so that web addresses and HTML attributes
     are not mistaken for attachment names. */
  var scan = PA.stripTags(text).replace(/(?:https?:\/\/|www\.)[^\s<>"'`|]+/gi, ' ');

  PA.extensionPattern.lastIndex = 0;
  while ((m = PA.extensionPattern.exec(scan)) !== null) {
    add(m[1]);
  }

  if (headers && headers.filenames) {
    for (var i = 0; i < headers.filenames.length; i++) { add(headers.filenames[i]); }
  }
  return out;
};

/* ===================== context ========================================== */

/* If the pasted text starts with a "Subject:" line, treat it as a subject. */
PA.extractSubject = function (text) {
  var m = String(text || '').match(/^[ \t]*subject[ \t]*:[ \t]*(.+)$/im);
  return m ? PA.util.trim(m[1]) : '';
};

PA.buildContext = function (body, rawHeaders) {
  var text = String(body || '');
  var headers = PA.parseHeaders(rawHeaders);
  return {
    text: text,
    lower: text.toLowerCase(),
    subject: PA.extractSubject(text) || (headers.present ? headers.subject : ''),
    links: PA.extractLinks(text),
    attachments: PA.extractAttachments(text, headers.present ? headers : null),
    headers: headers
  };
};

/* ===================== risk bands and severity =========================== */

PA.scoreBands = [
  {
    key: 'low', min: 0, max: 24, label: 'Low Risk', short: 'Low',
    summary: 'Hardly any warning signs were found in what you pasted.'
  },
  {
    key: 'suspicious', min: 25, max: 59, label: 'Suspicious', short: 'Medium',
    summary: 'Several warning signs were found. Verify this message independently before acting on it.'
  },
  {
    key: 'high', min: 60, max: 100, label: 'High Risk', short: 'High',
    summary: 'Many strong warning signs were found. Treat this message as hostile.'
  }
];

PA.bandFor = function (score) {
  for (var i = 0; i < PA.scoreBands.length; i++) {
    if (score >= PA.scoreBands[i].min && score <= PA.scoreBands[i].max) {
      return PA.scoreBands[i];
    }
  }
  return PA.scoreBands[PA.scoreBands.length - 1];
};

PA.severityFor = function (points) {
  if (points >= 25) { return { key: 'critical', label: 'Very strong indicator' }; }
  if (points >= 15) { return { key: 'high', label: 'Strong indicator' }; }
  if (points >= 10) { return { key: 'medium', label: 'Moderate indicator' }; }
  return { key: 'low', label: 'Weak indicator' };
};

PA.verdictText = function (band) {
  if (band.key === 'high') {
    return 'Several strong warning signs are present at the same time. Treat this message as hostile: '
      + 'do not click anything in it, do not reply, do not open attachments and do not send money.';
  }
  if (band.key === 'suspicious') {
    return 'There are real warning signs here. Do not act on the message directly -- verify it first '
      + 'using contact details you already trust.';
  }
  return 'Very little in the text you pasted matches the warning signs this tool checks for. That is '
    + 'mildly reassuring, but it is not proof that the message is genuine: a carefully written attack '
    + 'can contain none of these tells.';
};

/* ===================== the analysis run ================================= */

PA.analyse = function (input) {
  input = input || {};
  var ctx = PA.buildContext(input.body, input.headers);
  var allRules = PA.rules.concat(PA.headerRules);
  var findings = [];
  var notChecked = [];
  var tagSet = {};
  var rawTotal = 0;
  var i, j;

  for (i = 0; i < allRules.length; i++) {
    var rule = allRules[i];
    if ((rule.needs || 'body') === 'headers' && !ctx.headers.present) {
      notChecked[notChecked.length] = {
        id: rule.id, title: rule.title, points: rule.points, category: rule.category
      };
      continue;
    }
    var outcome = null;
    try { outcome = rule.test(ctx); } catch (err) { outcome = null; }
    if (!outcome || !outcome.matched || !outcome.evidence || !outcome.evidence.length) {
      continue;
    }
    rawTotal += rule.points;
    var tags = rule.tags || [];
    for (j = 0; j < tags.length; j++) { tagSet[tags[j]] = true; }
    findings[findings.length] = {
      id: rule.id,
      title: rule.title,
      category: rule.category || 'Other',
      points: rule.points,
      why: rule.why,
      evidence: outcome.evidence,
      tags: tags,
      severity: PA.severityFor(rule.points)
    };
  }

  findings.sort(function (a, b) { return b.points - a.points; });

  var score = rawTotal > 100 ? 100 : rawTotal;
  var band = PA.bandFor(score);

  var result = {
    score: score,
    rawTotal: rawTotal,
    capped: rawTotal > 100,
    band: band,
    verdict: PA.verdictText(band),
    findings: findings,
    tags: tagSet,
    notChecked: notChecked,
    checksRun: allRules.length - notChecked.length,
    checksTotal: allRules.length,
    links: ctx.links,
    attachments: ctx.attachments,
    subject: ctx.subject,
    headersPresent: ctx.headers.present,
    headerFacts: ctx.headers.present ? PA.headerSummary(ctx.headers) : [],
    headerReason: ctx.headers.reason || '',
    notes: [],
    recommendations: []
  };

  if (!ctx.headers.present) {
    result.notes[result.notes.length] =
      'No raw email headers were supplied, so the SPF, DKIM, DMARC, Reply-To and display-name checks were '
      + 'skipped. They are shown as "not checked" below rather than as passes.';
  }
  if (!ctx.links.length) {
    result.notes[result.notes.length] =
      'No web links were found in the message text, so the link-related checks had nothing to inspect.';
  }
  if (!ctx.attachments.length) {
    result.notes[result.notes.length] =
      'No attachment filenames were found. If the message has an attachment, its name may not appear in the '
      + 'text you pasted.';
  }
  if (result.capped) {
    result.notes[result.notes.length] =
      'The combined weight of the indicators was ' + rawTotal + ', which is above the maximum, so the score '
      + 'is shown as 100.';
  }

  result.recommendations = PA.buildRecommendations(result);
  return result;
};

/* ===================== advice =========================================== */

PA.buildRecommendations = function (r) {
  var recs = [];
  var tags = r.tags || {};
  var band = r.band.key;

  function add(level, title, text) {
    for (var i = 0; i < recs.length; i++) {
      if (recs[i].title === title) { return; }
    }
    recs[recs.length] = { level: level, title: title, text: text };
  }

  if (band === 'high') {
    add('now', 'Do not interact with this message',
      'Do not click any link, do not reply, do not open an attachment and do not pay or transfer anything. '
      + 'Once you have finished examining it, report it and delete it.');
  } else if (band === 'suspicious') {
    add('now', 'Pause before you act',
      'Nothing in this message needs an instant answer. Put it aside and verify it independently first, '
      + 'which is the opposite of what the message is trying to make you do.');
  }

  if (tags.credentials) {
    add('now', 'Never enter this password or code anywhere reached from this email',
      'No genuine IT team, bank or supplier asks for your password or a one-time code by email. If you have '
      + 'already typed your details, change that password immediately from a device you trust and tell your '
      + 'IT or security team.');
  }
  if (tags.payment) {
    add('now', 'Do not change any bank details or send a payment because of this message',
      'Telephone the supplier or colleague on a number you already hold, never the number in the email, and '
      + 'read the request back to them. Change-of-bank-details requests are the most costly phishing scam '
      + 'aimed at organisations.');
  }
  if (tags.attachment) {
    add('now', 'Do not open the attachment',
      'Opening it, and especially enabling macros or editing, is how malicious documents usually run their '
      + 'code. If you were not expecting the file, treat it as unsafe.');
  }
  if (tags.links) {
    add('verify', 'Check any link by navigating yourself',
      'Rather than clicking, open the organisation\'s official website or app the way you normally would -- '
      + 'by typing the address or using your own bookmark -- and sign in from there.');
  }
  if (tags.headers) {
    add('verify', 'Read the authentication results as evidence, not proof',
      'An SPF, DKIM or DMARC failure shows the message did not come from who it claims. Passing results only '
      + 'mean the sending domain is configured correctly; they do not prove the sender is honest.');
  }

  add('verify', 'Verify the message out of band',
    'Use contact details you already trust: the organisation\'s official website or app, a phone number on '
    + 'your account statement, card or contract, or a colleague you can speak to in person.');

  add('verify', 'Report it through the proper channel',
    'Send the message to your IT or security team, or forward it to the national reporting service for your '
    + 'country. Reporting protects everyone else as well.');

  if (band === 'low') {
    add('note', 'A low score is not a green light',
      'This tool only recognises patterns it has been taught. If the message arrived unexpectedly, asks for '
      + 'money, or asks you to log in somewhere new, verify it anyway.');
  }

  add('note', 'Never test a link or attachment to find out',
    'Clicking is how the attack succeeds, and some techniques work the moment you visit a page. If you are '
    + 'unsure, hand the message to a professional rather than experimenting with it yourself.');

  return recs;
};

/* A tidy list of every rule and its weight, used by the "how the score is
   calculated" panel and by the self-tests. */
PA.ruleCatalogue = function () {
  var all = PA.rules.concat(PA.headerRules);
  var rows = [];
  for (var i = 0; i < all.length; i++) {
    rows[rows.length] = {
      id: all[i].id,
      title: all[i].title,
      category: all[i].category,
      points: all[i].points,
      needs: all[i].needs || 'body'
    };
  }
  rows.sort(function (a, b) { return b.points - a.points; });
  return rows;
};

PA.maxPossibleScore = function () {
  var all = PA.rules.concat(PA.headerRules);
  var total = 0;
  for (var i = 0; i < all.length; i++) { total += all[i].points; }
  return total;
};
