/* ==========================================================================
 * selftest.js -- the built-in regression tests
 * --------------------------------------------------------------------------
 * These tests exist so that the scoring engine can be checked without a
 * browser. They are deliberately free of any DOM code, so the same file runs
 * in the browser (tests/tests.html) and under Windows Script Host.
 *
 * Run them from the command line with:   tools\run-tests.cmd
 * ========================================================================== */

window.PA = window.PA || {};
var PA = window.PA;

PA.runSelfTest = function () {
  var results = [];

  function check(name, pass, detail) {
    results[results.length] = {
      name: name,
      pass: !!pass,
      detail: detail == null ? '' : String(detail)
    };
  }

  function eq(name, actual, expected) {
    check(name, actual === expected, 'expected ' + expected + ', got ' + actual);
  }

  /* ---------------------- domain and URL helpers ---------------------- */
  var u;

  u = PA.parseUrl('http://192.0.2.45/secure-login/verify');
  check('Raw IP address in a link is detected',
    u.isIp === true && u.host === '192.0.2.45', u.host);
  check('http:// is reported as unencrypted',
    u.insecure === true, String(u.insecure));

  u = PA.parseUrl('https://bit.ly/3xample');
  check('Shortened link is detected', u.shortener === true, u.host);

  u = PA.parseUrl('https://verify-account.secure-login.tk/step1');
  eq('Risky top-level domain is detected', u.badTld, 'tk');

  u = PA.parseUrl('https://xn--microsft-h4a.example.com/signin');
  check('Punycode look-alike domain is detected', u.punycode === true, u.host);

  u = PA.parseUrl('http://microsoft.com@evil.example.net/login');
  check('"@" userinfo trick is detected and the real host is used',
    u.hasAt === true && u.host === 'evil.example.net', u.host);

  u = PA.parseUrl('https://microsoft-verify.example.com/login');
  eq('Brand placed in a subdomain is flagged', u.brandMismatch, 'microsoft');

  u = PA.parseUrl('https://www.microsoft.com/login');
  eq('Genuine Microsoft domain is NOT flagged', u.brandMismatch, '');

  u = PA.parseUrl('https://micro5oft-login.example.com/verify');
  eq('Look-alike "micro5oft" is caught as typosquatting', u.typosquat, 'microsoft');

  u = PA.parseUrl('https://a.b.c.d.example.com/x');
  check('Long subdomain chains are counted', u.labelCount >= 4, String(u.labelCount));

  u = PA.parseUrl('mailto:someone@example.com');
  eq('mailto: links are ignored', u.host, '');

  eq('registrableDomain handles two-part suffixes',
    PA.net.registrableDomain('mail.bbc.co.uk'), 'bbc.co.uk');
  eq('registrableDomain handles simple domains',
    PA.net.registrableDomain('a.b.example.com'), 'example.com');
  check('sameSite treats subdomains as one site',
    PA.net.sameSite('mail.example.com', 'www.example.com') === true, '');
  check('sameSite separates different domains',
    PA.net.sameSite('example.com', 'example.net') === false, '');

  /* ---------------------- link text mismatch ------------------------- */
  var linkCtx = {
    links: PA.extractLinks('<a href="http://192.0.2.9/login">https://www.paypal.com/signin</a>')
  };
  check('Anchor text that disagrees with the target is captured',
    linkCtx.links.length === 1 && linkCtx.links[0].text.indexOf('paypal') !== -1,
    linkCtx.links.length ? linkCtx.links[0].text : 'no links found');

  var mismatchRule = null;
  for (var ri = 0; ri < PA.rules.length; ri++) {
    if (PA.rules[ri].id === 'hidden_link_target') { mismatchRule = PA.rules[ri]; }
  }
  check('Misleading link text rule fires',
    !!mismatchRule && mismatchRule.test(linkCtx).matched === true, '');

  /* ---------------------- attachments -------------------------------- */
  var a;

  a = PA.makeAttachment('invoice.pdf.exe');
  check('Double extension is detected', a.doubleExtension === true, a.name);

  a = PA.makeAttachment('Statement_Oct.docm');
  eq('Macro-enabled document is classified', a.kind, 'macro-document');

  a = PA.makeAttachment('payroll.js');
  eq('Script attachment is classified as executable', a.kind, 'executable');

  a = PA.makeAttachment('photos.zip');
  eq('Archive attachment is classified', a.kind, 'archive');

  a = PA.makeAttachment('notice.html');
  eq('HTML attachment is classified as unusual', a.kind, 'unusual');

  a = PA.makeAttachment('invite.pdf');
  eq('Ordinary PDF attachment is not flagged', a.kind, 'document');

  var foundFiles = PA.extractAttachments('Please open invoice.pdf.exe and report.docm today.', null);
  eq('Filenames are found in body text', foundFiles.length, 2);

  var urlOnly = PA.extractAttachments('See https://portal.example.com/report.html for details.', null);
  eq('Attachment names are not invented from web addresses', urlOnly.length, 0);

  /* ---------------------- headers ------------------------------------ */
  var rawHeaders = [
    'Return-Path: <bounce@mailer.example.net>',
    'Authentication-Results: mx.recipient.example; spf=fail smtp.mailfrom=example.net; dkim=fail; dmarc=fail',
    'From: "Microsoft Account Team" <no-reply@micro5oft-support.example.com>',
    'Reply-To: helpdesk.team@gmail.com',
    'Subject: Verify your account',
    'Content-Disposition: attachment; filename="Remittance_Advice.xlsm"'
  ].join('\n');

  var h = PA.parseHeaders(rawHeaders);
  check('Headers are recognised as a header block', h.present === true, '');
  eq('From address is parsed', h.from.address, 'no-reply@micro5oft-support.example.com');
  eq('From display name is parsed', h.from.display, 'Microsoft Account Team');
  eq('SPF failure is read', h.spf, 'fail');
  eq('DKIM failure is read', h.dkim, 'fail');
  eq('DMARC failure is read', h.dmarc, 'fail');
  eq('Reply-To address is parsed', h.replyTo.address, 'helpdesk.team@gmail.com');
  eq('Attachment filename is read from the headers', h.filenames.length, 1);

  var emptyHeaders = PA.parseHeaders('Dear Customer, please click here.');
  eq('A message body is not treated as a header block', emptyHeaders.present, false);

  var multi = PA.parseHeaders([
    'Authentication-Results: mx1; spf=pass',
    'Authentication-Results: mx2; spf=fail'
  ].join('\n'));
  eq('The worst SPF result wins', multi.spf, 'fail');

  /* ---------------------- scoring ------------------------------------ */
  var clean = PA.analyse({
    body: 'Hi Jordan,\n\nLunch on Friday at 12:30?\n\nThanks,\nPriya',
    headers: ''
  });
  eq('An entirely innocent note scores zero', clean.score, 0);
  eq('An entirely innocent note is Low Risk', clean.band.key, 'low');

  var scoreCapped = PA.analyse({
    body: 'URGENT!!! Dear Customer, your account will be suspended immediately. '
      + 'Enter your password and confirm your identity at http://192.0.2.45/login '
      + 'within 24 hours or your account will be closed. Failure to comply will '
      + 'result in permanent closure. Kindly act now. Security Team.'
  });
  check('Extreme messages are capped at 100', scoreCapped.score === 100, String(scoreCapped.score));
  check('Every finding carries points and a reason',
    scoreCapped.findings.length > 0 && scoreCapped.findings[0].points > 0 &&
    typeof scoreCapped.findings[0].why === 'string', '');
  var sumOfFindings = 0;
  for (var fi = 0; fi < scoreCapped.findings.length; fi++) {
    sumOfFindings += scoreCapped.findings[fi].points;
  }
  check('The score equals the sum of the listed points (before capping)',
    sumOfFindings === scoreCapped.rawTotal,
    'sum ' + sumOfFindings + ' vs rawTotal ' + scoreCapped.rawTotal);

  var noHeaders = PA.analyse({ body: 'Hello there.', headers: '' });
  check('Header rules are reported as not checked when no headers are pasted',
    noHeaders.notChecked.length === PA.headerRules.length && noHeaders.notChecked.length > 0,
    String(noHeaders.notChecked.length));

  /* ---------------------- the demonstration emails -------------------- */
  for (var si = 0; si < PA.samples.length; si++) {
    var s = PA.samples[si];
    var r = PA.analyse({ body: s.body, headers: s.headers });
    var label = s.name + ': ';

    check(label + 'classification is ' + s.expect.band,
      r.band.key === s.expect.band, 'got ' + r.band.key + ' (' + r.score + ')');
    check(label + 'score is between ' + s.expect.min + ' and ' + s.expect.max,
      r.score >= s.expect.min && r.score <= s.expect.max, 'got ' + r.score);

    for (var mi = 0; mi < s.expect.mustInclude.length; mi++) {
      var wanted = s.expect.mustInclude[mi];
      var hit = false;
      for (var fj = 0; fj < r.findings.length; fj++) {
        if (r.findings[fj].id === wanted) { hit = true; }
      }
      check(label + 'detects "' + wanted + '"', hit, 'rule did not fire');
    }

    check(label + 'explains every finding',
      r.findings.length === 0 || (r.findings[0].why.length > 10 && r.findings[0].evidence.length > 0), '');
    check(label + 'offers advice', r.recommendations.length > 0, String(r.recommendations.length));
  }

  /* ---------------------- summary ------------------------------------ */
  var passed = 0;
  var failed = 0;
  for (var k = 0; k < results.length; k++) {
    if (results[k].pass) { passed++; } else { failed++; }
  }

  return {
    results: results,
    passed: passed,
    failed: failed,
    total: results.length,
    ok: failed === 0
  };
};

