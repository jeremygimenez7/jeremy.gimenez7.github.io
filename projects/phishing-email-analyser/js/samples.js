/* ==========================================================================
 * samples.js -- completely fictional teaching examples
 * --------------------------------------------------------------------------
 * IMPORTANT
 *   * Every name, company and address here is invented.
 *   * Only reserved / example domains are used (example.com, example.net,
 *     example.tk, 192.0.2.x), which cannot belong to a real attacker.
 *   * No link in these samples resolves to anything real or harmful.
 *   * The "expect" block is what the built-in self-test checks against, so a
 *     future edit that breaks the engine will be caught immediately.
 * ========================================================================== */

window.PA = window.PA || {};
var PA = window.PA;

PA.samples = [

  /* ------------------------------------------------------------------ 1 */
  {
    id: 'obvious-phishing',
    name: 'Obvious phishing',
    blurb: 'Crude and loud: shouting subject, generic greeting, threats, a raw IP link and a password request.',
    steps: [
      'The subject is in capitals with three exclamation marks.',
      'It uses "Dear Customer" instead of your name.',
      'It threatens to close the account within 24 hours.',
      'The only link is a bare IP address over unencrypted http.',
      'It asks you to type your password.'
    ],
    body: [
      'Subject: URGENT!!! YOUR ACCOUNT WILL BE CLOSED!!!',
      '',
      'Dear Customer,',
      '',
      'We have detected unusual activity on your account. Your account will be',
      'suspended within 24 hours unless you verify your account immediately.',
      '',
      'Click the link below to confirm your details and enter your password to',
      'restore access:',
      '',
      'http://192.0.2.45/secure-login/verify',
      '',
      'Failure to comply will result in permanent closure of your account.',
      'Kindly act now.',
      '',
      'Account Security Team'
    ].join('\n'),
    headers: [
      'Return-Path: <bounce@mail-relay.example.net>',
      'Received: from unknown (unknown [192.0.2.45])',
      '\tby mx.recipient.example (Postfix) with ESMTP id 7A1B2C3D',
      '\tfor <jordan@recipient.example>; Tue, 06 Oct 2026 03:22:41 +0000',
      'Authentication-Results: mx.recipient.example;',
      '\tspf=fail (sender IP is not authorised) smtp.mailfrom=example.net;',
      '\tdkim=none;',
      '\tdmarc=fail (p=none dis=none) header.from=example.net',
      'From: "Account Security" <no-reply@mail-relay.example.net>',
      'To: Jordan Bell <jordan@recipient.example>',
      'Subject: URGENT!!! YOUR ACCOUNT WILL BE CLOSED!!!',
      'Date: Tue, 06 Oct 2026 03:22:39 +0000',
      'Message-ID: <0011@mail-relay.example.net>',
      'Content-Type: text/plain; charset="utf-8"'
    ].join('\n'),
    expect: {
      band: 'high',
      min: 60,
      max: 100,
      mustInclude: [
        'account_threat', 'password_request', 'generic_greeting', 'url_raw_ip',
        'url_insecure_http', 'exclamation_shouting', 'deadline_pressure',
        'header_spf_fail', 'header_dmarc_fail'
      ]
    }
  },

  /* ------------------------------------------------------------------ 2 */
  {
    id: 'sophisticated-phishing',
    name: 'Sophisticated phishing',
    blurb: 'Calm, well written, no typos and no obvious bait. The give-away is in the headers, not the text.',
    steps: [
      'The body reads like a normal supplier email and uses your first name.',
      'The link uses https and a plausible domain, so the link checks stay quiet.',
      'The Reply-To address is on a different domain from the From address.',
      'SPF is only a soft fail, which many mail servers let through.',
      'The attachment name looks like an ordinary PDF.'
    ],
    body: [
      'Subject: Your invoice INV-20934 from Northwind Supplies',
      '',
      'Hi Jordan,',
      '',
      'Thanks for your continued business with Northwind Supplies. Please find',
      'attached invoice INV-20934 for last month\u2019s order.',
      '',
      'Invoice number: INV-20934',
      'Amount due: 2,480.00 GBP',
      'Payment is due 14 days from the date shown on the invoice.',
      '',
      'You can also view the invoice in our supplier portal:',
      'https://northwind-supplies.example.com/portal/invoices/INV-20934',
      '',
      'If anything looks wrong, just reply to this message.',
      '',
      'Kind regards,',
      'Priya',
      'Accounts Receivable, Northwind Supplies'
    ].join('\n'),
    headers: [
      'Return-Path: <bounce@northwind-supplies.example.com>',
      'Received: from mail.northwind-supplies.example.com (mail.northwind-supplies.example.com [192.0.2.91])',
      '\tby mx.recipient.example (Postfix) with ESMTPS id 4D5E6F7A',
      '\tfor <jordan@recipient.example>; Tue, 06 Oct 2026 09:14:02 +0000',
      'Authentication-Results: mx.recipient.example;',
      '\tspf=softfail (sender IP is not authorised) smtp.mailfrom=northwind-supplies.example.com;',
      '\tdkim=none;',
      '\tdmarc=pass (p=none dis=none) header.from=northwind-supplies.example.com',
      'From: "Northwind Supplies Accounts" <billing@northwind-supplies.example.com>',
      'To: Jordan Bell <jordan@recipient.example>',
      'Subject: Your invoice INV-20934 from Northwind Supplies',
      'Date: Tue, 06 Oct 2026 09:13:58 +0000',
      'Reply-To: northwind.billing@northwind-supplies.example.net',
      'Message-ID: <9f2c@northwind-supplies.example.com>',
      'Content-Type: multipart/mixed; boundary="b1"',
      'Content-Disposition: attachment; filename="INV-20934.pdf"'
    ].join('\n'),
    expect: {
      band: 'suspicious',
      min: 25,
      max: 59,
      mustInclude: [
        'unexpected_invoice', 'header_reply_to_mismatch', 'header_spf_softfail'
      ]
    }
  },

  /* ------------------------------------------------------------------ 3 */
  {
    id: 'fake-microsoft',
    name: 'Fake Microsoft 365 warning',
    blurb: 'A fake sign-in alert. Uses the "unusual activity" hook, a look-alike domain and a deadline.',
    steps: [
      'It claims a new sign-in was detected on your account.',
      'It uses "Dear User" instead of your name.',
      'It tells you to click a link to verify your identity.',
      'The domain "micro5oft-login.example.com" imitates Microsoft but is not Microsoft.',
      'It threatens suspension within 24 hours.'
    ],
    body: [
      'Subject: Action required: unusual sign-in activity on your Microsoft 365 account',
      '',
      'Dear User,',
      '',
      'We have detected a new sign-in from an unrecognised device. For your',
      'security, we have temporarily limited access to your account.',
      '',
      'To restore access, click the link below to sign in and verify your',
      'identity:',
      '',
      'https://micro5oft-login.example.com/verify?user=jordan.bell',
      '',
      'If you cannot confirm this activity, your account will be suspended',
      'within 24 hours.',
      '',
      'Microsoft 365 Team'
    ].join('\n'),
    headers: [
      'Return-Path: <no-reply@micro5oft-login.example.com>',
      'Received: from micro5oft-login.example.com (micro5oft-login.example.com [192.0.2.133])',
      '\tby mx.recipient.example (Postfix) with ESMTPS id 8B9C0D1E',
      '\tfor <jordan@recipient.example>; Tue, 06 Oct 2026 11:45:19 +0000',
      'Authentication-Results: mx.recipient.example;',
      '\tspf=fail (sender IP is not authorised) smtp.mailfrom=micro5oft-login.example.com;',
      '\tdkim=fail (body hash did not verify);',
      '\tdmarc=fail (p=none dis=none) header.from=micro5oft-login.example.com',
      'From: "Microsoft 365" <no-reply@micro5oft-login.example.com>',
      'To: Jordan Bell <jordan@recipient.example>',
      'Subject: Action required: unusual sign-in activity on your Microsoft 365 account',
      'Date: Tue, 06 Oct 2026 11:45:12 +0000',
      'Message-ID: <77ff@micro5oft-login.example.com>',
      'Content-Type: text/html; charset="utf-8"'
    ].join('\n'),
    expect: {
      band: 'high',
      min: 60,
      max: 100,
      mustInclude: [
        'impersonation_language', 'credential_harvesting', 'generic_greeting',
        'authority_impersonation', 'url_typosquat', 'account_threat',
        'header_spf_fail', 'header_dkim_fail', 'header_dmarc_fail'
      ]
    }
  },

  /* ------------------------------------------------------------------ 4 */
  {
    id: 'fake-parcel',
    name: 'Fake parcel delivery',
    blurb: 'A small "redelivery fee" scam. Low value so you pay without thinking, plus a phone number as a backup hook.',
    steps: [
      'It claims a parcel is waiting and a deadline is running.',
      'A small "payment of 1.99 GBP" is requested.',
      'It points to a domain containing a real postal brand but registered elsewhere.',
      'It invites you to ring an unverified number.',
      'It uses "Dear Customer" and stiff phrasing.'
    ],
    body: [
      'Subject: Your parcel could not be delivered - action required',
      '',
      'Dear Customer,',
      '',
      'We attempted to deliver your parcel today but there was no answer. Your',
      'parcel is now at our depot and will be returned to the sender within',
      '48 hours.',
      '',
      'To reschedule your delivery, confirm your details and pay the outstanding',
      'redelivery charge. A small payment of 1.99 GBP is required:',
      '',
      'https://royalmail-delivery.example.com/reschedule/pay',
      '',
      'Alternatively, call us on the number below and quote your reference',
      'RM4482913: 020 7946 0000',
      '',
      'Please be informed that a failure to confirm within 48 hours will result',
      'in your parcel being returned.',
      '',
      'Delivery Team, Royal Mail'
    ].join('\n'),
    headers: [
      'Return-Path: <mailer@royalmail-delivery.example.com>',
      'Received: from royalmail-delivery.example.com (royalmail-delivery.example.com [192.0.2.210])',
      '\tby mx.recipient.example (Postfix) with ESMTPS id 2C3D4E5F',
      '\tfor <jordan@recipient.example>; Tue, 06 Oct 2026 07:03:55 +0000',
      'Authentication-Results: mx.recipient.example;',
      '\tspf=pass (sender IP is 192.0.2.210) smtp.mailfrom=royalmail-delivery.example.com;',
      '\tdkim=none;',
      '\tdmarc=none',
      'From: "Royal Mail Delivery" <mailer@royalmail-delivery.example.com>',
      'To: Jordan Bell <jordan@recipient.example>',
      'Subject: Your parcel could not be delivered - action required',
      'Date: Tue, 06 Oct 2026 07:03:50 +0000',
      'Message-ID: <12ab@royalmail-delivery.example.com>',
      'Content-Type: text/html; charset="utf-8"'
    ].join('\n'),
    expect: {
      band: 'high',
      min: 60,
      max: 100,
      mustInclude: [
        'generic_greeting', 'deadline_pressure', 'url_brand_mismatch',
        'threat_to_contact', 'payment_request', 'credential_harvesting',
        'consequence_language'
      ]
    }
  },

  /* ------------------------------------------------------------------ 5 */
  {
    id: 'fake-invoice-bec',
    name: 'Fake invoice / BEC-style',
    blurb: 'Business email compromise: a short, secretive "favour" from someone pretending to be a senior colleague.',
    steps: [
      'It opens with "Are you at your desk?" and claims a meeting is imminent.',
      'It insists the request stays confidential and stays away from the finance team.',
      'It asks for an urgent wire transfer.',
      'It introduces brand-new bank account details.',
      'The Reply-To goes to a free webmail account, and SPF, DKIM and DMARC all fail.'
    ],
    body: [
      'Subject: Quick favour - confidential',
      '',
      'Hi,',
      '',
      'Are you at your desk? I need you to arrange an urgent wire transfer today',
      'before I go into a meeting at 3pm. It is for a new supplier and I would',
      'rather keep this between us until the deal is signed.',
      '',
      'Please transfer 9,750.00 GBP to the new bank account details below:',
      '',
      'Bank: Example Commercial Bank',
      'Account name: Halden Trading Ltd',
      'Sort code: 00-00-00',
      'Account number: 00000000',
      '',
      'Kindly confirm once the payment has been sent. Please do not discuss this',
      'with the finance team yet as it is confidential.',
      '',
      'Thanks,',
      'Alan'
    ].join('\n'),
    headers: [
      'Return-Path: <bounce@bulk-relay.example.net>',
      'Received: from bulk-relay.example.net (bulk-relay.example.net [192.0.2.55])',
      '\tby mx.recipient.example (Postfix) with ESMTP id 6E7F8A9B',
      '\tfor <jordan@recipient.example>; Tue, 06 Oct 2026 13:31:07 +0000',
      'Authentication-Results: mx.recipient.example;',
      '\tspf=fail (sender IP is not authorised) smtp.mailfrom=example.net;',
      '\tdkim=fail (no key for signature);',
      '\tdmarc=fail (p=reject dis=none) header.from=example-corp.co',
      'From: "Alan Wright (CEO)" <alan.wright@example-corp.co>',
      'To: Jordan Bell <jordan@recipient.example>',
      'Subject: Quick favour - confidential',
      'Date: Tue, 06 Oct 2026 13:31:01 +0000',
      'Reply-To: alan.wright.ceo@gmail.com',
      'Message-ID: <3d4e@bulk-relay.example.net>',
      'Content-Type: text/plain; charset="utf-8"'
    ].join('\n'),
    expect: {
      band: 'high',
      min: 60,
      max: 100,
      mustInclude: [
        'bec_quick_favour', 'payment_request', 'bank_details_change',
        'secrecy_request', 'urgency_language', 'header_reply_to_mismatch',
        'header_reply_to_freemail', 'header_spf_fail', 'header_dmarc_fail',
        'header_return_path_mismatch'
      ]
    }
  },

  /* ------------------------------------------------------------------ 6 */
  {
    id: 'legitimate-email',
    name: 'Legitimate email',
    blurb: 'An ordinary internal note from a known colleague, with clean authentication. It should score 0.',
    steps: [
      'It is short, specific and uses your name.',
      'There is no urgency, threat, payment or credential request.',
      'There are no links and no attachments.',
      'SPF, DKIM and DMARC all pass and the From and Return-Path agree.',
      'Nothing here matches any of the warning signs, so the score stays at 0.'
    ],
    body: [
      'Subject: Team meeting moved to Thursday at 10:00',
      '',
      'Hi Jordan,',
      '',
      'A quick note to confirm that our weekly team meeting has moved from',
      'Wednesday to Thursday at 10:00 in Meeting Room 2. The agenda is unchanged.',
      '',
      'If Thursday does not work for you, reply to me directly and we will find',
      'another slot.',
      '',
      'Thanks,',
      'Priya Sharma',
      'Operations, Contoso Example Ltd'
    ].join('\n'),
    headers: [
      'Return-Path: <priya.sharma@contoso-example.com>',
      'Received: from mail.contoso-example.com (mail.contoso-example.com [192.0.2.10])',
      '\tby mx.recipient.example (Postfix) with ESMTPS id 5C7D8E9F',
      '\tfor <jordan@recipient.example>; Mon, 05 Oct 2026 08:02:11 +0000',
      'Authentication-Results: mx.recipient.example;',
      '\tspf=pass (sender IP is 192.0.2.10) smtp.mailfrom=contoso-example.com;',
      '\tdkim=pass (signature was verified) header.d=contoso-example.com;',
      '\tdmarc=pass (p=none dis=none) header.from=contoso-example.com',
      'From: Priya Sharma <priya.sharma@contoso-example.com>',
      'To: Jordan Bell <jordan@recipient.example>',
      'Subject: Team meeting moved to Thursday at 10:00',
      'Date: Mon, 05 Oct 2026 08:02:05 +0000',
      'Message-ID: <abc123@contoso-example.com>',
      'Content-Type: text/plain; charset="utf-8"'
    ].join('\n'),
    expect: {
      band: 'low',
      min: 0,
      max: 4,
      mustInclude: []
    }
  }

];
