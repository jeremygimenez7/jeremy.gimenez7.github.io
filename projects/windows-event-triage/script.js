/* ==========================================================================
   Windows Security Event Log Triage Tool  -  script.js
   --------------------------------------------------------------------------
   PRIVACY STATEMENT (also shown in the interface):
   Your Windows security logs are analysed locally in your browser.
   Files are not uploaded or transmitted anywhere.

   This file is deliberately network-free. There is no server, no backend and
   no external service. Out of an abundance of caution, the project avoids
   every browser API that could send data off the machine:

       fetch(                -> NOT USED
       XMLHttpRequest        -> NOT USED
       navigator.sendBeacon  -> NOT USED
       WebSocket             -> NOT USED
       EventSource           -> NOT USED
       localStorage / sessionStorage -> NOT USED (nothing is persisted)
       document.cookie       -> NOT USED

   Those names appear in this file only inside comments like this one, so that
   a reader can search for them and confirm they are never called. Sample
   datasets are embedded as string constants precisely so that no file has to
   be fetched over the network to make the demo buttons work.

   SECURITY RULE FOR THIS FILE
   Uploaded CSV content is treated as untrusted input. Any value that comes
   from the file is inserted into the DOM through esc() or through
   textContent. Values are never inserted as raw HTML.
   ========================================================================== */

(function () {
  'use strict';

  /* ======================= 1. CONFIGURATION & CONSTANTS ==================== */

  /* Educational defaults. Security thresholds vary by environment; these are
     not universal SOC detection rules. See the Thresholds panel. */
  var DEFAULTS = {
    failedLoginThreshold: 5,        // Event ID 4625 count for one account
    failedLoginWindowMinutes: 10    // burst window when timestamps are usable
  };

  var LIMITS = {
    maxBytes: 60 * 1024 * 1024,     // 60 MB guard so the tab stays responsive
    maxRows: 200000                 // hard row cap
  };

  var SEVERITY = {
    INFORMATIONAL: 'Informational',
    LOW: 'Low',
    MEDIUM: 'Medium',
    HIGH: 'High'
  };

  var SEV_RANK = {
    'Informational': 0,
    'Low': 1,
    'Medium': 2,
    'High': 3
  };

  /* Explainable scoring weights. Every weight is surfaced to the user with the
     reason it fired. This is an educational prioritisation mechanism, NOT a
     probability of compromise. */
  var SCORE = {
    repeatedFailedLogons: 10,
    successAfterFailures: 20,
    privilegedGroupChange: 25,
    auditLogCleared: 30,
    accountCreated: 15,
    accountDeleted: 10,
    serviceInstalled: 15,
    encodedScriptBlock: 15,
    privilegedAccountCreated: 10,
    accountCreatedThenPrivileged: 10,
    maximum: 100
  };

  /* Group names that raise investigative priority. Matching is case-insensitive
     and includes wildcards for names such as "Hyper-V Administrators". */
  var PRIVILEGED_GROUPS = [
    'administrators', 'domain admins', 'enterprise admins', 'schema admins',
    'backup operators', 'account operators', 'server operators', 'power users',
    'group policy creator owners', 'remote desktop users', 'hyper-v administrators',
    'print operators', 'network configuration operators', 'cryptographic operators',
    'dnsadmins', 'exchange organization administrators', 'protected users',
    'domain controllers', 'replicator'
  ];

  var PRIVILEGED_GROUP_PATTERNS = [
    /admin/i, /operator/i, /replicator/i, /\broot\b/i, /controller/i
  ];

  /* Accounts that are normally background noise: machine accounts, service
     identities and unresolved entries. They are de-prioritised rather than
     discarded, and the count is disclosed in the report. */
  var NOISE_ACCOUNTS = [
    'system', 'local service', 'network service', 'anonymous logon',
    'nt authority\\system', 'nt authority\\local service',
    'nt authority\\network service', 'iusr', 'iwam', 'font driver host', '-'
  ];

  /* Windows "Logon Type" values, used to explain 4624 / 4625 in plain English. */
  var LOGON_TYPES = {
    '0': 'System / unknown',
    '2': 'Interactive (a person at the keyboard or console)',
    '3': 'Network (shared folder, printer, or remote access)',
    '4': 'Batch (a scheduled task)',
    '5': 'Service (a Windows service starting)',
    '7': 'Unlock (workstation was unlocked)',
    '8': 'NetworkCleartext (credentials sent without encryption)',
    '9': 'NewCredentials (RunAs with stored credentials)',
    '10': 'RemoteInteractive (Remote Desktop / RDP)',
    '11': 'CachedInteractive (cached credentials, no domain contact)'
  };

  /* Column name aliases. Header names are normalised first (lowercase, with
     every character other than a-z0-9 removed), so "Event ID", "EventID",
     "event_id" and "Event  Id" all collapse to "eventid".
     Both Event Viewer GUI exports and PowerShell Export-Csv exports are covered. */
  var COLUMN_ALIASES = {
    eventId:    ['eventid', 'id', 'eventcode', 'eventnumber', 'event'],
    timestamp:  ['dateandtime', 'timecreated', 'timestamp', 'datetime', 'date',
                 'systemtime', 'time', 'logged'],
    source:     ['source', 'providername', 'provider', 'sourcename'],
    level:      ['level', 'leveldisplayname', 'severity', 'loglevel'],
    user:       ['user', 'username', 'userid', 'account', 'accountname'],
    computer:   ['computer', 'computername', 'machinename', 'machine', 'hostname', 'host'],
    message:    ['message', 'description', 'msg', 'details'],
    taskCategory: ['taskcategory', 'task', 'category'],
    keywords:   ['keywords', 'keyword'],
    opcode:     ['opcode'],
    recordId:   ['recordid', 'eventrecordid', 'recordnumber'],
    logName:    ['logname', 'channel', 'log']
  };

  /* Non-English column headers we can still recognise, so a student on a
     localised Windows install gets a useful result instead of a hard failure. */
  var LOCALISED_ALIASES = {
    eventId:   ['ereignisid', 'iddevenement', 'iddeevenement', 'evento', 'idevento'],
    timestamp: ['datumunduhrzeit', 'dateetheure', 'fechayhora'],
    message:   ['beschreibung', 'descripcion'],
    level:     ['ebene', 'niveau', 'nivel'],
    computer:  ['ordinateur', 'equipo']
  };

  /* ======================= 2. EVENT ID KNOWLEDGE BASE ===================== */
  /* One single source of truth, used both for detection/scoring and for the
     beginner reference section in the interface. */
  var EVID = {
    4624: {
      id: 4624, name: 'Successful logon', severity: SEVERITY.INFORMATIONAL,
      category: 'Authentication',
      short: 'A Windows account successfully logged on.',
      plain: 'Windows created a logon session, meaning an account proved its identity. ' +
             'This is normal, constant background activity on a busy computer.',
      investigate: 'Never suspicious on its own. It becomes valuable as context: it shows which ' +
                   'account was active, from where, and with what type of logon.',
      labels: ['Account name', 'Logon type', 'Source IP', 'Workstation', 'Computer']
    },
    4625: {
      id: 4625, name: 'Failed logon', severity: SEVERITY.INFORMATIONAL,
      category: 'Authentication',
      short: 'An account failed to log on.',
      plain: 'Someone or something tried to authenticate and the credentials were rejected. ' +
             'A single failure is usually just a typo. Many failures for one account in a short ' +
             'time deserve a closer look.',
      investigate: 'Count failures per account, note the source address, and check whether the ' +
                   'failures were followed by a success.',
      labels: ['Account name', 'Failure reason', 'Source IP', 'Workstation', 'Logon type']
    },
    4720: {
      id: 4720, name: 'User account created', severity: SEVERITY.MEDIUM,
      category: 'Account management',
      short: 'A new Windows user account was created.',
      plain: 'A new user account now exists. Creating accounts is completely normal ' +
             'administration, but it is also how an intruder establishes persistence.',
      investigate: 'Confirm the account was requested and authorised, identify who created it, ' +
                   'and check what the account did afterwards.',
      labels: ['New account', 'Created by', 'Computer']
    },
    4726: {
      id: 4726, name: 'User account deleted', severity: SEVERITY.LOW,
      category: 'Account management',
      short: 'A user account was deleted.',
      plain: 'An account was removed. This is often tidy-up after a person leaves, but a rapid ' +
             'create-then-delete cycle can also be an attempt to cover activity.',
      investigate: 'Check whether the deletion matches a known process such as an employee ' +
                   'leaving, and whether the account had been created recently.',
      labels: ['Deleted account', 'Deleted by', 'Computer']
    },
    4728: {
      id: 4728, name: 'Member added to global security group', severity: SEVERITY.MEDIUM,
      category: 'Privilege change',
      short: 'A user was added to a global security group.',
      plain: 'Membership of a security group decides what an account is allowed to do. Joining a ' +
             'privileged group is a large change in capability.',
      investigate: 'Identify the group. If it is a privileged group such as Domain Admins, treat ' +
                   'it as high priority and confirm the change was authorised.',
      labels: ['Member added', 'Group', 'Added by', 'Computer']
    },
    4732: {
      id: 4732, name: 'Member added to local security group', severity: SEVERITY.MEDIUM,
      category: 'Privilege change',
      short: 'A user was added to a local security group.',
      plain: 'Similar to 4728, but the group is local to this computer. Adding an account to the ' +
             'local Administrators group gives it full control of that machine.',
      investigate: 'Identify the group. Local Administrators membership in particular should be ' +
                   'verifiable against a change record.',
      labels: ['Member added', 'Group', 'Added by', 'Computer']
    },
    1102: {
      id: 1102, name: 'Security audit log cleared', severity: SEVERITY.HIGH,
      category: 'Defence evasion',
      short: 'The Windows Security audit log was cleared.',
      plain: 'The Security log was emptied. This does happen during legitimate maintenance, but ' +
             'it also destroys the evidence an investigator would rely on, so it is treated as ' +
             'high priority.',
      investigate: 'Identify who cleared the log and from where. Confirm against maintenance ' +
                   'records, and check whether there is an unexplained gap in the timeline.',
      labels: ['Cleared by', 'Domain', 'Computer']
    },
    4688: {
      id: 4688, name: 'Process created', severity: SEVERITY.INFORMATIONAL,
      category: 'Process execution',
      short: 'A new process was created (requires process creation auditing).',
      plain: 'Windows recorded that a program started. It gives you the program name, who ' +
             'started it, and often the full command line and the parent process.',
      investigate: 'Mostly context. Interesting patterns include an unusual program starting ' +
                   'right after a logon, or a command-line tool spawned by an office application. ' +
                   'Version 1 of this tool does not attempt malware detection here.',
      labels: ['Process', 'Command line', 'Parent process', 'Account']
    },
    4104: {
      id: 4104, name: 'PowerShell script block logging', severity: SEVERITY.INFORMATIONAL,
      category: 'Script execution',
      short: 'PowerShell recorded the text of a script block it executed.',
      plain: 'PowerShell script block logging can provide valuable visibility into commands and ' +
             'scripts executed on the endpoint. PowerShell is a normal administrative tool and ' +
             'is not suspicious by itself.',
      investigate: 'Read the captured script text. Encoded or heavily obfuscated commands are ' +
                   'worth understanding, but they are also produced by legitimate management tools.',
      labels: ['Script text', 'Path', 'Computer']
    },
    7045: {
      id: 7045, name: 'Service installed', severity: SEVERITY.MEDIUM,
      category: 'Persistence',
      short: 'A new Windows service was installed on the system.',
      plain: 'A new background service was registered. Installers do this routinely, but a ' +
             'service that runs a program from a temporary or user-writable folder can be a way ' +
             'to stay on a machine.',
      investigate: 'Look at the service name, the program it runs, and its start type. Check the ' +
                   'file path against expected software locations.',
      labels: ['Service name', 'Image path', 'Start type', 'Account']
    },
    /* 4103 (PowerShell module logging) and 4672 (special privileges assigned) are
       intentionally NOT analysed in Version 1; they are documented as future work. */
    4672: {
      id: 4672, name: 'Special privileges assigned to new logon', severity: SEVERITY.INFORMATIONAL,
      category: 'Privilege use',
      short: 'A logon session was granted powerful privileges.',
      plain: 'Windows recorded that a session received sensitive privileges such as acting as ' +
             'part of the operating system. Administrators and services do this constantly.',
      investigate: 'Only interesting next to other evidence, for example a standard user account ' +
                   'suddenly receiving administrative privileges.',
      labels: ['Account name', 'Computer']
    }
  };

  /* Lookup keyed by string id, because CSV values arrive as text. */
  var EVID_BY_STRING = {};
  Object.keys(EVID).forEach(function (key) {
    EVID_BY_STRING[String(key)] = EVID[key];
  });

  /* Raw Event IDs requested by the correlation rules in Version 1. */
  var WATCHED_IDS = [4624, 4625, 4104, 4672, 4688, 4720, 4726, 4728, 4732, 7045, 1102];

  /* ======================= 3. HONEST LIMITATIONS ========================== */
  var LIMITATIONS = [
    'CSV exports differ between Windows configurations, versions and languages. Column names and ' +
    'the internal layout of the event message are not guaranteed to match this tool\'s expectations.',

    'Not every event contains network information. Many events have no source IP address at all, and ' +
    'the tool shows "unknown" rather than inventing a value.',

    'Event logging configuration affects available telemetry. Events such as 4688 (process creation) ' +
    'and 4104 (PowerShell script block logging) only exist if the corresponding audit policy or ' +
    'logging option was enabled before the activity occurred.',

    'The absence of an event does not prove that activity did not occur. It may simply have been ' +
    'logged elsewhere, overwritten, or never audited.',

    'This tool does not replace an EDR, SIEM or professional SOC platform. It performs a small, ' +
    'transparent subset of what those systems do.',

    'Static analysis inside a single browser tab provides limited correlation. It cannot join across ' +
    'multiple machines, other log sources, identity providers, or historical data.',

    'Detecting malicious behaviour requires context. The same event is routine in one environment ' +
    'and alarming in another, and only people who know the environment can tell the difference.',

    'Windows Event IDs alone cannot determine intent. An event tells you what happened, not why.',

    'Timestamps are usually local time with no timezone offset, so they are displayed exactly as ' +
    'written and are not converted between timezones.',

    'Month/day order in ambiguous dates such as "3/4/2026" cannot be determined reliably. The tool ' +
    'assumes month-first when an AM/PM marker is present, and records the ambiguity in the report.',

    'If the Message column is missing from your export, Event ID level analysis still works but the ' +
    'forensic detail (account, source IP, logon type) is unavailable.',

    'Version 1 does not parse raw .evtx files, does not support Sysmon, and does not perform ' +
    'malware detection or MITRE ATT&CK mapping.'
  ];

  /* ======================= 4. SAMPLE DATASET BUILDERS ===================== */
  /* Demo data is generated from compact declarative definitions so that the same
     fictional events can also be shipped as real CSV files in samples/.
     All names, hosts and addresses are fictional. Every IP address comes from a
     reserved or private range (RFC 1918 / RFC 5737). */

  var CSV_HEADER = ['Keywords', 'Date and Time', 'Source', 'Event ID', 'Task Category',
                    'Level', 'Opcode', 'User', 'Computer', 'Message'];

  function quoteCsv(value) {
    var s = String(value === null || value === undefined ? '' : value);
    if (/[",\r\n]/.test(s)) {
      return '"' + s.replace(/"/g, '""') + '"';
    }
    return s;
  }

  function rowsToCsv(rows) {
    return rows.map(function (row) {
      return row.map(quoteCsv).join(',');
    }).join('\r\n');
  }

  /* --- Compact but realistic Message templates ----------------------------
     These mirror the labelled layout Windows uses inside the Message column.
     They are trimmed for readability, but every label the parser reads appears
     in the same "Label: value" form as in a real event. */

  function msg4624(acct, domain, logonType, ip, workstation, elevated) {
    return 'An account was successfully logged on.\n\n' +
      'Subject:\n' +
      '\tSecurity ID:\t\tS-1-5-18\n' +
      '\tAccount Name:\t\t' + workstation + '$\n' +
      '\tAccount Domain:\t\tWORKGROUP\n' +
      '\tLogon ID:\t\t0x3E7\n\n' +
      'Logon Information:\n' +
      '\tLogon Type:\t\t' + logonType + '\n' +
      '\tRestricted Admin Mode:\t-\n' +
      '\tVirtual Account:\t\tNo\n' +
      '\tElevated Token:\t\t' + (elevated ? 'Yes' : 'No') + '\n\n' +
      'New Logon:\n' +
      '\tSecurity ID:\t\tS-1-5-21-1000000000-2000000000-3000000000-1001\n' +
      '\tAccount Name:\t\t' + acct + '\n' +
      '\tAccount Domain:\t\t' + domain + '\n' +
      '\tLogon ID:\t\t0x8DCDC\n' +
      '\tLogon GUID:\t\t{00000000-0000-0000-0000-000000000000}\n\n' +
      'Process Information:\n' +
      '\tProcess ID:\t\t0x44c\n' +
      '\tProcess Name:\t\tC:\\Windows\\System32\\svchost.exe\n\n' +
      'Network Information:\n' +
      '\tWorkstation Name:\t' + (workstation || '-') + '\n' +
      '\tSource Network Address:\t' + (ip || '-') + '\n' +
      '\tSource Port:\t\t51544\n\n' +
      'This event is generated when a logon session is created.';
  }

  function msg4625(acct, domain, logonType, ip, workstation, reason) {
    return 'An account failed to log on.\n\n' +
      'Subject:\n' +
      '\tSecurity ID:\t\tS-1-0-0\n' +
      '\tAccount Name:\t\t-\n' +
      '\tAccount Domain:\t\t-\n' +
      '\tLogon ID:\t\t0x0\n\n' +
      'Logon Type:\t\t\t' + logonType + '\n\n' +
      'Account For Which Logon Failed:\n' +
      '\tSecurity ID:\t\tS-1-0-0\n' +
      '\tAccount Name:\t\t' + acct + '\n' +
      '\tAccount Domain:\t\t' + domain + '\n\n' +
      'Failure Information:\n' +
      '\tFailure Reason:\t\t' + reason + '\n' +
      '\tStatus:\t\t\t0xC000006D\n' +
      '\tSub Status:\t\t0xC000006A\n\n' +
      'Process Information:\n' +
      '\tCaller Process ID:\t0x0\n' +
      '\tCaller Process Name:\t-\n\n' +
      'Network Information:\n' +
      '\tWorkstation Name:\t' + (workstation || '-') + '\n' +
      '\tSource Network Address:\t' + (ip || '-') + '\n' +
      '\tSource Port:\t\t51544';
  }

  function msg4720(newAcct, domain, actor) {
    return 'A user account was created.\n\n' +
      'Subject:\n' +
      '\tSecurity ID:\t\tS-1-5-21-1000000000-2000000000-3000000000-500\n' +
      '\tAccount Name:\t\t' + actor + '\n' +
      '\tAccount Domain:\t\t' + domain + '\n' +
      '\tLogon ID:\t\t0x2F1A4\n\n' +
      'New Account:\n' +
      '\tSecurity ID:\t\tS-1-5-21-1000000000-2000000000-3000000000-1105\n' +
      '\tAccount Name:\t\t' + newAcct + '\n' +
      '\tAccount Domain:\t\t' + domain + '\n\n' +
      'Attributes:\n' +
      '\tSAM Account Name:\t' + newAcct + '\n' +
      '\tDisplay Name:\t\t' + newAcct + '\n' +
      '\tUser Principal Name:\t' + newAcct + '@example.invalid\n' +
      '\tPassword Last Set:\t14/09/2026 09:41:02\n' +
      '\tAccount Expires:\t\tNever';
  }

  function msg4726(deletedAcct, domain, actor) {
    return 'A user account was deleted.\n\n' +
      'Subject:\n' +
      '\tSecurity ID:\t\tS-1-5-21-1000000000-2000000000-3000000000-500\n' +
      '\tAccount Name:\t\t' + actor + '\n' +
      '\tAccount Domain:\t\t' + domain + '\n' +
      '\tLogon ID:\t\t0x2F1A4\n\n' +
      'Target Account:\n' +
      '\tSecurity ID:\t\tS-1-5-21-1000000000-2000000000-3000000000-1105\n' +
      '\tAccount Name:\t\t' + deletedAcct + '\n' +
      '\tAccount Domain:\t\t' + domain;
  }

  function msgGroupAdd(groupName, groupDomain, member, memberDomain, actor, domain) {
    return 'A member was added to a security-enabled security group.\n\n' +
      'Subject:\n' +
      '\tSecurity ID:\t\tS-1-5-21-1000000000-2000000000-3000000000-500\n' +
      '\tAccount Name:\t\t' + actor + '\n' +
      '\tAccount Domain:\t\t' + domain + '\n' +
      '\tLogon ID:\t\t0x2F1A4\n\n' +
      'Member:\n' +
      '\tSecurity ID:\t\tS-1-5-21-1000000000-2000000000-3000000000-1105\n' +
      '\tAccount Name:\t\t' + member + '\n' +
      '\tAccount Domain:\t\t' + memberDomain + '\n\n' +
      'Group:\n' +
      '\tSecurity ID:\t\tS-1-5-32-544\n' +
      '\tGroup Name:\t\t' + groupName + '\n' +
      '\tGroup Domain:\t\t' + groupDomain;
  }

  function msg1102(actor, domain) {
    return 'The audit log was cleared.\n\n' +
      'Subject:\n' +
      '\tSecurity ID:\t\tS-1-5-21-1000000000-2000000000-3000000000-500\n' +
      '\tAccount Name:\t\t' + actor + '\n' +
      '\tDomain Name:\t\t' + domain + '\n' +
      '\tLogon ID:\t\t0x2F1A4';
  }

  function msg4688(account, domain, process, commandLine, parent) {
    return 'A new process has been created.\n\n' +
      'Creator Subject:\n' +
      '\tSecurity ID:\t\tS-1-5-21-1000000000-2000000000-3000000000-1001\n' +
      '\tAccount Name:\t\t' + account + '\n' +
      '\tAccount Domain:\t\t' + domain + '\n' +
      '\tLogon ID:\t\t0x8DCDC\n\n' +
      'Process Information:\n' +
      '\tNew Process ID:\t\t0x1a2b\n' +
      '\tNew Process Name:\t' + process + '\n' +
      '\tCreator Process ID:\t0x9c4\n' +
      '\tCreator Process Name:\t' + parent + '\n' +
      '\tProcess Command Line:\t' + commandLine;
  }

  function msg4104(scriptText, path) {
    return 'Creating Scriptblock text (1 of 1):\n' + scriptText + '\n\n' +
      'ScriptBlock ID: 8f2c1a44-3b7e-4c1d-9a55-1f4d2e6b7c88\n' +
      'Path: ' + (path || '');
  }

  function msg7045(serviceName, imagePath, startType, account) {
    return 'A service was installed in the system.\n\n' +
      'Service Name:  ' + serviceName + '\n' +
      'Service File Name:  ' + imagePath + '\n' +
      'Service Type:  user mode service\n' +
      'Service Start Type:  ' + startType + '\n' +
      'Service Account:  ' + account;
  }

  function msg4672(acct, domain) {
    return 'Special privileges assigned to new logon.\n\n' +
      'Subject:\n' +
      '\tSecurity ID:\t\tS-1-5-21-1000000000-2000000000-3000000000-500\n' +
      '\tAccount Name:\t\t' + acct + '\n' +
      '\tAccount Domain:\t\t' + domain + '\n' +
      '\tLogon ID:\t\t0x2F1A4\n\n' +
      'Privileges:\t\tSeSecurityPrivilege\n' +
      '\t\t\tSeBackupPrivilege\n' +
      '\t\t\tSeRestorePrivilege\n' +
      '\t\t\tSeTakeOwnershipPrivilege';
  }

  /* Fields capture the Account column the way Event Viewer does: DOMAIN\\user. */
  function domUser(domain, user) { return domain + '\\' + user; }

  /* Row helpers.
     Column order matches an Event Viewer GUI CSV export:
     Keywords, Date and Time, Source, Event ID, Task Category, Level, Opcode,
     User, Computer, Message */
  function secRow(time, id, task, user, computer, msg, keyword) {
    return [keyword || 'Audit Success', time, 'Microsoft-Windows-Security-Auditing',
            id, task, 'Information', 'Info', user, computer, msg];
  }
  function psRow(time, user, computer, msg) {
    return ['', time, 'Microsoft-Windows-PowerShell', 4104, 'ExecuteCommand',
            'Information', 'Info', user, computer, msg];
  }
  function svcRow(time, computer, msg) {
    return ['', time, 'Service Control Manager', 7045, 'General', 'Information',
            'Info', 'SYSTEM', computer, msg];
  }

  var WS = { js: 'WS-JSMITH', ak: 'WS-AKHAN', mw: 'WS-MWALKER', admin: 'WS-ADMIN01',
             lab: 'WS-LAB03', srv: 'SRV-FILES01' };

  /* --- Demo dataset 1: ordinary activity ---------------------------------- */
  function sampleNormal() {
    return rowsToCsv([CSV_HEADER,
      secRow('9/14/2026 8:00:03 AM', 4624, 'Logon', domUser('CORP', 'jsmith'), WS.js,
        msg4624('jsmith', 'CORP', '2', '10.20.30.21', WS.js, false)),
      secRow('9/14/2026 8:00:05 AM', 4672, 'Special Logon', domUser('CORP', 'jsmith'), WS.js,
        msg4672('jsmith', 'CORP')),
      secRow('9/14/2026 8:00:12 AM', 4688, 'Process Creation', domUser('CORP', 'jsmith'), WS.js,
        msg4688('jsmith', 'CORP', 'C:\\Windows\\explorer.exe', 'C:\\Windows\\explorer.exe',
                'C:\\Windows\\System32\\userinit.exe')),
      secRow('9/14/2026 8:15:41 AM', 4624, 'Logon', domUser('CORP', 'akhan'), WS.ak,
        msg4624('akhan', 'CORP', '2', '10.20.30.22', WS.ak, false)),
      secRow('9/14/2026 8:16:02 AM', 4688, 'Process Creation', domUser('CORP', 'akhan'), WS.ak,
        msg4688('akhan', 'CORP', 'C:\\Program Files\\Microsoft Office\\OUTLOOK.EXE',
                'C:\\Program Files\\Microsoft Office\\OUTLOOK.EXE',
                'C:\\Windows\\explorer.exe')),
      secRow('9/14/2026 9:02:11 AM', 4625, 'Logon', '-', WS.srv,
        msg4625('jsmith', 'CORP', '3', '10.20.30.21', WS.js,
                'Unknown user name or bad password.'), 'Audit Failure'),
      secRow('9/14/2026 9:02:29 AM', 4624, 'Logon', domUser('CORP', 'jsmith'), WS.srv,
        msg4624('jsmith', 'CORP', '3', '10.20.30.21', WS.js, false)),
      secRow('9/14/2026 11:20:44 AM', 4624, 'Logon', domUser('CORP', 'mwalker'), WS.mw,
        msg4624('mwalker', 'CORP', '10', '10.20.30.55', WS.mw, false)),
      psRow('9/14/2026 11:21:03 AM', domUser('CORP', 'mwalker'), WS.mw,
        msg4104("Get-Service | Where-Object {$_.Status -eq 'Running'}", '')),
      secRow('9/14/2026 1:45:19 PM', 4625, 'Logon', '-', WS.ak,
        msg4625('akhan', 'CORP', '2', '-', WS.ak,
                'Unknown user name or bad password.'), 'Audit Failure'),
      secRow('9/14/2026 1:45:33 PM', 4624, 'Logon', domUser('CORP', 'akhan'), WS.ak,
        msg4624('akhan', 'CORP', '2', '10.20.30.22', WS.ak, false)),
      secRow('9/14/2026 3:30:08 PM', 4688, 'Process Creation', domUser('CORP', 'mwalker'), WS.mw,
        msg4688('mwalker', 'CORP', 'C:\\Windows\\System32\\ipconfig.exe',
                'ipconfig /all', 'C:\\Windows\\System32\\cmd.exe')),
      secRow('9/14/2026 4:05:55 PM', 4624, 'Logon', domUser('CORP', 'Administrator'), WS.admin,
        msg4624('Administrator', 'CORP', '2', '10.20.30.10', WS.admin, true)),
      secRow('9/14/2026 4:06:10 PM', 4672, 'Special Logon', domUser('CORP', 'Administrator'), WS.admin,
        msg4672('Administrator', 'CORP')),
      secRow('9/14/2026 5:30:00 PM', 4688, 'Process Creation', domUser('CORP', 'jsmith'), WS.js,
        msg4688('jsmith', 'CORP', 'C:\\Windows\\System32\\notepad.exe',
                '"C:\\Users\\jsmith\\Desktop\\notes.txt"', 'C:\\Windows\\explorer.exe'))
    ]);
  }

  /* --- Demo dataset 2: password guessing followed by success --------------- */
  function samplePasswordGuessing() {
    var rows = [CSV_HEADER,
      secRow('9/14/2026 9:00:00 AM', 4624, 'Logon', domUser('CORP', 'akhan'), WS.ak,
        msg4624('akhan', 'CORP', '2', '10.20.30.22', WS.ak, false)),
      secRow('9/14/2026 9:05:00 AM', 4688, 'Process Creation', domUser('CORP', 'akhan'), WS.ak,
        msg4688('akhan', 'CORP', 'C:\\Windows\\System32\\cmd.exe', 'cmd.exe',
                'C:\\Windows\\explorer.exe'))
    ];

    /* Eight failed logons for one account, from one address, in about three
       minutes. Eight is above the default threshold of five. */
    var failures = ['10:12:01 AM', '10:12:19 AM', '10:12:37 AM', '10:12:55 AM',
                    '10:13:21 AM', '10:13:48 AM', '10:14:10 AM', '10:14:39 AM'];
    failures.forEach(function (t) {
      rows.push(secRow('9/14/2026 ' + t, 4625, 'Logon', '-', WS.lab,
        msg4625('jsmith', 'CORP', '3', '192.168.77.41', WS.lab,
                'Unknown user name or bad password.'), 'Audit Failure'));
    });

    /* Then a successful logon for the same account from the same address. */
    rows.push(secRow('9/14/2026 10:15:02 AM', 4624, 'Logon', domUser('CORP', 'jsmith'), WS.lab,
      msg4624('jsmith', 'CORP', '3', '192.168.77.41', WS.lab, false)));
    rows.push(secRow('9/14/2026 10:15:20 AM', 4688, 'Process Creation', domUser('CORP', 'jsmith'), WS.lab,
      msg4688('jsmith', 'CORP', 'C:\\Windows\\System32\\cmd.exe', 'cmd.exe /c whoami /all',
              'C:\\Windows\\System32\\cmd.exe')));
    return rowsToCsv(rows);
  }

  /* --- Demo dataset 3: account created, then granted privileges ----------- */
  function sampleAccountPersistence() {
    return rowsToCsv([CSV_HEADER,
      secRow('9/14/2026 2:02:00 PM', 4624, 'Logon', domUser('CORP', 'Administrator'), WS.admin,
        msg4624('Administrator', 'CORP', '2', '10.20.30.10', WS.admin, true)),
      secRow('9/14/2026 2:03:11 PM', 4720, 'User Account Management',
        domUser('CORP', 'Administrator'), WS.admin, msg4720('temp-admin', 'CORP', 'Administrator')),
      secRow('9/14/2026 2:07:44 PM', 4732, 'Security Group Management',
        domUser('CORP', 'Administrator'), WS.admin,
        msgGroupAdd('Administrators', 'BUILTIN', 'temp-admin', 'CORP',
                    'Administrator', 'CORP')),
      secRow('9/14/2026 2:08:02 PM', 4672, 'Special Logon', domUser('CORP', 'temp-admin'), WS.admin,
        msg4672('temp-admin', 'CORP')),
      secRow('9/14/2026 2:08:15 PM', 4688, 'Process Creation', domUser('CORP', 'temp-admin'), WS.admin,
        msg4688('temp-admin', 'CORP', 'C:\\Windows\\System32\\cmd.exe', 'cmd.exe',
                'C:\\Windows\\System32\\cmd.exe')),
      secRow('9/14/2026 2:20:00 PM', 4624, 'Logon', domUser('CORP', 'temp-admin'), WS.admin,
        msg4624('temp-admin', 'CORP', '2', '10.20.30.10', WS.admin, true))
    ]);
  }

  /* --- Demo dataset 4: mixed suspicious administrative activity ----------- */
  /* The long string is the real Base64 encoding of a fictional PowerShell
     command, so the demo data looks exactly like something an analyst would
     meet in the wild. The address 203.0.113.77 is from the reserved TEST-NET-3
     range (RFC 5737) and 198.51.100.9 from TEST-NET-2; neither can be routed
     on the internet. */
  var ENC_B64 = 'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMA' +
                'bABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0' +
                'AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADkALwBwAC4AcABzADEAJwApAA==';

  function sampleMixed() {
    var rows = [CSV_HEADER,
      secRow('9/14/2026 1:58:00 AM', 4624, 'Logon', domUser('CORP', 'jsmith'), WS.js,
        msg4624('jsmith', 'CORP', '2', '10.20.30.21', WS.js, false))
    ];

    /* Six failed logons for one account from one unfamiliar address. */
    ['2:06:05 AM', '2:06:23 AM', '2:06:41 AM', '2:07:02 AM', '2:07:29 AM', '2:07:55 AM']
      .forEach(function (t) {
        rows.push(secRow('9/14/2026 ' + t, 4625, 'Logon', '-', WS.lab,
          msg4625('jsmith', 'CORP', '10', '203.0.113.77', WS.lab,
                  'Unknown user name or bad password.'), 'Audit Failure'));
      });

    /* Then a successful logon from the same address. */
    rows.push(secRow('9/14/2026 2:08:31 AM', 4624, 'Logon', domUser('CORP', 'jsmith'), WS.lab,
      msg4624('jsmith', 'CORP', '10', '203.0.113.77', WS.lab, false)));

    /* A new account is created by the compromised user, then given power. */
    rows.push(secRow('9/14/2026 2:09:12 AM', 4688, 'Process Creation', domUser('CORP', 'jsmith'), WS.lab,
      msg4688('jsmith', 'CORP', 'C:\\Windows\\System32\\net.exe',
              'net user svc-backup2 /add', 'C:\\Windows\\System32\\cmd.exe')));
    rows.push(secRow('9/14/2026 2:11:40 AM', 4720, 'User Account Management',
      domUser('CORP', 'jsmith'), WS.lab, msg4720('svc-backup2', 'CORP', 'jsmith')));
    rows.push(secRow('9/14/2026 2:12:30 AM', 4732, 'Security Group Management',
      domUser('CORP', 'jsmith'), WS.lab,
      msgGroupAdd('Administrators', 'BUILTIN', 'svc-backup2', 'CORP', 'jsmith', 'CORP')));
    rows.push(secRow('9/14/2026 2:14:02 AM', 4732, 'Security Group Management',
      domUser('CORP', 'jsmith'), WS.lab,
      msgGroupAdd('Remote Desktop Users', 'BUILTIN', 'svc-backup2', 'CORP', 'jsmith', 'CORP')));

    /* Encoded PowerShell, seen first in the command line then in the log. */
    rows.push(secRow('9/14/2026 2:15:20 AM', 4688, 'Process Creation',
      domUser('CORP', 'svc-backup2'), WS.lab,
      msg4688('svc-backup2', 'CORP', 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
              'powershell.exe -nop -w hidden -enc ' + ENC_B64,
              'C:\\Windows\\System32\\cmd.exe')));
    rows.push(psRow('9/14/2026 2:15:26 AM', domUser('CORP', 'svc-backup2'), WS.lab,
      msg4104("$c = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('" +
              ENC_B64 + "')); Invoke-Expression $c", '')));

    /* A new service, installed from a user-writable folder. */
    rows.push(svcRow('9/14/2026 2:18:47 AM', WS.srv,
      msg7045('DemoUpdater', 'C:\\ProgramData\\DemoUpdater\\updater.exe',
              'auto start', 'LocalSystem')));

    /* The Security log is cleared, then an account is removed. */
    rows.push(secRow('9/14/2026 2:31:05 AM', 1102, 'Audit Log Cleared', domUser('CORP', 'jsmith'),
      WS.lab, msg1102('jsmith', 'CORP')));
    rows.push(secRow('9/14/2026 3:02:00 AM', 4726, 'User Account Management',
      domUser('CORP', 'Administrator'), WS.admin, msg4726('temp-admin', 'CORP', 'Administrator')));

    /* Later, ordinary administrative work, to show the dataset is not uniform. */
    rows.push(secRow('9/14/2026 3:20:00 AM', 4624, 'Logon', domUser('CORP', 'Administrator'), WS.admin,
      msg4624('Administrator', 'CORP', '2', '10.20.30.10', WS.admin, true)));

    return rowsToCsv(rows);
  }

  /* Registry of demo datasets used by both the buttons and the report label. */
  var SAMPLES = {
    normal: {
      key: 'normal',
      label: 'Normal Windows activity',
      file: 'samples/normal-windows-events.csv',
      expect: 'Mostly informational activity, with no high-priority alerts.',
      build: sampleNormal
    },
    password: {
      key: 'password',
      label: 'Password guessing',
      file: 'samples/password-guessing.csv',
      expect: 'Repeated Failed Logons, then a Possible Password Guessing Followed By Success alert.',
      build: samplePasswordGuessing
    },
    persistence: {
      key: 'persistence',
      label: 'Privilege escalation',
      file: 'samples/account-persistence.csv',
      expect: 'A New Account Granted Privileges alert.',
      build: sampleAccountPersistence
    },
    mixed: {
      key: 'mixed',
      label: 'Mixed SOC activity',
      file: 'samples/suspicious-admin-activity.csv',
      expect: 'Several correlated findings, including log clearing and privilege changes.',
      build: sampleMixed
    }
  };

  /* ======================= 5. DOM UTILITIES =============================== */
  /* Small helpers. The security rule is centralised here: esc() is the only
     way untrusted text is ever placed into an HTML template. */

  function $(id) { return document.getElementById(id); }

  function esc(value) {
    if (value === null || value === undefined) { return ''; }
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function show(node) { if (node) { node.hidden = false; } }
  function hide(node) { if (node) { node.hidden = true; } }

  function setText(node, text) { if (node) { node.textContent = text; } }

  function clearChildren(node) {
    if (!node) { return; }
    while (node.firstChild) { node.removeChild(node.firstChild); }
  }

  function makeEl(tag, className, text) {
    var node = document.createElement(tag);
    if (className) { node.className = className; }
    if (text !== undefined && text !== null) { node.textContent = String(text); }
    return node;
  }

  function setStatus(node, kind, message) {
    if (!node) { return; }
    node.className = 'status status-' + kind;
    node.innerHTML = message;   // callers pass pre-escaped markup only
    show(node);
  }

  /* ======================= 6. CSV PARSER (RFC 4180) ====================== */
  /* A real character-by-character parser rather than split(','), because:
       - the Windows Message column contains commas
       - the Windows Message column contains line breaks inside quoted fields
       - quoted fields may contain escaped quotes written as ""            */

  function stripBom(text) {
    if (text && text.charCodeAt(0) === 0xFEFF) { return text.slice(1); }
    return text;
  }

  function countOutsideQuotes(line, delimiter) {
    var inQuotes = false;
    var count = 0;
    for (var i = 0; i < line.length; i++) {
      var ch = line.charAt(i);
      if (ch === '"') {
        if (inQuotes && line.charAt(i + 1) === '"') { i++; continue; }
        inQuotes = !inQuotes;
      } else if (ch === delimiter && !inQuotes) {
        count++;
      }
    }
    return count;
  }

  function detectDelimiter(text) {
    var sample = text.slice(0, 8000);
    var lines = sample.split(/\r?\n/);
    var header = '';
    for (var i = 0; i < lines.length; i++) {
      if (lines[i].trim() !== '') { header = lines[i]; break; }
    }
    var candidates = [',', ';', '\t', '|'];
    var best = ',';
    var bestCount = -1;
    for (var c = 0; c < candidates.length; c++) {
      var n = countOutsideQuotes(header, candidates[c]);
      if (n > bestCount) { bestCount = n; best = candidates[c]; }
    }
    return best;
  }

  function parseCsvText(text, delimiter) {
    var rows = [];
    var row = [];
    var field = '';
    var inQuotes = false;
    var i = 0;
    var length = text.length;
    var truncatedAtRowLimit = false;

    while (i < length) {
      var ch = text.charAt(i);

      if (inQuotes) {
        if (ch === '"') {
          if (text.charAt(i + 1) === '"') { field += '"'; i += 2; continue; }
          inQuotes = false; i++; continue;
        }
        field += ch; i++; continue;
      }

      if (ch === '"') {
        if (field.trim() === '') { field = ''; inQuotes = true; i++; continue; }
        field += ch; i++; continue;
      }

      if (ch === delimiter) { row.push(field); field = ''; i++; continue; }

      if (ch === '\r') {
        if (text.charAt(i + 1) === '\n') { i++; }
        row.push(field); rows.push(row);
        row = []; field = ''; i++;
        if (rows.length >= LIMITS.maxRows) { truncatedAtRowLimit = true; break; }
        continue;
      }

      if (ch === '\n') {
        row.push(field); rows.push(row);
        row = []; field = ''; i++;
        if (rows.length >= LIMITS.maxRows) { truncatedAtRowLimit = true; break; }
        continue;
      }

      field += ch; i++;
    }

    if (!truncatedAtRowLimit && (field !== '' || row.length > 0)) {
      row.push(field);
      rows.push(row);
    }

    /* Drop fully empty trailing rows produced by a final newline. */
    while (rows.length > 0 && rows[rows.length - 1].every(function (v) {
      return String(v).trim() === '';
    })) {
      rows.pop();
    }

    return { rows: rows, truncatedAtRowLimit: truncatedAtRowLimit, unclosedQuote: inQuotes };
  }

  /* ======================= 7. COLUMN MAPPING ============================= */

  function normaliseHeader(name) {
    return String(name === null || name === undefined ? '' : name)
      .toLowerCase()
      .replace(/[^a-z0-9]/g, '');
  }

  function buildColumnMap(headerRow) {
    var normalised = headerRow.map(normaliseHeader);
    var map = {};
    var keys = Object.keys(COLUMN_ALIASES);

    function firstIndex(list) {
      for (var i = 0; i < list.length; i++) {
        var idx = normalised.indexOf(list[i]);
        if (idx !== -1) { return idx; }
      }
      return -1;
    }

    keys.forEach(function (key) {
      var idx = firstIndex(COLUMN_ALIASES[key]);
      if (idx === -1 && LOCALISED_ALIASES[key]) {
        idx = firstIndex(LOCALISED_ALIASES[key]);
      }
      if (idx !== -1) { map[key] = idx; }
    });

    return { map: map, normalised: normalised, raw: headerRow };
  }

  function readCell(cells, columnMap, key) {
    var idx = columnMap.map[key];
    if (idx === undefined || idx === null || idx < 0 || idx >= cells.length) { return ''; }
    return String(cells[idx] === null || cells[idx] === undefined ? '' : cells[idx]).trim();
  }

  function extractEventId(raw) {
    var m = String(raw === null || raw === undefined ? '' : raw).match(/(\d{1,7})/);
    if (!m) { return null; }
    return parseInt(m[1], 10);
  }

  /* ======================= 8. TIMESTAMP PARSING ========================== */
  /* Windows CSV exports normally contain local time with no timezone offset,
     so the value is kept as written for display. The Date object is only used
     for ordering and time-window maths. */

  var MONTH_DAY_AMBIGUITY = { seen: false, examples: [] };

  function parseLooseDateTime(s) {
    var m = String(s).match(
      /^(\d{1,2})[\/\-.](\d{1,2})[\/\-.](\d{2,4})(?:[ T]+(\d{1,2}):(\d{2})(?::(\d{2}))?)?\s*([AaPp][Mm])?$/
    );
    if (!m) { return null; }

    var p1 = parseInt(m[1], 10);
    var p2 = parseInt(m[2], 10);
    var year = parseInt(m[3], 10);
    if (year < 100) { year += 2000; }

    var hour = m[4] ? parseInt(m[4], 10) : 0;
    var min = m[5] ? parseInt(m[5], 10) : 0;
    var sec = m[6] ? parseInt(m[6], 10) : 0;
    var ap = m[7] ? m[7].toLowerCase() : '';

    var month, day;
    if (p1 > 12) { day = p1; month = p2; }
    else if (p2 > 12) { month = p1; day = p2; }
    else if (ap) { month = p1; day = p2; }       // AM/PM implies month-first
    else { month = p1; day = p2; }

    if (ap === 'pm' && hour < 12) { hour += 12; }
    if (ap === 'am' && hour === 12) { hour = 0; }

    var d = new Date(year, month - 1, day, hour, min, sec);
    if (isNaN(d.getTime())) { return null; }
    return d;
  }

  function parseTimestamp(raw) {
    var s = String(raw === null || raw === undefined ? '' : raw).trim();
    var info = { date: null, raw: s, ambiguous: false };
    if (!s) { return info; }

    var hasAmPm = /\b(am|pm)\b/i.test(s);
    var date = new Date(s);

    if (isNaN(date.getTime())) {
      date = parseLooseDateTime(s);
    }

    if (date && !isNaN(date.getTime())) {
      info.date = date;
    } else {
      /* Try a trailing-or-leading ISO fragment, e.g. 2026-09-14T02:15:20. */
      var iso = s.match(/(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?)/);
      if (iso) {
        var d2 = new Date(iso[1].replace(' ', 'T'));
        if (!isNaN(d2.getTime())) { info.date = d2; }
      }
    }

    /* Record genuine month/day ambiguity rather than silently guessing. */
    var nums = s.match(/^(\d{1,2})[\/\-.](\d{1,2})[\/\-.](\d{4})/);
    if (nums && !hasAmPm) {
      var a = parseInt(nums[1], 10);
      var b = parseInt(nums[2], 10);
      if (a <= 12 && b <= 12 && a !== b) {
        info.ambiguous = true;
        MONTH_DAY_AMBIGUITY.seen = true;
        if (MONTH_DAY_AMBIGUITY.examples.length < 3) {
          MONTH_DAY_AMBIGUITY.examples.push(s);
        }
      }
    }

    return info;
  }

  /* ======================= 9. MESSAGE FIELD EXTRACTION =================== */
  /* Windows puts the useful detail inside one multi-line Message column, in
     "Label: value" form, grouped into sections such as "Subject:" and
     "New Logon:". The same label can appear in several sections, so values are
     read by SECTION first and label second. This is what makes the parser
     survive layout differences between Windows versions. */

  function escapeRegex(s) {
    return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  function cleanValue(v, keepSpacing) {
    var s = String(v === null || v === undefined ? '' : v).replace(/[\t\r]/g, ' ').trim();
    if (s === '' || s === '-') { return ''; }
    return keepSpacing ? s : s.replace(/\s{2,}/g, ' ');
  }

  var SECTION_HEADER_RE = /^([A-Za-z][A-Za-z0-9 \/\-\(\)\.']{0,50}):\s*$/;

  function splitMessageSections(message) {
    var text = String(message === null || message === undefined ? '' : message)
      .replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    var lines = text.split('\n');
    var order = ['__root__'];
    var buckets = { '__root__': [] };
    var current = '__root__';

    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      var m = line.match(SECTION_HEADER_RE);
      if (m) {
        var name = m[1].trim().toLowerCase();
        if (name !== '') {
          current = name;
          if (!buckets[current]) { buckets[current] = []; order.push(current); }
          continue;
        }
      }
      buckets[current].push(line);
    }

    var sections = {};
    Object.keys(buckets).forEach(function (key) {
      sections[key] = buckets[key].join('\n');
    });
    return {
      order: order,
      sections: sections,
      root: sections['__root__'] || '',
      rawMessage: text
    };
  }

  function findLabel(text, label, keepSpacing) {
    if (!text) { return ''; }
    var re = new RegExp('(?:^|\\n)[ \\t]*' + escapeRegex(label) + '[ \\t]*:[ \\t]*([^\\n]*)', 'i');
    var m = String(text).match(re);
    if (!m) { return ''; }
    return cleanValue(m[1], keepSpacing);
  }

  /* Search a list of section names in priority order, then fall back to root. */
  function labelIn(split, sectionNames, label, keepSpacing) {
    for (var i = 0; i < sectionNames.length; i++) {
      var name = String(sectionNames[i]).toLowerCase();
      var value = findLabel(split.sections[name], label, keepSpacing);
      if (value) { return value; }
    }
    return findLabel(split.root, label, keepSpacing);
  }

  /* PowerShell script block text needs its own pattern: it can be many lines
     long and contains arbitrary characters. */
  function extractScriptBlock(message) {
    var text = String(message === null || message === undefined ? '' : message)
      .replace(/\r\n/g, '\n');
    var m = text.match(
      /Creating Scriptblock text[^\n]*:\s*\n([\s\S]*?)(?:\n\s*ScriptBlock ID:|\n\s*Path:|$)/i
    );
    if (m) { return m[1].replace(/\s+$/, ''); }
    return '';
  }

  /* --- Account classification -------------------------------------------- */

  function isMachineAccountName(name) {
    var n = String(name || '').trim();
    if (!n) { return false; }
    if (n.slice(-1) === '$') { return true; }
    if (/^(DWM|UMFD)-\d+$/i.test(n)) { return true; }
    return false;
  }

  function isNoiseAccount(name) {
    var n = String(name || '').trim().toLowerCase();
    if (!n) { return true; }
    if (NOISE_ACCOUNTS.indexOf(n) !== -1) { return true; }
    if (isMachineAccountName(name)) { return true; }
    return false;
  }

  function displayAccount(account, domain) {
    var a = String(account || '').trim();
    var d = String(domain || '').trim();
    if (!a) { return ''; }
    if (d && d !== '-' && d.toUpperCase() !== 'WORKGROUP' && a.indexOf('\\') === -1) {
      return d + '\\' + a;
    }
    return a;
  }

  /* --- Per-event detail extraction --------------------------------------- */

  function extractDetails(id, split) {
    var d = {};

    function inSections(names, label, keepSpacing) {
      return labelIn(split, names, label, keepSpacing);
    }

    if (id === 4624) {
      d.account = inSections(['new logon'], 'Account Name');
      d.accountDomain = inSections(['new logon'], 'Account Domain');
      d.actor = inSections(['subject'], 'Account Name');
      d.actorDomain = inSections(['subject'], 'Account Domain');
      d.logonType = inSections(['logon information', 'new logon'], 'Logon Type');
      d.sourceIp = inSections(['network information'], 'Source Network Address');
      d.workstation = inSections(['network information'], 'Workstation Name');
      d.processName = inSections(['process information'], 'Process Name');
      d.elevated = inSections(['logon information'], 'Elevated Token');

    } else if (id === 4625) {
      d.account = inSections(['account for which logon failed'], 'Account Name');
      d.accountDomain = inSections(['account for which logon failed'], 'Account Domain');
      d.logonType = inSections(['subject'], 'Logon Type');
      d.failureReason = findLabel(split.sections['failure information'], 'Failure Reason');
      d.sourceIp = inSections(['network information'], 'Source Network Address');
      d.workstation = inSections(['network information'], 'Workstation Name');

    } else if (id === 4720) {
      d.account = inSections(['new account'], 'Account Name');
      d.accountDomain = inSections(['new account'], 'Account Domain');
      d.actor = inSections(['subject'], 'Account Name');
      d.actorDomain = inSections(['subject'], 'Account Domain');

    } else if (id === 4726) {
      d.account = inSections(['target account'], 'Account Name');
      d.accountDomain = inSections(['target account'], 'Account Domain');
      d.actor = inSections(['subject'], 'Account Name');
      d.actorDomain = inSections(['subject'], 'Account Domain');

    } else if (id === 4728 || id === 4732) {
      d.account = inSections(['member'], 'Account Name');
      d.accountDomain = inSections(['member'], 'Account Domain');
      d.groupName = inSections(['group'], 'Group Name');
      d.groupDomain = inSections(['group'], 'Group Domain');
      d.actor = inSections(['subject'], 'Account Name');
      d.actorDomain = inSections(['subject'], 'Account Domain');

    } else if (id === 1102) {
      d.account = inSections(['subject'], 'Account Name');
      d.accountDomain = inSections(['subject'], 'Domain Name');
      d.actor = d.account;
      d.actorDomain = d.accountDomain;

    } else if (id === 4688) {
      d.account = inSections(['creator subject', 'subject'], 'Account Name');
      d.accountDomain = inSections(['creator subject', 'subject'], 'Account Domain');
      d.actor = d.account;
      d.processName = inSections(['process information'], 'New Process Name');
      d.commandLine = inSections(['process information'], 'Process Command Line', true);
      d.parentProcess = inSections(['process information'], 'Creator Process Name');

    } else if (id === 4104) {
      d.scriptBlock = extractScriptBlock(split.rawMessage || '');
      d.scriptPath = findLabel(split.root, 'Path', true);

    } else if (id === 7045) {
      d.serviceName = findLabel(split.root, 'Service Name');
      d.servicePath = findLabel(split.root, 'Service File Name', true);
      d.serviceStartType = findLabel(split.root, 'Service Start Type');
      d.serviceAccount = findLabel(split.root, 'Service Account');

    } else if (id === 4672) {
      d.account = inSections(['subject'], 'Account Name');
      d.accountDomain = inSections(['subject'], 'Account Domain');
      d.actor = d.account;
      d.actorDomain = d.accountDomain;
    }

    return d;
  }

  /* ======================= 10. EVENT NORMALISATION ======================= */

  function splitUserColumn(value) {
    var v = String(value || '').trim();
    if (!v || v === '-') { return { domain: '', user: '' }; }
    var idx = v.indexOf('\\');
    if (idx > -1) {
      return { domain: v.slice(0, idx), user: v.slice(idx + 1) };
    }
    return { domain: '', user: v };
  }

  function isPrivilegedGroup(name) {
    var n = String(name || '').trim().toLowerCase();
    if (!n) { return false; }
    if (PRIVILEGED_GROUPS.indexOf(n) !== -1) { return true; }
    for (var i = 0; i < PRIVILEGED_GROUP_PATTERNS.length; i++) {
      if (PRIVILEGED_GROUP_PATTERNS[i].test(n)) { return true; }
    }
    return false;
  }

  function severityForEvent(eventId, details) {
    var kb = EVID_BY_STRING[String(eventId)];
    var base = kb ? kb.severity : SEVERITY.INFORMATIONAL;

    /* Context raises priority. It never lowers it. */
    if ((eventId === 4728 || eventId === 4732) && isPrivilegedGroup(details.groupName)) {
      return SEVERITY.HIGH;
    }
    return base;
  }

  function makeEvent(cells, columns, rowIndex) {
    var eventIdRaw = readCell(cells, columns, 'eventId');
    var eventId = extractEventId(eventIdRaw);
    if (eventId === null) { return null; }

    var message = readCell(cells, columns, 'message');
    var split = splitMessageSections(message);
    var details = extractDetails(eventId, split);
    var ts = parseTimestamp(readCell(cells, columns, 'timestamp'));
    var userColumn = splitUserColumn(readCell(cells, columns, 'user'));
    var kb = EVID_BY_STRING[String(eventId)];

    var account = details.account || userColumn.user;
    var accountDomain = details.accountDomain || userColumn.domain;

    var ev = {
      index: rowIndex,
      eventId: eventId,
      eventIdRaw: eventIdRaw,
      known: !!kb,
      name: kb ? kb.name : 'Unrecognised Event ID',
      category: kb ? kb.category : 'Other',
      severity: severityForEvent(eventId, details),
      baseSeverity: severityForEvent(eventId, details),
      time: ts.date,
      timeRaw: ts.raw,
      timeAmbiguous: ts.ambiguous,
      source: readCell(cells, columns, 'source'),
      logName: readCell(cells, columns, 'logName'),
      levelRaw: readCell(cells, columns, 'level'),
      computer: readCell(cells, columns, 'computer'),
      account: account || '',
      accountDomain: accountDomain || '',
      displayAccount: displayAccount(account, accountDomain),
      actor: details.actor || '',
      actorDomain: details.actorDomain || '',
      logonType: details.logonType || '',
      sourceIp: details.sourceIp || '',
      workstation: details.workstation || '',
      failureReason: details.failureReason || '',
      processName: details.processName || '',
      commandLine: details.commandLine || '',
      parentProcess: details.parentProcess || '',
      groupName: details.groupName || '',
      groupDomain: details.groupDomain || '',
      serviceName: details.serviceName || '',
      servicePath: details.servicePath || '',
      serviceStartType: details.serviceStartType || '',
      serviceAccount: details.serviceAccount || '',
      scriptBlock: details.scriptBlock || '',
      scriptPath: details.scriptPath || '',
      elevated: details.elevated || '',
      message: message,
      raw: cells
    };

    ev.isNoiseAccount = isNoiseAccount(ev.account);
    ev.hasDetail = !!(ev.sourceIp || ev.logonType || ev.groupName || ev.processName ||
                      ev.serviceName || ev.scriptBlock);

    ev.searchBlob = [
      ev.eventId, ev.name, ev.category, ev.severity, ev.account, ev.actor,
      ev.computer, ev.sourceIp, ev.workstation, ev.logonType, ev.groupName,
      ev.processName, ev.commandLine, ev.parentProcess, ev.serviceName,
      ev.servicePath, ev.scriptBlock, ev.source, ev.logName, ev.message
    ].join(' ').toLowerCase();

    return ev;
  }

  /* ======================= 11. PARSE PIPELINE ============================ */

  function delimiterName(d) {
    if (d === ',') { return 'comma'; }
    if (d === ';') { return 'semicolon'; }
    if (d === '\t') { return 'tab'; }
    if (d === '|') { return 'pipe'; }
    return d;
  }

  function buildDataset(csvText, meta) {
    var result = {
      ok: false,
      errors: [],
      warnings: [],
      events: [],
      skippedRows: 0,
      dataRowCount: 0,
      delimiter: ',',
      delimiterLabel: 'comma',
      columns: null,
      headerRaw: [],
      hasMessageColumn: false,
      hasTimestampColumn: false,
      detailUnavailable: false,
      meta: meta || {},
      stats: null,
      findings: [],
      score: null,
      timeline: [],
      adminGroups: [],
      noiseCount: 0
    };

    var text = stripBom(csvText);

    if (!text || text.replace(/\s/g, '') === '') {
      result.errors.push('The file is empty, or contains only whitespace. ' +
        'Export the events again and check that the saved file is not zero bytes.');
      return result;
    }

    result.delimiter = detectDelimiter(text);
    result.delimiterLabel = delimiterName(result.delimiter);

    var parsed = parseCsvText(text, result.delimiter);
    var rows = parsed.rows;

    if (parsed.unclosedQuote) {
      result.warnings.push('The file contains an unclosed quotation mark. It was still parsed, but one ' +
        'or more rows may be incomplete &mdash; this usually happens when a CSV has been re-saved by ' +
        'another program such as Excel.');
    }
    if (parsed.truncatedAtRowLimit) {
      result.warnings.push('The file is very large. Only the first ' + LIMITS.maxRows +
        ' rows were analysed so that the browser tab stays responsive.');
    }
    if (rows.length === 0) {
      result.errors.push('No rows could be read from the file.');
      return result;
    }

    var header = rows[0];
    var columns = buildColumnMap(header);
    result.columns = columns;
    result.headerRaw = header;

    if (columns.map.eventId === undefined) {
      result.errors.push('An Event ID column could not be found, so the events cannot be identified. ' +
        'This tool looked for a column named any of: <code>Event ID</code>, <code>EventID</code>, ' +
        '<code>event_id</code>, <code>Id</code>. <strong>Columns found in your file were:</strong> ' +
        esc(header.slice(0, 40).join(' | ')) +
        (header.length > 40 ? ' (&hellip;and ' + (header.length - 40) + ' more)' : ''));
      return result;
    }

    result.hasMessageColumn = columns.map.message !== undefined;
    result.hasTimestampColumn = columns.map.timestamp !== undefined;

    if (!result.hasMessageColumn) {
      result.warnings.push('No Message column was found. Event IDs can still be analysed, but the ' +
        'detail inside each event (account, source IP, logon type, group name) is unavailable, so ' +
        'many findings will be less specific.');
    }
    if (!result.hasTimestampColumn) {
      result.warnings.push('No date/time column was found, or it could not be named. Time-based ' +
        'correlation is disabled and failures are grouped across the whole dataset instead. ' +
        'The timeline section will be empty.');
    }

    var events = [];
    var detailHitCount = 0;
    var nonEmptyMessageCount = 0;

    for (var i = 1; i < rows.length; i++) {
      var cells = rows[i];
      if (!cells || cells.length === 0) { continue; }

      var allEmpty = true;
      for (var c = 0; c < cells.length; c++) {
        if (String(cells[c]).trim() !== '') { allEmpty = false; break; }
      }
      if (allEmpty) { continue; }

      var ev = makeEvent(cells, columns, i);
      if (!ev) { result.skippedRows++; continue; }

      if (ev.hasDetail) { detailHitCount++; }
      if (ev.message && ev.message.trim() !== '') { nonEmptyMessageCount++; }
      if (ev.isNoiseAccount) { result.noiseCount++; }
      events.push(ev);
    }

    result.dataRowCount = rows.length - 1;

    if (result.skippedRows > 0) {
      result.warnings.push(result.skippedRows + ' row(s) were skipped because no Event ID could be ' +
        'read from them. This is normally harmless and can be caused by a trailing summary line.');
    }

    if (events.length === 0) {
      result.errors.push('The file was parsed, but no row contained a usable numeric Event ID. ' +
        'Check that the column listed as the Event ID really contains numbers such as 4624 or 4625.');
      return result;
    }

    if (result.hasMessageColumn && nonEmptyMessageCount > 0 && detailHitCount === 0) {
      result.detailUnavailable = true;
      result.warnings.push('The Message column was found, but none of the expected field labels ' +
        '(such as <code>Account Name:</code>, <code>Logon Type:</code> or <code>Group Name:</code>) ' +
        'could be read from it. This usually means the export came from a Windows installation ' +
        'using a different display language, or that only truncated message text was exported. ' +
        'Event ID level analysis still works.');
    }

    if (MONTH_DAY_AMBIGUITY.seen) {
      result.warnings.push('Some dates are ambiguous (for example ' +
        esc(MONTH_DAY_AMBIGUITY.examples.join(', ')) +
        '). Where no AM/PM marker is present the tool assumes month-first, so ordering and time ' +
        'windows for those rows may be wrong. This is a limitation of the CSV export, not of the events.');
    }

    result.events = events;
    result.ok = true;
    return result;
  }

  /* ======================= 12. TIME HELPERS ============================== */

  function sortedByTime(list) {
    return list.slice().sort(function (a, b) {
      if (a.time && b.time) { return a.time - b.time; }
      if (a.time) { return -1; }
      if (b.time) { return 1; }
      return a.index - b.index;
    });
  }

  function timeRangeLabel(events) {
    if (!events || events.length === 0) { return 'unknown'; }
    var withTime = events.filter(function (e) { return e.time && e.timeRaw; });
    if (withTime.length === 0) {
      return 'not available (no usable timestamps in this dataset)';
    }
    var sorted = sortedByTime(withTime);
    var first = sorted[0].timeRaw;
    var last = sorted[sorted.length - 1].timeRaw;
    if (first === last) { return first; }
    return first + '  \u2192  ' + last;
  }

  function formatDuration(minutes) {
    if (minutes === null || minutes === undefined) { return 'unknown'; }
    if (minutes < 1) { return 'less than a minute'; }
    if (minutes < 60) { return minutes + (minutes === 1 ? ' minute' : ' minutes'); }
    var hours = Math.floor(minutes / 60);
    var mins = minutes % 60;
    var text = hours + (hours === 1 ? ' hour' : ' hours');
    if (mins > 0) { text += ' ' + mins + ' min'; }
    return text;
  }

  function blankFinding() {
    return {
      id: '',
      name: '',
      severity: SEVERITY.INFORMATIONAL,
      eventIds: [],
      account: '',
      accountDomain: '',
      actor: '',
      timeRange: '',
      sourceIp: '',
      workstation: '',
      computer: '',
      observed: [],
      why: '',
      benign: '',
      nextSteps: [],
      evidenceChain: '',
      scorePoints: 0,
      scoreReasons: [],
      events: [],
      notes: []
    };
  }

  function findingEventIds(events) {
    var seen = {};
    var list = [];
    events.forEach(function (e) {
      var key = String(e.eventId);
      if (!seen[key]) { seen[key] = true; list.push(e.eventId); }
    });
    return list;
  }

  function uniqueValues(list, getter) {
    var seen = {};
    var out = [];
    list.forEach(function (item) {
      var v = getter(item);
      if (v && !seen[v]) { seen[v] = true; out.push(v); }
    });
    return out;
  }

  function sameAccount(a, b) {
    if (!a || !b) { return false; }
    return String(a).trim().toLowerCase() === String(b).trim().toLowerCase();
  }

  function isAfter(candidate, reference) {
    if (candidate.time && reference.time) { return candidate.time >= reference.time; }
    return candidate.index > reference.index;
  }

  /* ======================= 13. DETECTION & CORRELATION =================== */
  /* Each rule below is written so that its reasoning reads like a sentence.
     Nothing here claims that a system is compromised. */

  function groupFailedLogons(events) {
    var groups = {};
    events.forEach(function (ev) {
      if (ev.eventId !== 4625) { return; }
      var key = (ev.account || '(unknown account)').toLowerCase();
      if (!groups[key]) {
        groups[key] = {
          key: key,
          account: ev.account || '(unknown account)',
          domain: ev.accountDomain || '',
          events: [],
          ips: {},
          workstations: {},
          reasons: {}
        };
      }
      var g = groups[key];
      g.events.push(ev);
      if (ev.sourceIp) { g.ips[ev.sourceIp] = (g.ips[ev.sourceIp] || 0) + 1; }
      if (ev.workstation) { g.workstations[ev.workstation] = (g.workstations[ev.workstation] || 0) + 1; }
      if (ev.failureReason) { g.reasons[ev.failureReason] = (g.reasons[ev.failureReason] || 0) + 1; }
    });
    return groups;
  }

  function mostCommon(map) {
    var best = '';
    var bestCount = -1;
    Object.keys(map).forEach(function (key) {
      if (map[key] > bestCount) { bestCount = map[key]; best = key; }
    });
    return best;
  }

  /* Largest cluster of events that all fall inside one time window. */
  function largestBurst(list, windowMinutes) {
    var withTime = sortedByTime(list.filter(function (e) { return e.time; }));
    if (withTime.length === 0) { return null; }
    var windowMs = windowMinutes * 60 * 1000;
    var best = null;
    var start = 0;
    for (var end = 0; end < withTime.length; end++) {
      while (withTime[end].time - withTime[start].time > windowMs) { start++; }
      var size = end - start + 1;
      if (!best || size > best.length) {
        best = withTime.slice(start, end + 1);
      }
    }
    return best;
  }

  /* --- Rules 1 and 2: failed logons, and a success that follows ----------- */

  function analyseAuthentication(events, settings) {
    var findings = [];
    var notes = [];
    var groups = groupFailedLogons(events);
    var threshold = settings.failedLoginThreshold;
    var windowMinutes = settings.failedLoginWindowMinutes;
    var successes = events.filter(function (e) { return e.eventId === 4624; });

    Object.keys(groups).forEach(function (key) {
      var g = groups[key];
      var total = g.events.length;
      var timed = g.events.filter(function (e) { return !!e.time; }).length > 0;
      var burst = timed ? largestBurst(g.events, windowMinutes) : null;
      var burstEvents = burst || [];
      var qualifying = null;
      var groupingNote = '';

      if (timed && burstEvents.length >= threshold) {
        qualifying = burstEvents;
      } else if (!timed && total >= threshold) {
        qualifying = g.events;
        groupingNote = 'This dataset contains no usable timestamps, so the ' + windowMinutes +
          '-minute window could not be applied. All ' + total + ' failures for this account were ' +
          'grouped together instead. Bear in mind they may have been spread over a long period.';
      }

      /* Above the threshold, but never clustered inside the window. */
      if (!qualifying && timed && total >= threshold) {
        notes.push(
          'Account ' + g.account + ' failed to log on ' + total +
            ' time(s), but never ' + threshold + ' times inside a ' + windowMinutes +
            '-minute window (the largest burst was ' + burstEvents.length + '). It was therefore ' +
            'not raised as an alert. Changing the threshold or the window would change that result ' +
            '\u2014 which is exactly how tuning produces different outcomes.'
        );
      }

      /* Below the threshold: explained rather than quietly ignored. */
      if (!qualifying && total < threshold) {
        notes.push(
          'Account ' + g.account + ' had ' + total +
            ' failed logon(s), which is below the current threshold of ' + threshold +
            '. No alert was raised. One or two failures are usually just a mistyped password.'
        );
      }

      if (!qualifying) { return; }

      var ips = Object.keys(g.ips);
      var workstations = Object.keys(g.workstations);
      var ipLabel = ips.length ? ips.join(', ') : 'not present in this export';
      var wsLabel = workstations.length ? workstations.join(', ') : 'not present in this export';
      var chain = qualifying.map(function () { return '4625'; }).join(' \u2192 ');

      /* ------------------ Rule 1: repeated failed logons ---------------- */
      var r1 = blankFinding();
      r1.id = 'repeated-failed-logons';
      r1.name = 'REPEATED FAILED LOGONS';
      r1.severity = qualifying.length >= threshold * 2 ? SEVERITY.MEDIUM : SEVERITY.LOW;
      r1.eventIds = [4625];
      r1.account = g.account;
      r1.accountDomain = g.domain;
      r1.timeRange = timeRangeLabel(qualifying);
      r1.sourceIp = ips.join(', ');
      r1.workstation = workstations.join(', ');
      r1.computer = uniqueValues(qualifying, function (e) { return e.computer; }).join(', ');
      r1.events = qualifying;
      r1.evidenceChain = chain;
      r1.observed = [
        'Account: ' + g.account,
        'Failures: ' + qualifying.length,
        'Time range: ' + r1.timeRange,
        'Source IP: ' + ipLabel,
        'Source workstation: ' + wsLabel
      ];
      if (Object.keys(g.reasons).length) {
        r1.observed.push('Reported failure reason: ' + mostCommon(g.reasons));
      }
      r1.why = 'Repeated authentication failures may indicate password guessing, but they could ' +
        'equally be caused by a legitimate user entering the wrong password, or by an application ' +
        'or scheduled task still using outdated credentials. The count alone does not tell you which.';
      r1.benign = 'A person repeatedly mistyping a password, a device holding an old saved password, ' +
        'a mapped drive or mail client retrying in a loop, or a service account whose password was ' +
        'rotated without updating the service.';
      r1.nextSteps = [
        'Identify the source system behind ' + (ips.length ? ips.join(', ') : 'the failures') + '.',
        'Review the affected account ' + g.account + ' and confirm it is still required.',
        'Check whether the failures were followed by a successful login.',
        'Determine whether other accounts were targeted in the same period.',
        'Review MFA or endpoint telemetry if available, which can help separate a person from a script.'
      ];
      r1.scoreReasons = [{
        points: SCORE.repeatedFailedLogons,
        reason: 'Repeated failed logons (' + g.account + ', ' + qualifying.length + ' failures)'
      }];
      /* State clearly why this severity was chosen, rather than leaving the
         reader to guess. */
      if (r1.severity === SEVERITY.LOW) {
        r1.notes.push('Severity is Low: ' + qualifying.length + ' failures exceed the threshold of ' +
          threshold + ', but are below twice that threshold (' + (threshold * 2) + '), so this is ' +
          'treated as a low-priority item worth a look. If these failures were followed by a ' +
          'successful logon, the correlated finding raises the priority.');
      } else {
        r1.notes.push('Severity is Medium: ' + qualifying.length + ' failures are at least twice ' +
          'the threshold of ' + threshold + '.');
      }
      if (groupingNote) { r1.notes.push(groupingNote); }
      findings.push(r1);

      /* --------- Rule 2: successful logon after the failures ------------- */
      var orderedFailures = sortedByTime(qualifying);
      var lastFailure = orderedFailures[orderedFailures.length - 1];
      var firstFailure = orderedFailures[0];

      var candidates = successes.filter(function (s) {
        return sameAccount(s.account, g.account) && isAfter(s, lastFailure);
      });
      if (candidates.length === 0) {
        candidates = successes.filter(function (s) {
          return sameAccount(s.account, g.account) && isAfter(s, firstFailure);
        });
      }

      if (candidates.length > 0) {
        var successEv = sortedByTime(candidates)[0];
        var sameIp = !!(successEv.sourceIp && ips.indexOf(successEv.sourceIp) !== -1);
        var withinWindow = !!(successEv.time && lastFailure.time &&
          (successEv.time - lastFailure.time) <= windowMinutes * 60 * 1000);
        var strong = (sameIp && withinWindow) || (sameIp && !timed) ||
                     (withinWindow && !successEv.sourceIp);

        var r2 = blankFinding();
        r2.id = 'guessing-then-success';
        r2.name = 'POSSIBLE PASSWORD GUESSING FOLLOWED BY SUCCESS';
        r2.severity = strong ? SEVERITY.HIGH : SEVERITY.MEDIUM;
        r2.eventIds = [4625, 4624];
        r2.account = g.account;
        r2.accountDomain = g.domain;
        r2.timeRange = timeRangeLabel(qualifying.concat([successEv]));
        r2.sourceIp = successEv.sourceIp || '';
        r2.workstation = successEv.workstation || wsLabel;
        r2.computer = successEv.computer ||
          uniqueValues(qualifying, function (e) { return e.computer; }).join(', ');
        r2.events = qualifying.concat([successEv]);
        r2.evidenceChain = chain + ' \u2192 4624';
        r2.observed = [
          'Account: ' + g.account,
          'Failed logins: ' + qualifying.length,
          'Successful login: Yes',
          'Successful login time: ' + (successEv.timeRaw || 'unknown'),
          'Successful login source IP: ' + (successEv.sourceIp || 'not present in this export'),
          'Same source IP used for the failures: ' +
            (sameIp ? 'Yes (' + successEv.sourceIp + ')' : 'No, or not recorded'),
          'Success within ' + windowMinutes + ' minutes of the last failure: ' +
            (withinWindow ? 'Yes' : (timed ? 'No' : 'Cannot be determined (no usable timestamps)')),
          'Logon type of the successful login: ' +
            (successEv.logonType
              ? successEv.logonType + ' \u2013 ' + (LOGON_TYPES[successEv.logonType] || 'unknown meaning')
              : 'unknown')
        ];
        r2.why = 'Multiple failed login attempts followed by a successful login can indicate that a ' +
          'password was eventually guessed, because an attacker working through a password list ' +
          'stops failing once they succeed. It can equally represent a legitimate user who eventually ' +
          'entered the correct password after several mistakes, or a device that re-authenticated ' +
          'once its saved credentials were corrected.';
        r2.benign = 'The legitimate user mistyped their password several times and then got it right. ' +
          'This is the most common explanation by far, and it is why the source address and the ' +
          'activity after the login matter more than the failure count.';
        r2.nextSteps = [
          'Verify the source IP' + (successEv.sourceIp ? ' (' + successEv.sourceIp + ')' : '') +
            ' and whether it is a device this account normally uses.',
          'Determine whether the device belongs to the user, or is shared or a lab machine.',
          'Review what happened after the successful login, including process creation events.',
          'Look for authentication attempts against other accounts from the same source.',
          'Where available, check MFA records for the successful login.'
        ];
        r2.scoreReasons = [{
          points: SCORE.successAfterFailures,
          reason: 'Successful logon followed ' + qualifying.length + ' failed logons for ' + g.account
        }];
        if (sameIp) {
          r2.notes.push('The failures and the success came from the same source address, which makes ' +
            'the sequence more coherent than a success from an unrelated location.');
        }
        if (!strong) {
          r2.notes.push('The evidence for this sequence is not strong: the successful login was not ' +
            'clearly linked to the failures by time window or source address. It is reported at ' +
            r2.severity + ' rather than High for that reason.');
        }
        findings.push(r2);
      }
    });

    return { findings: findings, notes: notes };
  }

  /* --- Rule 3: account created, then privileges granted ------------------- */

  function analyseAccountAndPrivileges(events) {
    var findings = [];
    var used = {};
    var creations = events.filter(function (e) { return e.eventId === 4720; });
    var privilegeAdds = events.filter(function (e) {
      return e.eventId === 4728 || e.eventId === 4732;
    });

    creations.forEach(function (created) {
      var matched = privilegeAdds.filter(function (p) {
        return sameAccount(p.account, created.account) && isAfter(p, created);
      });
      if (matched.length === 0) { return; }

      var privileged = matched.filter(function (m) { return isPrivilegedGroup(m.groupName); });
      var ordered = sortedByTime([created].concat(matched));
      var last = ordered[ordered.length - 1];
      var gapMinutes = (created.time && last.time)
        ? Math.round((last.time - created.time) / 60000) : null;

      used[created.index] = true;
      matched.forEach(function (m) { used[m.index] = true; });

      var f = blankFinding();
      f.id = 'account-created-then-privileged';
      f.name = 'NEW ACCOUNT GRANTED PRIVILEGES';
      f.severity = privileged.length ? SEVERITY.HIGH : SEVERITY.MEDIUM;
      f.eventIds = findingEventIds(ordered);
      f.account = created.account;
      f.accountDomain = created.accountDomain;
      f.actor = created.actor;
      f.timeRange = timeRangeLabel(ordered);
      f.computer = uniqueValues(ordered, function (e) { return e.computer; }).join(', ');
      f.events = ordered;
      f.evidenceChain = ordered.map(function (e) { return String(e.eventId); }).join(' \u2192 ');
      f.observed = [
        'Account: ' + created.account,
        'Created: ' + (created.timeRaw || 'unknown'),
        'Created by: ' + (created.actor || 'not recorded in this export'),
        'Privileges added: ' + matched.map(function (m) {
          return m.eventId + ' \u2013 ' + (m.groupName || 'group not recorded');
        }).join('; '),
        'Elapsed time from creation to the last privilege change: ' + formatDuration(gapMinutes),
        'Privileged group involved: ' + (privileged.length
          ? 'Yes (' + uniqueValues(privileged, function (m) { return m.groupName; }).join(', ') + ')'
          : 'No')
      ];
      f.why = 'Creating an account and then granting it elevated privileges can be legitimate ' +
        'administration, but it is also a well-known way of establishing persistence and escalating ' +
        'privileges. Elapsed time matters: a change made minutes after creation is less likely to ' +
        'have been part of a planned joiner process than one made days later.';
      f.benign = 'An administrator setting up a new starter, a temporary administrator account for a ' +
        'documented task, a software installation that needs a dedicated service account, or a ' +
        'change covered by a change request.';
      f.nextSteps = [
        'Confirm whether the creation of ' + created.account + ' was authorised, and by whom.',
        'Identify the administrator responsible: ' + (created.actor || 'not recorded') + '.',
        'Review the activity performed by ' + created.account + ' after the change.',
        'Check whether the account is still required and whether it has an expiry or password policy.',
        'Look for a matching change record or ticket.'
      ];
      f.scoreReasons = [{
        points: SCORE.accountCreatedThenPrivileged,
        reason: 'Account ' + created.account + ' created and then granted group membership'
      }];
      if (privileged.length) {
        f.scoreReasons.push({
          points: SCORE.privilegedGroupChange,
          reason: 'Privileged group membership change (' +
            uniqueValues(privileged, function (m) { return m.groupName; }).join(', ') + ')'
        });
        f.notes.push('The group involved, ' +
          uniqueValues(privileged, function (m) { return m.groupName; }).join(', ') +
          ', is treated as privileged by this tool, which is why the severity is High. Being in a ' +
          'privileged group is not itself evidence of wrongdoing.');
      }
      if (gapMinutes !== null && gapMinutes <= 15) {
        f.notes.push('Only ' + formatDuration(gapMinutes) + ' passed between account creation and ' +
          'the privilege change, which is a fast sequence.');
      }
      findings.push(f);
    });

    return { findings: findings, used: used };
  }

  /* --- Rule 4 and the remaining single-event findings --------------------- */

  function analyseAdministrativeEvents(events, used) {
    var findings = [];

    /* ----------------- Rule 4: the Security log was cleared -------------- */
    var clears = events.filter(function (e) { return e.eventId === 1102; });
    if (clears.length > 0) {
      var f = blankFinding();
      f.id = 'audit-log-cleared';
      f.name = 'SECURITY AUDIT LOG CLEARED';
      f.severity = SEVERITY.HIGH;
      f.eventIds = [1102];
      f.account = clears[0].account;
      f.accountDomain = clears[0].accountDomain;
      f.actor = clears[0].actor;
      f.timeRange = timeRangeLabel(clears);
      f.computer = uniqueValues(clears, function (e) { return e.computer; }).join(', ');
      f.events = clears;
      f.evidenceChain = clears.length > 1 ? '1102 \u00d7 ' + clears.length : '1102';
      f.observed = [
        'Events: ' + clears.length + ' (Event ID 1102)',
        'Time: ' + f.timeRange,
        'Computer: ' + (f.computer || 'not recorded'),
        'Account that cleared the log: ' + (clears[0].account || 'not recorded in this export'),
        'Domain: ' + (clears[0].accountDomain || 'not recorded')
      ];
      f.why = 'This event means the Windows Security audit log was cleared. This can happen during ' +
        'legitimate maintenance, but because attackers may clear logs to remove evidence, it should ' +
        'normally be investigated. It also means the events that would have shown what happened ' +
        'immediately before the clear are no longer available in this log.';
      f.benign = 'A documented maintenance or housekeeping task, a log-size limit being reached and ' +
        'an administrator clearing the log manually, or an imaging or deployment process that resets ' +
        'a machine before handover.';
      f.nextSteps = [
        'Identify who cleared the log and from where.',
        'Check whether the clear matches a maintenance window or a change record.',
        'Look for a gap in the timeline: events immediately before a clear are often the most informative.',
        'Check whether the same account performed other administrative actions in this dataset.',
        'Because local evidence has been removed, check centralised log collection if it exists.'
      ];
      f.scoreReasons = [{
        points: SCORE.auditLogCleared,
        reason: 'Security audit log cleared (Event ID 1102)'
      }];
      f.notes.push('This finding is raised at High priority on its own, without needing any other ' +
        'event to support it, because the action itself destroys audit evidence.');
      findings.push(f);
    }

    /* ----------------- User account created (not paired) ----------------- */
    events.filter(function (e) { return e.eventId === 4720 && !used[e.index]; })
      .forEach(function (e) {
        findings.push(simpleFinding({
          id: 'account-created',
          name: 'USER ACCOUNT CREATED',
          severity: SEVERITY.MEDIUM,
          eventIds: [4720],
          account: e.account,
          accountDomain: e.accountDomain,
          actor: e.actor,
          timeRange: e.timeRaw || 'unknown',
          computer: e.computer,
          events: [e],
          evidenceChain: '4720',
          observed: [
            'New account: ' + (e.account || 'not recorded'),
            'Created by: ' + (e.actor || 'not recorded in this export'),
            'Time: ' + (e.timeRaw || 'unknown'),
            'Computer: ' + (e.computer || 'not recorded')
          ],
          why: 'Account creation may be completely legitimate administrative activity, but a new ' +
            'account should always be verifiable against a business reason. An account that nobody ' +
            'can explain is worth understanding, because accounts are how access is retained.',
          benign: 'A new employee starting, a new service account, a test or training account, or an ' +
            'account recreated after a naming change.',
          nextSteps: [
            'Confirm who requested the account and whether it was authorised.',
            'Check what the account did after it was created.',
            'Verify whether the account is still needed and whether it has a strong password policy.',
            'Check for a matching change record.'
          ],
          scoreReasons: [{
            points: SCORE.accountCreated,
            reason: 'User account created (' + (e.account || 'name not recorded') + ')'
          }]
        }));
      });

    /* ----------------- User account deleted ----------------------------- */
    events.filter(function (e) { return e.eventId === 4726; })
      .forEach(function (e) {
        findings.push(simpleFinding({
          id: 'account-deleted',
          name: 'USER ACCOUNT DELETED',
          severity: SEVERITY.LOW,
          eventIds: [4726],
          account: e.account,
          accountDomain: e.accountDomain,
          actor: e.actor,
          timeRange: e.timeRaw || 'unknown',
          computer: e.computer,
          events: [e],
          evidenceChain: '4726',
          observed: [
            'Deleted account: ' + (e.account || 'not recorded'),
            'Deleted by: ' + (e.actor || 'not recorded in this export'),
            'Time: ' + (e.timeRaw || 'unknown'),
            'Computer: ' + (e.computer || 'not recorded')
          ],
          why: 'A normal account closure, for example when somebody leaves, looks exactly like this. ' +
            'It deserves attention mainly when it is unusual in context: for example an account that ' +
            'was created shortly before being deleted, which can be an attempt to tidy up after ' +
            'temporary access.',
          benign: 'An employee leaving, a contractor engagement ending, a duplicate account being ' +
            'cleaned up, or a scheduled account-lifecycle process.',
          nextSteps: [
            'Check whether the deletion matches a known leaver process.',
            'If the account was recently created, review what it did in the meantime.',
            'Confirm the account did not need to be retained for audit or mailbox purposes.'
          ],
          scoreReasons: [{
            points: SCORE.accountDeleted,
            reason: 'User account deleted (' + (e.account || 'name not recorded') + ')'
          }]
        }));
      });

    /* ----------------- Privileged group change (not paired) -------------- */
    events.filter(function (e) {
      return (e.eventId === 4728 || e.eventId === 4732) && !used[e.index];
    }).forEach(function (e) {
      var isPriv = isPrivilegedGroup(e.groupName);
      findings.push(simpleFinding({
        id: 'group-membership-change',
        name: 'GROUP MEMBERSHIP CHANGE',
        severity: isPriv ? SEVERITY.HIGH : SEVERITY.MEDIUM,
        eventIds: [e.eventId],
        account: e.account,
        accountDomain: e.accountDomain,
        actor: e.actor,
        timeRange: e.timeRaw || 'unknown',
        computer: e.computer,
        events: [e],
        evidenceChain: String(e.eventId),
        observed: [
          'Member added: ' + (e.account || 'not recorded'),
          'Group: ' + (e.groupName || 'not recorded') +
            (e.groupDomain ? ' (' + e.groupDomain + ')' : ''),
          'Added by: ' + (e.actor || 'not recorded in this export'),
          'Time: ' + (e.timeRaw || 'unknown'),
          'Computer: ' + (e.computer || 'not recorded'),
          'Group treated as privileged by this tool: ' + (isPriv ? 'Yes' : 'No')
        ],
        why: 'Group membership decides what an account may do. A change to a privileged group ' +
          'increases the account\u2019s capability, and a change that nobody can explain is worth ' +
          'understanding. This is reported as higher priority when the group name looks privileged, ' +
          'which is a naming heuristic and not proof of anything.',
        benign: 'A legitimate promotion, cover for a colleague on leave, a helpdesk task, or a ' +
          'software deployment that requires temporary elevated rights.',
        nextSteps: [
          'Confirm that the change was authorised and recorded.',
          'Identify the account that made the change: ' + (e.actor || 'not recorded') + '.',
          'Check how long the membership is intended to last.',
          'Review what the added account did after the change.'
        ],
        scoreReasons: isPriv ? [{
          points: SCORE.privilegedGroupChange,
          reason: 'Privileged group membership change (' + (e.groupName || 'group') + ')'
        }] : []
      }));
    });

    /* ----------------- Service installed --------------------------------- */
    events.filter(function (e) { return e.eventId === 7045; })
      .forEach(function (e) {
        var path = e.servicePath || '';
        /* Normalise separators first, so the check does not depend on tricky
           backslash escaping inside a regular expression. */
        var normalisedPath = path.replace(/\\/g, '/').toLowerCase();
        var userWritableFolders = /(\/temp\/|\/tmp\/|\/users\/|\/appdata\/|\/programdata\/|\/downloads\/|\/public\/)/;
        var suspiciousPath = userWritableFolders.test(normalisedPath);
        findings.push(simpleFinding({
          id: 'service-installed',
          name: 'SERVICE INSTALLED',
          severity: suspiciousPath ? SEVERITY.HIGH : SEVERITY.MEDIUM,
          eventIds: [7045],
          account: e.serviceAccount || '',
          timeRange: e.timeRaw || 'unknown',
          computer: e.computer,
          events: [e],
          evidenceChain: '7045',
          observed: [
            'Service name: ' + (e.serviceName || 'not recorded'),
            'Program the service runs: ' + (path || 'not recorded'),
            'Start type: ' + (e.serviceStartType || 'not recorded'),
            'Service account: ' + (e.serviceAccount || 'not recorded'),
            'Time: ' + (e.timeRaw || 'unknown'),
            'Computer: ' + (e.computer || 'not recorded'),
            'Launched from a temporary, user-writable or data folder: ' + (suspiciousPath ? 'Yes' : 'No')
          ],
          why: 'Creating a Windows service can be completely legitimate software installation, but a ' +
            'service is also a convenient way to keep something running automatically. A service that ' +
            'launches a program from a temporary, user-writable or data folder is more interesting ' +
            'than one launched from Program Files, because those locations are easier for a ' +
            'non-administrator to write to.',
          benign: 'A software installer registering its own service, an update agent, a backup or ' +
            'monitoring agent, or a printer driver component.',
          nextSteps: [
            'Identify what installed the service and confirm it was expected.',
            'Check the program path against the vendor\u2019s normal installation location.',
            'Verify the file signature and hash of the program if you can obtain it safely.',
            'Check whether the service starts automatically and under which account.',
            'Look for other events around the same time, such as process creation.'
          ],
          scoreReasons: [{ points: SCORE.serviceInstalled,
            reason: 'New service installed (' + (e.serviceName || 'name not recorded') + ')' }]
        }));
      });

    /* ----------------- PowerShell script block logging ------------------ */
    var scriptEvents = events.filter(function (e) { return e.eventId === 4104; });
    var encodedProcesses = events.filter(function (e) {
      return e.eventId === 4688 && looksEncodedOrObfuscated(e.commandLine).flag;
    });

    if (scriptEvents.length > 0) {
      var flagged = scriptEvents.filter(function (e) {
        return looksEncodedOrObfuscated(e.scriptBlock).flag;
      });

      if (flagged.length > 0) {
        var reasons = looksEncodedOrObfuscated(flagged[0].scriptBlock).reasons;
        var evidence = flagged.concat(encodedProcesses);
        findings.push(simpleFinding({
          id: 'encoded-powershell',
          name: 'ENCODED OR OBFUSCATED POWERSHELL',
          severity: SEVERITY.MEDIUM,
          eventIds: findingEventIds(evidence),
          account: flagged[0].account || (encodedProcesses[0] ? encodedProcesses[0].account : ''),
          accountDomain: flagged[0].accountDomain,
          timeRange: timeRangeLabel(evidence),
          computer: uniqueValues(evidence, function (e) { return e.computer; }).join(', '),
          events: evidence,
          evidenceChain: evidence.map(function (e) { return String(e.eventId); }).join(' + '),
          observed: [
            'Script block logging events examined: ' + scriptEvents.length,
            'Events with encoded or obfuscated content: ' + flagged.length,
            'Patterns matched: ' + reasons.join('; '),
            'Time: ' + timeRangeLabel(evidence),
            'Computer: ' + (uniqueValues(evidence, function (e) { return e.computer; }).join(', ') ||
              'not recorded'),
            encodedProcesses.length
              ? 'Related process creation events with encoded command lines: ' + encodedProcesses.length
              : 'No related 4688 process creation events with encoded command lines in this dataset'
          ],
          why: 'PowerShell script block logging can provide valuable visibility into commands and ' +
            'scripts executed on the endpoint. The patterns matched here are simple string checks ' +
            'for encoded or obfuscated content. Encoding is used by attackers to hide intent, but it ' +
            'is also used by legitimate management tools, installers and remote administration ' +
            'systems. This is a reason to read the script, not a verdict on it.',
          benign: 'Software deployment frameworks, configuration management tools and remote ' +
            'administration products routinely pass encoded commands. Some vendors encode their ' +
            'scripts purely to avoid quoting problems.',
          nextSteps: [
            'Decode the encoded content and read what it actually does.',
            'Identify the parent process that launched PowerShell, using the process creation events.',
            'Determine which account and which host this ran on.',
            'Check whether the same pattern appears across many machines, which suggests a managed tool.',
            'Treat PowerShell itself as neutral: it is a normal administrative tool.'
          ],
          scoreReasons: [{ points: SCORE.encodedScriptBlock,
            reason: 'Encoded or obfuscated PowerShell content detected' }]
        }));
      } else {
        findings.push(simpleFinding({
          id: 'powershell-visibility',
          name: 'POWERSHELL SCRIPT BLOCK ACTIVITY (CONTEXT)',
          severity: SEVERITY.INFORMATIONAL,
          eventIds: [4104],
          account: scriptEvents[0].account,
          timeRange: timeRangeLabel(scriptEvents),
          computer: uniqueValues(scriptEvents, function (e) { return e.computer; }).join(', '),
          events: scriptEvents,
          evidenceChain: '4104 \u00d7 ' + scriptEvents.length,
          observed: [
            'PowerShell script block events: ' + scriptEvents.length,
            'None matched the simple encoded or obfuscated content patterns'
          ],
          why: 'PowerShell script block logging can provide valuable visibility into commands and ' +
            'scripts executed on the endpoint. These entries did not match any of the simple ' +
            'encoding patterns, and PowerShell is not suspicious by itself. They are listed so that ' +
            'you can read them as context.',
          benign: 'Normal administrative scripting, including logon scripts and automation.',
          nextSteps: [
            'Skim the script text for anything you do not recognise.',
            'Compare against the accounts and hosts you would expect to run scripts.'
          ],
          scoreReasons: []
        }));
      }
    }

    return findings;
  }

  /* Patterns that suggest a command has been deliberately obscured. These are
     simple, transparent string checks, documented in the README. */
  function looksEncodedOrObfuscated(text) {
    var t = String(text || '');
    var reasons = [];
    if (!t) { return { flag: false, reasons: reasons }; }

    if (/-enc(odedcommand)?\b/i.test(t)) {
      reasons.push('uses -enc / -EncodedCommand');
    }
    if (/FromBase64String/i.test(t)) {
      reasons.push('calls FromBase64String');
    }
    var b64 = t.match(/[A-Za-z0-9+\/]{80,}={0,2}/g);
    if (b64 && b64.length > 0) {
      reasons.push('contains a long Base64-style string (' + b64[0].length + ' characters)');
    }
    if (/\[char\]\s*\d+/i.test(t) || /-join\s*\(/i.test(t)) {
      reasons.push('builds a command from character codes');
    }
    if (/-w(indowstyle)?\s+hidden/i.test(t)) {
      reasons.push('requests a hidden window');
    }
    if (/-nop(rofile)?\b/i.test(t) || /-ExecutionPolicy\s+Bypass/i.test(t)) {
      reasons.push('uses arguments often used to avoid policy restrictions');
    }

    return { flag: reasons.length > 0, reasons: reasons };
  }

  /* Build a finding from a plain object of overrides. */
  function simpleFinding(spec) {
    var f = blankFinding();
    Object.keys(spec).forEach(function (key) { f[key] = spec[key]; });
    return f;
  }

  /* --- Rule 5: Administrative / Privilege Activity summary --------------- */
  /* These events are summarised together, grouped by the account that made the
     change, and only when the account actually matches. Unrelated accounts are
     listed separately rather than blended into a single accusation. */

  function buildAdminGroups(events) {
    var adminIds = { 4720: true, 4726: true, 4728: true, 4732: true, 7045: true, 1102: true };
    var groups = {};

    function bucketFor(name) {
      var key = String(name || '(not recorded)');
      if (!groups[key]) {
        groups[key] = {
          actor: key,
          events: [],
          orders: {},
          privilegedGroups: {},
          accountsCreated: {},
          accountsDeleted: {},
          services: {},
          clears: 0
        };
      }
      return groups[key];
    }

    events.forEach(function (e) {
      if (!adminIds[e.eventId]) { return; }

      /* Attribute the event to the person who caused it. For 4720/4726/4728/4732
         and 1102 that is the Subject (actor). For 7045 there is no actor, so the
         event is attributed to the computer it happened on. */
      var owner = (e.eventId === 7045) ? ('(service on ' + (e.computer || 'unknown computer') + ')')
                                       : (e.actor || '(actor not recorded)');
      var g = bucketFor(owner);
      var entry = {
        eventId: e.eventId,
        time: e.timeRaw || 'time not available',
        summary: ''
      };

      if (e.eventId === 4720) {
        entry.summary = 'Created user account ' + (e.account || '(name not recorded)');
        g.accountsCreated[e.account || '(unknown)'] = true;
      } else if (e.eventId === 4726) {
        entry.summary = 'Deleted user account ' + (e.account || '(name not recorded)');
        g.accountsDeleted[e.account || '(unknown)'] = true;
      } else if (e.eventId === 4728 || e.eventId === 4732) {
        var grp = e.groupName || '(group not recorded)';
        entry.summary = 'Added ' + (e.account || '(account not recorded)') + ' to group ' + grp +
          (isPrivilegedGroup(grp) ? ' [privileged]' : '');
        if (isPrivilegedGroup(grp)) { g.privilegedGroups[grp] = true; }
      } else if (e.eventId === 7045) {
        entry.summary = 'Installed service ' + (e.serviceName || '(name not recorded)') +
          (e.servicePath ? ' running ' + e.servicePath : '');
        g.services[e.serviceName || '(unknown)'] = true;
      } else if (e.eventId === 1102) {
        entry.summary = 'Cleared the Security audit log';
        g.clears++;
      }

      g.events.push(entry);
    });

    return Object.keys(groups).map(function (key) {
      var g = groups[key];
      var accounts = {};
      g.events.forEach(function (e) {
        var m = e.summary.match(/(?:Created|Deleted) user account (\S+)/);
        if (m) { accounts[m[1]] = true; }
      });
      return {
        actor: g.actor,
        events: g.events,
        privilegedGroups: Object.keys(g.privilegedGroups),
        accountsCreated: Object.keys(g.accountsCreated),
        accountsDeleted: Object.keys(g.accountsDeleted),
        services: Object.keys(g.services),
        clears: g.clears,
        touchesPrivilege: Object.keys(g.privilegedGroups).length > 0 || g.clears > 0
      };
    }).sort(function (a, b) {
      if (a.touchesPrivilege !== b.touchesPrivilege) { return a.touchesPrivilege ? -1 : 1; }
      return b.events.length - a.events.length;
    });
  }

  /* ======================= 14. SCORING, STATISTICS, TIMELINE ============= */

  function computeScore(findings) {
    var ledger = [];
    var seen = {};
    var total = 0;

    findings.forEach(function (f) {
      f.scorePoints = f.scoreReasons.reduce(function (sum, r) { return sum + r.points; }, 0);
      f.scoreReasons.forEach(function (r) {
        var key = r.points + '::' + r.reason;
        if (seen[key]) { return; }
        seen[key] = true;
        ledger.push({ points: r.points, reason: r.reason });
        total += r.points;
      });
    });

    ledger.sort(function (a, b) { return b.points - a.points; });

    return {
      total: total,
      capped: Math.min(total, SCORE.maximum),
      cappedApplied: total > SCORE.maximum,
      ledger: ledger,
      maximum: SCORE.maximum
    };
  }

  function computeStats(events, findings) {
    var counts = {
      successfulLogons: 0,
      failedLogons: 0,
      accountsCreated: 0,
      accountsDeleted: 0,
      privilegeChanges: 0,
      auditClears: 0,
      processCreations: 0,
      scriptBlocks: 0,
      servicesInstalled: 0,
      specialLogons: 0,
      unrecognised: 0
    };
    var byId = {};
    var byAccount = {};
    var failedByAccount = {};
    var failuresBelowThreshold = 0;

    events.forEach(function (e) {
      byId[e.eventId] = (byId[e.eventId] || 0) + 1;

      var acct = e.account || '(not recorded)';
      byAccount[acct] = (byAccount[acct] || 0) + 1;

      switch (e.eventId) {
        case 4624: counts.successfulLogons++; break;
        case 4625:
          counts.failedLogons++;
          failedByAccount[acct] = (failedByAccount[acct] || 0) + 1;
          break;
        case 4720: counts.accountsCreated++; break;
        case 4726: counts.accountsDeleted++; break;
        case 4728:
        case 4732: counts.privilegeChanges++; break;
        case 1102: counts.auditClears++; break;
        case 4688: counts.processCreations++; break;
        case 4104: counts.scriptBlocks++; break;
        case 7045: counts.servicesInstalled++; break;
        case 4672: counts.specialLogons++; break;
        default:
          if (!e.known) { counts.unrecognised++; }
      }
    });

    var investigative = findings.filter(function (f) {
      return SEV_RANK[f.severity] >= SEV_RANK[SEVERITY.LOW];
    });

    Object.keys(byAccount).forEach(function (a) {
      if (failedByAccount[a]) {
        failuresBelowThreshold += failedByAccount[a];
      }
    });

    function topEntries(map, limit) {
      return Object.keys(map).map(function (k) {
        return { label: k, count: map[k] };
      }).sort(function (a, b) {
        if (b.count !== a.count) { return b.count - a.count; }
        return a.label < b.label ? -1 : (a.label > b.label ? 1 : 0);
      }).slice(0, limit || 10);
    }

    var idList = Object.keys(byId).map(function (k) {
      return { id: parseInt(k, 10), count: byId[k], name: (EVID_BY_STRING[k] ? EVID_BY_STRING[k].name : 'Unrecognised') };
    }).sort(function (a, b) { return b.count - a.count; });

    return {
      totalEvents: events.length,
      counts: counts,
      byId: byId,
      topEventIds: idList,
      topAccounts: topEntries(byAccount, 10),
      topFailedAccounts: topEntries(failedByAccount, 10),
      findingCount: findings.length,
      investigateCount: investigative.length,
      highCount: findings.filter(function (f) { return f.severity === SEVERITY.HIGH; }).length,
      mediumCount: findings.filter(function (f) { return f.severity === SEVERITY.MEDIUM; }).length,
      lowCount: findings.filter(function (f) { return f.severity === SEVERITY.LOW; }).length,
      infoCount: findings.filter(function (f) { return f.severity === SEVERITY.INFORMATIONAL; }).length,
      totalFailures: counts.failedLogons
    };
  }

  function buildTimeline(findings) {
    var entries = {};
    var max = 80;

    findings.forEach(function (f) {
      if (SEV_RANK[f.severity] < SEV_RANK[SEVERITY.LOW]) { return; }
      f.events.forEach(function (e) {
        var existing = entries[e.index];
        if (!existing) {
          entries[e.index] = {
            event: e,
            severity: f.severity,
            findings: [f.name]
          };
        } else {
          if (SEV_RANK[f.severity] > SEV_RANK[existing.severity]) {
            existing.severity = f.severity;
          }
          if (existing.findings.indexOf(f.name) === -1) {
            existing.findings.push(f.name);
          }
        }
      });
    });

    var list = Object.keys(entries).map(function (k) {
      return entries[k];
    }).sort(function (a, b) {
      if (a.event.time && b.event.time) { return a.event.time - b.event.time; }
      if (a.event.time) { return -1; }
      if (b.event.time) { return 1; }
      return a.event.index - b.event.index;
    });

    /* Honesty check: if no event in this list has a usable timestamp, the list
       is in file order rather than chronological order, and the rendering must
       say so instead of implying a sequence that cannot be supported. */
    var anyUsableTime = list.some(function (entry) {
      return !!entry.event.time;
    });

    var truncated = false;
    if (list.length > max) {
      list = list.slice(0, max);
      truncated = true;
    }

    return {
      entries: list,
      truncated: truncated,
      anyUsableTime: anyUsableTime
    };
  }

  /* ======================= 15. ANALYSIS ORCHESTRATOR ===================== */

  function analyseDataset(dataset, settings) {
    var events = dataset.events;

    var auth = analyseAuthentication(events, settings);
    var acc = analyseAccountAndPrivileges(events);
    var admin = analyseAdministrativeEvents(events, acc.used);

    var findings = auth.findings.concat(acc.findings).concat(admin);

    /* Below-threshold authentication activity is reported too, at
       Informational level, so that nothing is silently discarded. */
    if (auth.notes.length > 0) {
      findings.push(simpleFinding({
        id: 'authentication-below-threshold',
        name: 'AUTHENTICATION ACTIVITY BELOW THRESHOLD',
        severity: SEVERITY.INFORMATIONAL,
        eventIds: [4625],
        observed: auth.notes,
        why: 'Failed logons that do not reach the current threshold are shown here rather than ' +
          'hidden, so that you can see what the tool decided not to escalate and judge whether you ' +
          'agree with it.',
        benign: 'Small numbers of failed logons are a normal part of everyday Windows activity.',
        nextSteps: [
          'Decide whether the threshold you chose is appropriate for this dataset.',
          'Consider whether these failures would matter if they happened every day.'
        ],
        scoreReasons: []
      }));
    }

    /* Highest severity first, then by the earliest event time. */
    findings.sort(function (a, b) {
      var sev = SEV_RANK[b.severity] - SEV_RANK[a.severity];
      if (sev !== 0) { return sev; }
      var at = a.events[0] && a.events[0].time ? a.events[0].time.getTime() : Infinity;
      var bt = b.events[0] && b.events[0].time ? b.events[0].time.getTime() : Infinity;
      if (at !== bt) { return at - bt; }
      return a.name < b.name ? -1 : (a.name > b.name ? 1 : 0);
    });

    /* Raise the severity shown for individual events that are part of a
       higher-priority finding, so the event table reflects the correlation. */
    findings.forEach(function (f) {
      f.eventIds = findingEventIds(f.events);
      f.events.forEach(function (e) {
        if (SEV_RANK[f.severity] > SEV_RANK[e.severity]) {
          e.severity = f.severity;
          e.severityRaisedBy = f.name;
        }
      });
    });

    var score = computeScore(findings);
    var stats = computeStats(events, findings);
    var timeline = buildTimeline(findings);
    var adminGroups = buildAdminGroups(events);

    return {
      findings: findings,
      score: score,
      stats: stats,
      timeline: timeline,
      adminGroups: adminGroups,
      authNotes: auth.notes
    };
  }

  /* ======================= 16. RENDERING ================================= */

  function severityBadge(sev) {
    return '<span class="sev sev-' + esc(String(sev).toLowerCase()) + '">' + esc(sev) + '</span>';
  }

  function renderScore(score) {
    var totalNode = $('score-total');
    var ledgerNode = $('score-ledger');
    if (!totalNode || !ledgerNode) { return; }

    totalNode.innerHTML = 'Dataset investigation priority score: ' +
      '<span class="score-num">' + score.capped + '</span> / ' + score.maximum +
      (score.cappedApplied ? ' (total contributions reached ' + score.total + ', capped at ' +
        score.maximum + ')' : '');

    clearChildren(ledgerNode);

    if (score.ledger.length === 0) {
      ledgerNode.appendChild(makeEl('li', 'reason',
        'No scoring contributions. Nothing in this dataset increased the investigation score.'));
      return;
    }

    score.ledger.forEach(function (item) {
      var li = makeEl('li');
      li.appendChild(makeEl('span', 'points', '+' + item.points));
      li.appendChild(makeEl('span', 'reason', item.reason));
      ledgerNode.appendChild(li);
    });

    var sum = makeEl('li');
    sum.appendChild(makeEl('span', 'points', '= ' + score.total));
    sum.appendChild(makeEl('span', 'reason',
      'Total of every contribution above. This is an educational prioritisation score, not a ' +
      'probability of compromise.'));
    ledgerNode.appendChild(sum);
  }

  function renderStats(stats) {
    var grid = $('stat-grid');
    if (!grid) { return; }
    clearChildren(grid);

    var items = [
      { label: 'Total events', value: stats.totalEvents },
      { label: 'Successful logons (4624)', value: stats.counts.successfulLogons },
      { label: 'Failed logons (4625)', value: stats.counts.failedLogons },
      { label: 'Accounts created (4720)', value: stats.counts.accountsCreated },
      { label: 'Accounts deleted (4726)', value: stats.counts.accountsDeleted },
      { label: 'Privilege changes (4728 / 4732)', value: stats.counts.privilegeChanges },
      { label: 'Audit log cleared (1102)', value: stats.counts.auditClears },
      { label: 'Process creation (4688)', value: stats.counts.processCreations },
      { label: 'PowerShell script blocks (4104)', value: stats.counts.scriptBlocks },
      { label: 'Services installed (7045)', value: stats.counts.servicesInstalled },
      { label: 'Special logons (4672)', value: stats.counts.specialLogons },
      { label: 'Unrecognised Event IDs', value: stats.counts.unrecognised }
    ];

    items.forEach(function (item) {
      var li = makeEl('li', 'stat');
      li.appendChild(makeEl('span', 'stat-value', item.value));
      li.appendChild(makeEl('span', 'stat-label', item.label));
      grid.appendChild(li);
    });

    var attention = makeEl('li', 'stat is-attention');
    attention.appendChild(makeEl('span', 'stat-value', stats.investigateCount));
    attention.appendChild(makeEl('span', 'stat-label',
      'Findings requiring investigation (Low or above)'));
    grid.appendChild(attention);

    var info = makeEl('li', 'stat');
    info.appendChild(makeEl('span', 'stat-value', stats.infoCount));
    info.appendChild(makeEl('span', 'stat-label', 'Informational findings'));
    grid.appendChild(info);
  }

  function renderFindings(findings) {
    var list = $('findings-list');
    if (!list) { return; }
    clearChildren(list);

    if (findings.length === 0) {
      var none = makeEl('div', 'findings-none');
      none.appendChild(makeEl('p', null,
        'No findings were produced for this dataset. That is a meaningful result, not a guarantee: ' +
        'it means nothing in the events you exported matched the rules in this tool.'));
      none.appendChild(makeEl('p', null,
        'Remember that absence of evidence is not evidence of absence. Activity may have been logged ' +
        'elsewhere, overwritten, or never audited in the first place.'));
      list.appendChild(none);
      return;
    }

    findings.forEach(function (f, i) {
      var card = makeEl('article', 'finding sev-border-' + f.severity.toLowerCase());
      card.setAttribute('aria-labelledby', 'finding-title-' + i);

      /* Header: alert name and severity badge. */
      var head = makeEl('div', 'finding-head');
      var title = makeEl('h4', 'finding-name', f.name);
      title.id = 'finding-title-' + i;
      head.appendChild(title);
      var badgeWrap = makeEl('span');
      badgeWrap.innerHTML = severityBadge(f.severity);
      head.appendChild(badgeWrap);

      if (f.scorePoints > 0) {
        var scoreSpan = makeEl('span', 'finding-score');
        scoreSpan.innerHTML = 'priority <span class="points">+' + f.scorePoints + '</span>';
        head.appendChild(scoreSpan);
      }
      card.appendChild(head);

      /* Structured facts, in the order the project specification requests. */
      var dl = makeEl('dl', 'finding-grid');
      function addFact(label, value) {
        if (!value) { return; }
        dl.appendChild(makeEl('dt', null, label));
        dl.appendChild(makeEl('dd', null, String(value)));
      }
      addFact('Severity', f.severity);
      addFact('Event ID(s)', f.eventIds.join(', '));
      addFact('Account', f.account || 'not recorded');
      if (f.actor && f.actor !== f.account) { addFact('Action taken by', f.actor); }
      addFact('Timestamp / range', f.timeRange);
      if (f.sourceIp) { addFact('Source IP', f.sourceIp); }
      if (f.workstation) { addFact('Workstation', f.workstation); }
      if (f.computer) { addFact('Computer', f.computer); }
      if (f.evidenceChain) { addFact('Event sequence', f.evidenceChain); }
      card.appendChild(dl);

      /* Observed activity. */
      if (f.observed && f.observed.length) {
        var sec1 = makeEl('div', 'finding-section');
        sec1.appendChild(makeEl('h5', null, 'Observed activity'));
        var ul = makeEl('ul');
        f.observed.forEach(function (line) { ul.appendChild(makeEl('li', null, line)); });
        sec1.appendChild(ul);
        card.appendChild(sec1);
      }

      if (f.why) {
        var sec2 = makeEl('div', 'finding-section');
        sec2.appendChild(makeEl('h5', null, 'Why this matters'));
        sec2.appendChild(makeEl('p', null, f.why));
        card.appendChild(sec2);
      }

      if (f.benign) {
        var sec3 = makeEl('div', 'finding-section');
        sec3.appendChild(makeEl('h5', null, 'Possible benign explanation'));
        var bp = makeEl('p', 'benign', f.benign);
        sec3.appendChild(bp);
        card.appendChild(sec3);
      }

      if (f.nextSteps && f.nextSteps.length) {
        var sec4 = makeEl('div', 'finding-section');
        sec4.appendChild(makeEl('h5', null, 'Suggested investigation'));
        var ol = makeEl('ol');
        f.nextSteps.forEach(function (step) { ol.appendChild(makeEl('li', null, step)); });
        sec4.appendChild(ol);
        card.appendChild(sec4);
      }

      if (f.notes && f.notes.length) {
        var sec5 = makeEl('div', 'finding-section');
        sec5.appendChild(makeEl('h5', null, 'Analyst notes'));
        var nul = makeEl('ul');
        f.notes.forEach(function (n) { nul.appendChild(makeEl('li', null, n)); });
        sec5.appendChild(nul);
        card.appendChild(sec5);
      }

      list.appendChild(card);
    });
  }

  function makeTable(captionText, headers, rows, numericLastColumn) {
    var wrap = makeEl('div');
    var table = makeEl('table');
    if (captionText) { table.appendChild(makeEl('caption', 'field-help', captionText)); }

    var thead = makeEl('thead');
    var headRow = makeEl('tr');
    headers.forEach(function (h) {
      var th = makeEl('th', null, h);
      th.setAttribute('scope', 'col');
      headRow.appendChild(th);
    });
    thead.appendChild(headRow);
    table.appendChild(thead);

    var tbody = makeEl('tbody');
    rows.forEach(function (row) {
      var tr = makeEl('tr');
      row.forEach(function (cell, idx) {
        var isNum = numericLastColumn && idx === row.length - 1;
        tr.appendChild(makeEl('td', isNum ? 'num' : null, cell));
      });
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    wrap.appendChild(table);
    return wrap;
  }

  function renderEmpty(container, message) {
    if (!container) { return; }
    clearChildren(container);
    container.appendChild(makeEl('p', 'field-help', message));
  }

  function renderTimeline(timeline) {
    var list = $('timeline-list');
    if (!list) { return; }
    clearChildren(list);

    if (!timeline || timeline.entries.length === 0) {
      var li = makeEl('li', 'tl-empty',
        'No noteworthy activity could be placed on a timeline. Note that activity is only shown ' +
        'here when timestamps could be read from the export, and when an event participates in a ' +
        'finding of Low priority or above.');
      list.appendChild(li);
      return;
    }

    timeline.entries.forEach(function (entry) {
      var e = entry.event;
      var cls = 'tl-' + entry.severity.toLowerCase();
      var item = makeEl('li', cls);

      var timeSpan = makeEl('span', 'tl-time', e.timeRaw || 'time not available');
      item.appendChild(timeSpan);

      var body = makeEl('span', 'tl-body');
      body.textContent = e.eventId + ' \u2014 ' + e.name +
        (e.displayAccount ? ' \u2014 ' + e.displayAccount : '') +
        (e.computer ? ' on ' + e.computer : '') +
        ' \u2014 ' + entry.findings.join('; ');
      item.appendChild(body);

      list.appendChild(item);
    });

    if (!timeline.anyUsableTime) {
      var warn = makeEl('li', 'tl-empty',
        'None of these events had a readable timestamp, so this list is in file order, not ' +
        'chronological order. Treat it as a list of noteworthy events rather than a timeline.');
      list.insertBefore(warn, list.firstChild);
    }

    if (timeline.truncated) {
      var li2 = makeEl('li', 'tl-empty',
        'The timeline was limited to the first 80 noteworthy events so that the page stays readable.');
      list.appendChild(li2);
    }
  }

  function renderTables(stats) {
    var topAccounts = $('tbl-top-accounts');
    if (topAccounts) {
      clearChildren(topAccounts);
      if (stats.topAccounts.length === 0) {
        renderEmpty(topAccounts, 'No accounts were identified in this dataset.');
      } else {
        topAccounts.appendChild(makeTable(null, ['Account', 'Events'],
          stats.topAccounts.map(function (r) { return [r.label, r.count]; }), true));
      }
    }

    var topFailed = $('tbl-top-failed');
    if (topFailed) {
      clearChildren(topFailed);
      if (stats.topFailedAccounts.length === 0) {
        renderEmpty(topFailed, 'No failed logons (4625) were found in this dataset.');
      } else {
        topFailed.appendChild(makeTable(null, ['Account', 'Failed logons'],
          stats.topFailedAccounts.map(function (r) { return [r.label, r.count]; }), true));
      }
    }

    var commonIds = $('tbl-common-ids');
    if (commonIds) {
      clearChildren(commonIds);
      commonIds.appendChild(makeTable(null, ['Event ID', 'Meaning', 'Count'],
        stats.topEventIds.map(function (r) { return [r.id, r.name, r.count]; }), true));
    }
  }

  function renderAdminActivity(groups) {
    var container = $('admin-activity');
    if (!container) { return; }
    clearChildren(container);

    if (!groups || groups.length === 0) {
      container.appendChild(makeEl('p', 'field-help',
        'No account creation, account deletion, privilege change, service installation or ' +
        'audit-log clearing events were present in this dataset.'));
      return;
    }

    groups.forEach(function (g) {
      var box = makeEl('div', 'admin-group');
      box.appendChild(makeEl('h4', null, 'Performed by: ' + g.actor));

      var ul = makeEl('ul');
      g.events.forEach(function (e) {
        ul.appendChild(makeEl('li', null, '[' + e.time + '] ' + e.eventId + ' \u2014 ' + e.summary));
      });
      box.appendChild(ul);

      var parts = [];
      if (g.accountsCreated.length) {
        parts.push('accounts created: ' + g.accountsCreated.join(', '));
      }
      if (g.accountsDeleted.length) {
        parts.push('accounts deleted: ' + g.accountsDeleted.join(', '));
      }
      if (g.privilegedGroups.length) {
        parts.push('privileged groups touched: ' + g.privilegedGroups.join(', '));
      }
      if (g.services.length) {
        parts.push('services installed: ' + g.services.join(', '));
      }
      if (g.clears) {
        parts.push('audit log clears: ' + g.clears);
      }

      box.appendChild(makeEl('p', 'field-help',
        'Summary: ' + (parts.length ? parts.join('; ') : 'no summary available') + '.'));

      if (g.touchesPrivilege) {
        box.appendChild(makeEl('p', 'field-help',
          'This account touched privilege-related activity (a privileged group or the audit log), ' +
          'so its events are listed first. This is a grouping convenience, not a conclusion: the ' +
          'same account performing several separate legitimate tasks looks identical here.'));
      } else {
        box.appendChild(makeEl('p', 'field-help',
          'These events are grouped because the same account made the changes. They are listed ' +
          'separately from other accounts deliberately: unrelated users should not be blended ' +
          'into one story.'));
      }

      container.appendChild(box);
    });
  }

  function renderEventIdReference() {
    var container = $('eventid-reference');
    if (!container) { return; }
    clearChildren(container);

    Object.keys(EVID).map(function (k) { return EVID[k]; })
      .sort(function (a, b) {
        return SEV_RANK[b.severity] - SEV_RANK[a.severity] || a.id - b.id;
      })
      .forEach(function (entry) {
        var box = makeEl('div', 'ref-item');

        var head = makeEl('div', 'ref-head');
        head.appendChild(makeEl('span', 'ref-id', entry.id));
        head.appendChild(makeEl('span', 'ref-name', entry.name));
        var badge = makeEl('span');
        badge.innerHTML = severityBadge(entry.severity);
        head.appendChild(badge);
        head.appendChild(makeEl('span', 'ref-labels', entry.category));
        box.appendChild(head);

        box.appendChild(makeEl('p', null, entry.plain));
        box.appendChild(makeEl('p', 'ref-labels',
          'Useful labels to look for: ' + entry.labels.join(', ') + '.'));
        box.appendChild(makeEl('p', 'ref-labels',
          'Why it is worth looking at: ' + entry.investigate));

        container.appendChild(box);
      });
  }

  function renderLimitations() {
    var list = $('limitations-list');
    if (!list) { return; }
    clearChildren(list);
    LIMITATIONS.forEach(function (text) {
      list.appendChild(makeEl('li', null, text));
    });
  }

  /* --- Key detail column ------------------------------------------------- */

  function keyDetail(ev) {
    if (ev.eventId === 4624 || ev.eventId === 4625) {
      var bits = [];
      if (ev.logonType) {
        bits.push('Type ' + ev.logonType +
          (LOGON_TYPES[ev.logonType] ? ' (' + LOGON_TYPES[ev.logonType].split(' (')[0] + ')' : ''));
      }
      if (ev.workstation) { bits.push('WS ' + ev.workstation); }
      if (ev.failureReason) { bits.push(ev.failureReason); }
      return bits.join(' \u00b7 ') || 'no further detail in export';
    }
    if (ev.eventId === 4720) { return 'created by ' + (ev.actor || 'unknown'); }
    if (ev.eventId === 4726) { return 'deleted by ' + (ev.actor || 'unknown'); }
    if (ev.eventId === 4728 || ev.eventId === 4732) {
      return 'group: ' + (ev.groupName || 'unknown') +
        (ev.groupDomain ? ' (' + ev.groupDomain + ')' : '');
    }
    if (ev.eventId === 4688) {
      return (ev.processName || 'unknown process') +
        (ev.commandLine ? ' \u00b7 ' + ev.commandLine : '');
    }
    if (ev.eventId === 4104) {
      var s = String(ev.scriptBlock || '').replace(/\s+/g, ' ');
      return s ? (s.length > 120 ? s.slice(0, 120) + '\u2026' : s) : 'no script text in export';
    }
    if (ev.eventId === 7045) {
      return (ev.serviceName || 'unknown service') +
        (ev.servicePath ? ' \u00b7 ' + ev.servicePath : '');
    }
    if (ev.eventId === 1102) { return 'cleared by ' + (ev.account || 'unknown'); }
    if (ev.eventId === 4672) { return 'privileges assigned to ' + (ev.account || 'unknown'); }
    return ev.displayAccount || ev.actor || 'no further detail in export';
  }

  /* --- Filters ----------------------------------------------------------- */

  var state = {
    settings: {
      failedLoginThreshold: DEFAULTS.failedLoginThreshold,
      failedLoginWindowMinutes: DEFAULTS.failedLoginWindowMinutes
    },
    dataset: null,
    analysis: null,
    filters: { eventId: '', account: '', severity: '', ip: '', type: '', search: '' }
  };

  function readFilters() {
    state.filters.eventId = ($('filter-eventid') ? $('filter-eventid').value : '');
    state.filters.account = ($('filter-account') ? $('filter-account').value : '');
    state.filters.severity = ($('filter-severity') ? $('filter-severity').value : '');
    state.filters.ip = ($('filter-ip') ? $('filter-ip').value : '');
    state.filters.type = ($('filter-type') ? $('filter-type').value : '');
    state.filters.search = ($('filter-search') ? $('filter-search').value : '').trim().toLowerCase();
    return state.filters;
  }

  function applyFilters(events, f) {
    return events.filter(function (e) {
      if (f.eventId && String(e.eventId) !== f.eventId) { return false; }
      if (f.account && (e.account || '(not recorded)') !== f.account) { return false; }
      if (f.severity && e.severity !== f.severity) { return false; }
      if (f.ip && (e.sourceIp || '(none)') !== f.ip) { return false; }
      if (f.type && e.category !== f.type) { return false; }
      if (f.search && e.searchBlob.indexOf(f.search) === -1) { return false; }
      return true;
    });
  }

  function fillSelect(node, values, allLabel, format) {
    if (!node) { return; }
    var current = node.value;
    clearChildren(node);
    var optAll = makeEl('option', null, allLabel);
    optAll.value = '';
    node.appendChild(optAll);
    values.forEach(function (v) {
      var opt = makeEl('option', null, format ? format(v) : v);
      opt.value = v;
      node.appendChild(opt);
    });
    /* Keep the previous selection when it is still available. */
    var stillThere = values.some(function (v) { return v === current; });
    node.value = stillThere ? current : '';
  }

  function populateFilters(events) {
    var ids = uniqueValues(events, function (e) { return String(e.eventId); })
      .sort(function (a, b) { return parseInt(a, 10) - parseInt(b, 10); });
    var accounts = uniqueValues(events, function (e) { return e.account || '(not recorded)'; }).sort();
    var severities = uniqueValues(events, function (e) { return e.severity; })
      .sort(function (a, b) { return SEV_RANK[b] - SEV_RANK[a]; });
    var ips = uniqueValues(events, function (e) { return e.sourceIp; }).sort();
    var types = uniqueValues(events, function (e) { return e.category; }).sort();

    fillSelect($('filter-eventid'), ids, 'All Event IDs', function (v) {
      return v + ' \u2014 ' + (EVID_BY_STRING[v] ? EVID_BY_STRING[v].name : 'Unrecognised');
    });
    fillSelect($('filter-account'), accounts, 'All accounts');
    fillSelect($('filter-severity'), severities, 'All severities');
    fillSelect($('filter-ip'), ips, 'All source IPs');
    fillSelect($('filter-type'), types, 'All event types');
  }

  /* --- Events table ------------------------------------------------------ */

  var MAX_TABLE_ROWS = 500;

  function renderEventsTable() {
    var tbody = $('events-tbody');
    var countNode = $('events-count');
    if (!tbody || !state.dataset) { return; }

    var filters = readFilters();
    var filtered = applyFilters(state.dataset.events, filters);
    var shown = filtered.slice(0, MAX_TABLE_ROWS);

    clearChildren(tbody);

    shown.forEach(function (e) {
      var tr = makeEl('tr');
      var rank = SEV_RANK[e.severity];
      if (rank >= SEV_RANK[SEVERITY.MEDIUM]) { tr.className = 'row-medium'; }
      if (rank >= SEV_RANK[SEVERITY.HIGH]) { tr.className = 'row-high'; }
      if (rank === SEV_RANK[SEVERITY.LOW]) { tr.className = 'row-low'; }

      /* Severity cell keeps the visual badge. */
      var sevCell = makeEl('td');
      sevCell.innerHTML = severityBadge(e.severity);
      tr.appendChild(sevCell);

      tr.appendChild(makeEl('td', 'mono', e.eventId));
      tr.appendChild(makeEl('td', 'mono', e.timeRaw || 'not available'));
      tr.appendChild(makeEl('td', null, e.displayAccount || e.account || 'not recorded'));
      tr.appendChild(makeEl('td', null, e.category));
      tr.appendChild(makeEl('td', 'mono', e.sourceIp || '\u2014'));
      tr.appendChild(makeEl('td', null, e.computer || '\u2014'));
      tr.appendChild(makeEl('td', 'mono', keyDetail(e)));

      tbody.appendChild(tr);
    });

    if (shown.length === 0) {
      var emptyRow = makeEl('tr');
      var emptyCell = makeEl('td', 'mono', 'No events match the current filters.');
      emptyCell.colSpan = 8;
      emptyRow.appendChild(emptyCell);
      tbody.appendChild(emptyRow);
    }

    if (countNode) {
      var text = 'Showing ' + shown.length + ' of ' + filtered.length +
        ' event(s) matching the filters (' + state.dataset.events.length + ' parsed in total).';
      if (filtered.length > MAX_TABLE_ROWS) {
        text += ' The table is limited to the first ' + MAX_TABLE_ROWS +
          ' rows for performance; narrow the filters to see the rest.';
      }
      countNode.textContent = text;
    }
  }

  /* --- Report header ----------------------------------------------------- */

  function renderMeta(dataset, analysis) {
    var node = $('report-meta');
    if (!node) { return; }
    var meta = dataset.meta || {};
    var bits = [];
    bits.push('Source: ' + (meta.label || 'uploaded file'));
    if (meta.fileName) { bits.push('File: ' + meta.fileName); }
    if (meta.isSample) { bits.push('DEMO DATA \u2014 fictional dataset'); }
    bits.push('Delimiter detected: ' + dataset.delimiterLabel);
    bits.push('Events analysed: ' + dataset.events.length);
    if (dataset.skippedRows) { bits.push('Rows skipped: ' + dataset.skippedRows); }
    bits.push('Thresholds: ' + state.settings.failedLoginThreshold + ' failures in ' +
      state.settings.failedLoginWindowMinutes + ' minutes');
    bits.push('Timestamp correlation: ' +
      (dataset.hasTimestampColumn ? 'available' : 'unavailable'));
    bits.push('Message detail: ' +
      (dataset.detailUnavailable ? 'not readable' :
        (dataset.hasMessageColumn ? 'read from the Message column' : 'absent from export')));
    if (dataset.noiseCount) {
      bits.push('Background/noise events (machine or service accounts): ' + dataset.noiseCount);
    }
    node.textContent = bits.join('  \u00b7  ');
  }

  /* ======================= 17. REPORT PIPELINE =========================== */

  function renderWarnings(warnings) {
    var node = $('parse-warnings');
    if (!node) { return; }
    clearChildren(node);
    if (!warnings || warnings.length === 0) { hide(node); return; }
    warnings.forEach(function (w) {
      var li = makeEl('li');
      li.innerHTML = '&#9888; ' + w;   // warnings are built from constants and esc()'d values
      node.appendChild(li);
    });
    show(node);
  }

  function formatBytes(bytes) {
    if (!bytes && bytes !== 0) { return 'unknown size'; }
    if (bytes < 1024) { return bytes + ' bytes'; }
    if (bytes < 1024 * 1024) { return (bytes / 1024).toFixed(1) + ' KB'; }
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  }

  function renderFullReport(dataset, analysis) {
    show($('report'));
    renderMeta(dataset, analysis);
    renderScore(analysis.score);
    renderStats(analysis.stats);
    renderFindings(analysis.findings);
    renderTimeline(analysis.timeline);
    renderTables(analysis.stats);
    renderAdminActivity(analysis.adminGroups);
    populateFilters(dataset.events);
    renderEventsTable();
  }

  function processCsvText(csvText, meta) {
    var errorNode = $('parse-error');
    var statusNode = $('parse-status');
    var warnNode = $('parse-warnings');

    hide(errorNode);
    hide(statusNode);
    hide(warnNode);
    hide($('report'));

    /* Reset per-run state before parsing. */
    MONTH_DAY_AMBIGUITY.seen = false;
    MONTH_DAY_AMBIGUITY.examples = [];
    state.dataset = null;
    state.analysis = null;

    var dataset = buildDataset(csvText, meta);

    if (!dataset.ok) {
      setStatus(errorNode, 'error',
        '<strong>This file could not be analysed.</strong><ul><li>' +
        dataset.errors.join('</li><li>') + '</li></ul>' +
        '<p style="margin:0.5em 0 0">Nothing was uploaded anywhere. The file was read in this ' +
        'browser tab only.</p>');
      return;
    }

    var analysis = analyseDataset(dataset, state.settings);
    state.dataset = dataset;
    state.analysis = analysis;

    var summary = '<strong>Parsed successfully.</strong> ' +
      dataset.events.length + ' event(s) read from ' +
      (meta && meta.fileName ? esc(meta.fileName) : 'the supplied data') +
      ' using a ' + dataset.delimiterLabel + '-separated format. ' +
      dataset.events.length + ' of ' + dataset.dataRowCount + ' data row(s) contained a usable Event ID.';

    if (analysis.stats.investigateCount > 0) {
      summary += ' <strong>' + analysis.stats.investigateCount +
        '</strong> finding(s) are flagged as Low priority or above.';
    } else {
      summary += ' No findings were flagged above Informational priority.';
    }

    setStatus(statusNode, 'ok', summary);
    renderWarnings(dataset.warnings);
    renderFullReport(dataset, analysis);

    var reportNode = $('report');
    if (reportNode && typeof reportNode.scrollIntoView === 'function') {
      reportNode.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }

  /* ======================= 18. FILE INPUT ================================ */

  function handleFile(file) {
    var errorNode = $('parse-error');
    var metaNode = $('file-meta');

    if (!file) { return; }

    var name = file.name || 'unnamed file';
    var type = file.type || 'unknown type';

    if (file.size > LIMITS.maxBytes) {
      setStatus(errorNode, 'error',
        '<strong>This file is too large to analyse in the browser.</strong> It is ' +
        formatBytes(file.size) + ', and the limit for this educational tool is ' +
        formatBytes(LIMITS.maxBytes) + ' so that the page stays responsive. Filter the events in ' +
        'Event Viewer to a smaller time range, or export the Event IDs you specifically want to study.');
      return;
    }

    if (metaNode) {
      metaNode.textContent = 'Loaded file: ' + name + '  \u00b7  ' + formatBytes(file.size) +
        '  \u00b7  reported type: ' + type + '  \u00b7  read locally in this browser, not uploaded.';
      show(metaNode);
    }

    var reader = new FileReader();

    reader.onload = function () {
      var text = String(reader.result || '');
      var softWarnings = [];
      if (!/\.(csv|txt|log)$/i.test(name)) {
        softWarnings.push('The file name does not end in .csv, .txt or .log. It was still parsed ' +
          'because some exports use other names, but check that this is the file you meant to load.');
      }
      processCsvText(text, { fileName: name, label: 'uploaded file' });
      if (softWarnings.length) {
        var dataset = state.dataset;
        if (dataset) {
          renderWarnings(dataset.warnings.concat(softWarnings));
        }
      }
    };

    reader.onerror = function () {
      setStatus(errorNode, 'error',
        '<strong>The file could not be read.</strong> The browser refused to read it, or the file ' +
        'was locked by another program. Close any program that has the file open and try again.');
    };

    reader.readAsText(file);
  }

  function loadSample(key) {
    var sample = SAMPLES[key];
    if (!sample) { return; }

    var metaNode = $('file-meta');
    if (metaNode) {
      metaNode.textContent = 'Loaded demo dataset: ' + sample.label +
        '  \u00b7  DEMO DATA, entirely fictional  \u00b7  generated in this browser, not uploaded.';
      show(metaNode);
    }

    var csvText = sample.build();
    processCsvText(csvText, {
      label: 'Demo Data \u2014 ' + sample.label,
      fileName: sample.file,
      isSample: true
    });

    var statusNode = $('parse-status');
    if (statusNode && !statusNode.hidden) {
      statusNode.innerHTML += '<p style="margin:0.5em 0 0"><strong>Expected result for this demo ' +
        'dataset:</strong> ' + esc(sample.expect) + '</p>';
    }
  }

  /* ======================= 19. SETTINGS ================================= */

  function readSettingsFromInputs() {
    var thresholdNode = $('setting-threshold');
    var windowNode = $('setting-window');
    var noteNode = $('settings-note');

    var threshold = parseInt(thresholdNode ? thresholdNode.value : '', 10);
    var windowMinutes = parseInt(windowNode ? windowNode.value : '', 10);

    var messages = [];

    if (isNaN(threshold) || threshold < 2) {
      threshold = DEFAULTS.failedLoginThreshold;
      if (thresholdNode) { thresholdNode.value = threshold; }
      messages.push('Failed login threshold must be 2 or more; the default of ' + threshold +
        ' was restored.');
    }
    if (threshold > 1000) {
      threshold = 1000;
      if (thresholdNode) { thresholdNode.value = threshold; }
      messages.push('Failed login threshold was capped at 1000.');
    }
    if (isNaN(windowMinutes) || windowMinutes < 1) {
      windowMinutes = DEFAULTS.failedLoginWindowMinutes;
      if (windowNode) { windowNode.value = windowMinutes; }
      messages.push('Time window must be at least 1 minute; the default of ' + windowMinutes +
        ' was restored.');
    }
    if (windowMinutes > 10080) {
      windowMinutes = 10080;
      if (windowNode) { windowNode.value = windowMinutes; }
      messages.push('Time window was capped at 10080 minutes (one week).');
    }

    state.settings.failedLoginThreshold = threshold;
    state.settings.failedLoginWindowMinutes = windowMinutes;

    if (noteNode) {
      noteNode.textContent = messages.length
        ? messages.join(' ')
        : 'Thresholds applied: ' + threshold + ' failures within ' + windowMinutes +
          ' minutes. Change a value above to re-run the analysis immediately.';
    }
  }

  function resetSettings() {
    var thresholdNode = $('setting-threshold');
    var windowNode = $('setting-window');
    if (thresholdNode) { thresholdNode.value = DEFAULTS.failedLoginThreshold; }
    if (windowNode) { windowNode.value = DEFAULTS.failedLoginWindowMinutes; }
    readSettingsFromInputs();
    var noteNode = $('settings-note');
    if (noteNode) {
      noteNode.textContent = 'Defaults restored: ' + DEFAULTS.failedLoginThreshold +
        ' failed logons within ' + DEFAULTS.failedLoginWindowMinutes + ' minutes. Reminder: security ' +
        'thresholds vary by environment, and these are educational defaults rather than universal ' +
        'SOC detection rules.';
    }
    reanalyse();
  }

  /* Re-run the analysis when a threshold changes, so the effect is visible. */
  function reanalyse() {
    if (!state.dataset) { return; }

    /* A previous run may have raised severities on individual events through
       correlation, so reset each event to its own base severity first. */
    state.dataset.events.forEach(function (e) {
      e.severity = e.baseSeverity;
      delete e.severityRaisedBy;
    });

    var analysis = analyseDataset(state.dataset, state.settings);
    state.analysis = analysis;
    renderFullReport(state.dataset, analysis);
  }

  /* ======================= 20. EVENT WIRING ============================= */

  function openFileDialog() {
    var input = $('file-input');
    if (input) { input.click(); }
  }

  function wireDropZone() {
    var zone = $('drop-zone');
    if (!zone) { return; }

    zone.addEventListener('click', openFileDialog);

    zone.addEventListener('keydown', function (ev) {
      if (ev.key === 'Enter' || ev.key === ' ' || ev.key === 'Spacebar') {
        ev.preventDefault();
        openFileDialog();
      }
    });

    ['dragenter', 'dragover'].forEach(function (type) {
      zone.addEventListener(type, function (ev) {
        ev.preventDefault();
        ev.stopPropagation();
        zone.classList.add('is-dragover');
      });
    });

    ['dragleave', 'dragend'].forEach(function (type) {
      zone.addEventListener(type, function (ev) {
        ev.preventDefault();
        ev.stopPropagation();
        zone.classList.remove('is-dragover');
      });
    });

    zone.addEventListener('drop', function (ev) {
      ev.preventDefault();
      ev.stopPropagation();
      zone.classList.remove('is-dragover');

      var transfer = ev.dataTransfer;
      if (!transfer) { return; }

      if (transfer.files && transfer.files.length > 0) {
        handleFile(transfer.files[0]);
        return;
      }
      if (transfer.items && transfer.items.length > 0 && transfer.items[0].kind === 'file') {
        var file = transfer.items[0].getAsFile();
        if (file) { handleFile(file); }
      }
    });

    /* Stop the browser navigating away when a file is dropped outside the zone. */
    ['dragover', 'drop'].forEach(function (type) {
      document.addEventListener(type, function (ev) { ev.preventDefault(); }, false);
    });
  }

  function wireFileInput() {
    var input = $('file-input');
    if (!input) { return; }
    input.addEventListener('change', function () {
      if (input.files && input.files.length > 0) {
        handleFile(input.files[0]);
      }
      /* Allow the same file to be chosen again after an error. */
      input.value = '';
    });
  }

  function wireSampleButtons() {
    [['sample-normal', 'normal'],
     ['sample-password', 'password'],
     ['sample-persistence', 'persistence'],
     ['sample-mixed', 'mixed']].forEach(function (pair) {
      var button = $(pair[0]);
      if (button) {
        button.addEventListener('click', function () { loadSample(pair[1]); });
      }
    });
  }

  function wireSettings() {
    var thresholdNode = $('setting-threshold');
    var windowNode = $('setting-window');
    var resetNode = $('btn-reset-defaults');

    function onChange() {
      readSettingsFromInputs();
      reanalyse();
    }

    if (thresholdNode) {
      thresholdNode.addEventListener('change', onChange);
      thresholdNode.addEventListener('input', onChange);
    }
    if (windowNode) {
      windowNode.addEventListener('change', onChange);
      windowNode.addEventListener('input', onChange);
    }
    if (resetNode) {
      resetNode.addEventListener('click', resetSettings);
    }
  }

  function wireFilters() {
    ['filter-eventid', 'filter-account', 'filter-severity', 'filter-ip', 'filter-type']
      .forEach(function (id) {
        var node = $(id);
        if (node) { node.addEventListener('change', renderEventsTable); }
      });

    var search = $('filter-search');
    if (search) {
      search.addEventListener('input', renderEventsTable);
      search.addEventListener('search', renderEventsTable);
    }

    var clear = $('btn-clear-filters');
    if (clear) {
      clear.addEventListener('click', function () {
        ['filter-eventid', 'filter-account', 'filter-severity', 'filter-ip', 'filter-type']
          .forEach(function (id) {
            var node = $(id);
            if (node) { node.value = ''; }
          });
        if (search) { search.value = ''; }
        renderEventsTable();
      });
    }
  }

  function renderBuildInfo() {
    var node = $('build-info');
    if (!node) { return; }
    node.textContent = 'Version 1.0  \u00b7  Educational build  \u00b7  static HTML, CSS and ' +
      'vanilla JavaScript  \u00b7  no server, no database, no analytics, no telemetry, and ' +
      'no network requests of any kind.';
  }

  /* ======================= 22. TEST HOOK ================================ */
  /* These functions are exposed on window so that automated self-tests, and
     curious students working from the browser console, can exercise the pure
     logic directly. Everything exposed here is a pure function: it reads its
     arguments and returns a value. Nothing here performs any network access,
     and nothing is persisted. */

  window.TriageTool = {
    version: '1.0',
    parseCsvText: parseCsvText,
    detectDelimiter: detectDelimiter,
    buildColumnMap: buildColumnMap,
    buildDataset: buildDataset,
    analyseDataset: analyseDataset,
    processCsvText: processCsvText,
    parseTimestamp: parseTimestamp,
    splitMessageSections: splitMessageSections,
    findLabel: findLabel,
    extractDetails: extractDetails,
    looksEncodedOrObfuscated: looksEncodedOrObfuscated,
    isPrivilegedGroup: isPrivilegedGroup,
    esc: esc,
    samples: SAMPLES,
    defaults: DEFAULTS
  };

  /* ======================= 21. INITIALISE ================================ */

  function init() {
    renderEventIdReference();
    renderLimitations();
    renderBuildInfo();
    readSettingsFromInputs();
    wireDropZone();
    wireFileInput();
    wireSampleButtons();
    wireSettings();
    wireFilters();
    hide($('report'));
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
