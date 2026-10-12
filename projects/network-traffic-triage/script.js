'use strict';
(() => {
  const MAX_BYTES = 10 * 1024 * 1024, MAX_ROWS = 50000;
  const defaults = Object.freeze({ volume: 50, hosts: 10, ports: 10, icmp: 30, dns: 30, repeat: 40 });
  const labels = { volume: 'Packets per source', hosts: 'Unique destination IPs', ports: 'Unique destination ports', icmp: 'ICMP packets per source', dns: 'DNS packets per source', repeat: 'Source-to-destination packets' };
  const aliases = {
    source: ['source', 'sourceip', 'src', 'ipsrc', 'ipv6src', 'srcip', 'sourceaddress'],
    destination: ['destination', 'destinationip', 'dst', 'ipdst', 'ipv6dst', 'dstip', 'destinationaddress'],
    protocol: ['protocol', 'proto', 'wscolprotocol'], length: ['length', 'len', 'framelen', 'packetlength', 'size'],
    info: ['info', 'information', 'summary', 'wscolinfo'], time: ['time', 'timestamp', 'frametimerelative'], number: ['no', 'number', 'framenumber']
  };
  const normalize = s => s.trim().toLowerCase().replace(/[^a-z0-9]/g, '');
  function csvRows(text) {
    if (new Blob([text]).size > MAX_BYTES) throw Error('File exceeds the 10 MB limit. Export a smaller packet list.');
    text = text.replace(/^\uFEFF/, '');
    if (text.includes('\0')) throw Error('This file contains binary data, not a supported text CSV.');
    const rows = []; let row = [], value = '', state = 'start';
    const field = () => { row.push(value); value = ''; state = 'start'; };
    const line = () => { field(); if (row.some(v => v.trim() !== '')) rows.push(row); row = []; if (rows.length > MAX_ROWS + 1) throw Error('More than 50,000 packet rows. Export a smaller CSV.'); };
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (state === 'quoted') { if (c === '"') { if (text[i + 1] === '"') { value += '"'; i++; } else state = 'closed'; } else value += c; continue; }
      if (c === ',') { field(); continue; }
      if (c === '\r' || c === '\n') { if (c === '\r' && text[i + 1] === '\n') i++; line(); continue; }
      if (state === 'closed') { if (c === ' ' || c === '\t') continue; throw Error('Malformed CSV: unexpected text after a quoted field.'); }
      if (c === '"') { if (state !== 'start') throw Error('Malformed CSV: quotation mark inside an unquoted field.'); state = 'quoted'; }
      else { value += c; state = 'plain'; }
    }
    if (state === 'quoted') throw Error('Malformed CSV: a quoted field was not closed.');
    if (row.length || value || state === 'closed') line();
    return rows;
  }
  function parseCSV(text) {
    const rows = csvRows(text);
    if (!rows.length) throw Error('The CSV is empty.');
    const headers = rows.shift().map(normalize), fields = {}, warnings = [];
    for (const [key, names] of Object.entries(aliases)) {
      const matches = headers.map((h, i) => names.includes(h) ? i : -1).filter(i => i >= 0);
      if (matches.length > 1) throw Error(`Ambiguous ${key} columns. Keep one column for this field.`);
      fields[key] = matches.length ? matches[0] : -1;
    }
    if (Object.values(fields).every(i => i < 0)) throw Error('No recognised Wireshark columns. Include a header row and use comma-separated CSV.');
    for (const key of ['source', 'destination', 'protocol', 'length', 'info']) if (fields[key] < 0) warnings.push(`This CSV does not contain a recognised ${key} column. Related analysis is unavailable.`);
    let invalidLengths = 0, blankSources = 0, blankDestinations = 0, blankProtocols = 0;
    const packets = rows.map((r, i) => {
      if (r.length !== headers.length) throw Error(`CSV record ${i + 2} has ${r.length} fields; expected ${headers.length}. No partial report was generated.`);
      const get = key => fields[key] < 0 ? '' : r[fields[key]].trim();
      const rawLength = get('length');
      const length = /^\d+$/.test(rawLength) && Number.isSafeInteger(Number(rawLength)) ? Number(rawLength) : null;
      if (fields.length >= 0 && length === null) invalidLengths++;
      const source = get('source'), destination = get('destination'), protocol = get('protocol').toUpperCase();
      if (!source) blankSources++; if (!destination) blankDestinations++; if (!protocol) blankProtocols++;
      return { number: get('number') || String(i + 1), time: get('time'), source, destination, protocol, length, info: get('info') };
    });
    if (!packets.length) throw Error('The CSV contains headings but no packet rows.');
    if (invalidLengths) warnings.push(`${invalidLengths} missing or invalid lengths excluded from the average.`);
    if (fields.source >= 0 && blankSources) warnings.push(`${blankSources} rows have no source; excluded from source-based analysis.`);
    if (fields.destination >= 0 && blankDestinations) warnings.push(`${blankDestinations} rows have no destination; excluded from destination-based analysis.`);
    if (fields.protocol >= 0 && blankProtocols) warnings.push(`${blankProtocols} rows have no protocol; excluded from protocol-specific rules.`);
    return { packets, fields, warnings };
  }
  function isIP(value) {
    if (/^\d+\.\d+\.\d+\.\d+$/.test(value)) return value.split('.').every(n => Number(n) <= 255);
    if (!value.includes(':') || /[^a-fA-F0-9:.]/.test(value)) return false;
    try { return new URL(`http://[${value}]/`).hostname.startsWith('['); } catch { return false; }
  }
  function destinationPort(p) {
    if (!['TCP', 'UDP'].includes(p.protocol)) return null;
    const match = p.info.match(/^\s*(\d{1,5})\s*(?:→|->|>)\s*(\d{1,5})(?=\s|$|\[)/);
    return match && Number(match[1]) <= 65535 && Number(match[2]) <= 65535 ? Number(match[2]) : null;
  }
  const increment = (map, key) => { if (key) map.set(key, (map.get(key) || 0) + 1); };
  const ranked = map => [...map].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  function analyse(packets, thresholds = defaults) {
    for (const key of Object.keys(defaults)) if (!Number.isSafeInteger(thresholds[key]) || thresholds[key] < 0) throw Error('Thresholds must be nonnegative whole numbers.');
    const sources = new Map(), destinations = new Map(), protocols = new Map(), hosts = new Map();
    let sum = 0, lengths = 0, portPackets = 0;
    for (const p of packets) {
      increment(sources, p.source); increment(destinations, p.destination); increment(protocols, p.protocol || '(Unavailable)');
      if (p.length !== null) { sum += p.length; lengths++; }
      if (!p.source) continue;
      if (!hosts.has(p.source)) hosts.set(p.source, { packets: [], destinations: new Set(), pairs: new Map(), icmp: [], dns: [] });
      const h = hosts.get(p.source); h.packets.push(p);
      if (isIP(p.destination)) h.destinations.add(p.destination.toLowerCase());
      if (['ICMP', 'ICMPV6'].includes(p.protocol)) h.icmp.push(p);
      if (p.protocol === 'DNS') h.dns.push(p);
      if (p.destination) {
        if (!h.pairs.has(p.destination)) h.pairs.set(p.destination, { packets: [], ports: new Set(), portEvidence: [] });
        const pair = h.pairs.get(p.destination); pair.packets.push(p);
        const port = destinationPort(p); if (port !== null) { pair.ports.add(port); pair.portEvidence.push(p); portPackets++; }
      }
    }
    const alerts = [];
    const add = (rule, severity, source, destination, count, unit, evidence, why, benign, investigation, extra = '') => {
      if (count <= thresholds[rule]) return;
      const names = { volume: 'High Packet Volume', hosts: 'Possible Network Scanning', ports: 'Possible Port Scanning', icmp: 'High ICMP Activity', dns: 'High DNS Activity', repeat: 'Repeated Source-to-Destination Communication' };
      alerts.push({ rule, name: names[rule], severity, source, destination, count, threshold: thresholds[rule], observed: `${count} ${unit}${extra}`, why, benign, investigation, evidence });
    };
    for (const [source, h] of hosts) {
      add('volume', 'Low', source, '', h.packets.length, 'packets from this source.', h.packets, 'High packet counts can identify a busy or unexpectedly active device. Volume alone does not establish harmful intent.', 'File transfers, software updates, backups, automated scripts, or routine application use.', 'Identify the device and capture duration; compare with its normal role. Review destinations and endpoint logs for unexpected automation, scanning, or misconfiguration.');
      add('hosts', 'Medium', source, '', h.destinations.size, 'unique destination IP addresses.', h.packets.filter(p => isIP(p.destination)), 'Contact with many systems may be consistent with host discovery or network scanning; this rule does not establish intent or timing.', 'Authorised vulnerability scanning, asset discovery, network management, monitoring, or applications using many services.', 'Identify the source; check whether it is an authorised scanner. Review destination addresses, ports, and protocols and correlate with endpoint telemetry.');
      add('icmp', 'Medium', source, '', h.icmp.length, 'ICMP/ICMPv6 packets.', h.icmp, 'Large ICMP counts can accompany discovery, ping sweeps, or denial-of-service activity, but counts alone cannot distinguish those from routine use.', 'Troubleshooting, monitoring, IPv6 neighbour discovery, or expected diagnostic tests.', 'Review ICMP types and request/reply direction in Wireshark. Check monitoring schedules, capture duration, and whether destinations are expected.');
      add('dns', 'Low', source, '', h.dns.length, 'DNS packets (queries and responses are not distinguished).', h.dns, 'Heavy DNS activity can reflect automated lookups or suspicious beaconing, but this rule does not analyse domains, timing, or prove either behaviour.', 'Normal browsing, software updates, DNS resolver responses, automated applications, or misconfiguration.', 'Determine whether the host is a DNS resolver. Review query names, failures, and timing in Wireshark and correlate with process activity.');
      for (const [destination, pair] of h.pairs) {
        const pm = new Map(); pair.packets.forEach(p => increment(pm, p.protocol || '(Unavailable)'));
        add('repeat', 'Low', source, destination, pair.packets.length, 'packets in this direction.', pair.packets, 'Repeated communication can identify persistent application traffic or automated activity. No periodicity or beaconing is inferred.', 'Streaming, backups, long-lived application sessions, downloads, or monitoring.', 'Identify the destination service and owning process. Review capture duration, payload visibility, timing, and whether the relationship is expected.', ` Most common protocol: ${ranked(pm)[0][0]}.`);
        add('ports', 'Medium', source, destination, pair.ports.size, 'distinct destination ports inferred from TCP/UDP Info.', pair.portEvidence, 'Many ports on one destination may be consistent with service discovery or port scanning. Direction and intent need confirmation.', 'Authorised service discovery, vulnerability testing, application behaviour, or server responses to many client ephemeral ports.', 'Confirm which side initiated connections in Wireshark. Review ports, TCP flags, source processes, and authorised scanning activity.', ` Ports: ${[...pair.ports].sort((a,b) => a-b).join(', ')}.`);
      }
    }
    return { sources, destinations, protocols, alerts, average: lengths ? sum / lengths : null, lengths, portPackets };
  }
  const el = (tag, text, className) => { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (className) n.className = className; return n; };
  function alertCard(a) {
    const card = el('article', undefined, 'card alert'); card.append(el('h4', a.name), el('p', `Severity: ${a.severity} — investigative priority only`, `severity ${a.severity}`));
    const dl = el('dl');
    for (const [label, value] of [['Source Host', a.source], ['Destination Host', a.destination || 'Multiple / not specific to one destination'], ['Observed Activity', a.observed], ['Configured Threshold', `More than ${a.threshold}`], ['Why This Could Matter', a.why], ['Possible Benign Explanations', a.benign], ['Suggested Investigation', a.investigation]]) dl.append(el('dt', label), el('dd', value));
    card.append(dl); return card;
  }
  window.Triage = Object.freeze({ parseCSV, analyse, defaults, destinationPort, isIP, alertCard, MAX_BYTES, MAX_ROWS });
  if (!document.getElementById('file')) return;
  const $ = id => document.getElementById(id);
  let loaded = null, report = null, thresholds = { ...defaults }, loadToken = 0;
  for (const key of Object.keys(defaults)) { const label = el('label', labels[key]); const input = el('input'); input.id = `threshold-${key}`; input.type = 'number'; input.min = '0'; input.max = '1000000000'; input.step = '1'; input.required = true; input.value = defaults[key]; label.append(input); $('thresholds').append(label); }
  function table(container, headings, rows) {
    const t = el('table'), head = el('thead'), tr = el('tr'); headings.forEach(h => { const th = el('th', h); th.scope = 'col'; tr.append(th); }); head.append(tr); t.append(head);
    const body = el('tbody'); for (const row of rows) { const r = el('tr'); row.forEach(v => r.append(el('td', String(v)))); body.append(r); } t.append(body); container.replaceChildren(t);
  }
  function resetFilters() { for (const id of ['source-filter', 'destination-filter', 'severity-filter', 'search-filter']) $(id).value = ''; $('protocol-filter').replaceChildren(new Option('All protocols', '')); }
  function clear() { loaded = null; report = null; $('results').hidden = true; for (const id of ['warnings', 'overview', 'sources', 'destinations', 'protocols', 'coverage', 'alerts', 'packets']) $(id).replaceChildren(); resetFilters(); $('file').value = ''; }
  function render() {
    report = analyse(loaded.packets, thresholds); $('results').hidden = false;
    const top = map => map.size ? `${ranked(map)[0][0]} (${ranked(map)[0][1]} packets)` : 'Unavailable';
    const metrics = [['Total packets', loaded.packets.length], ['Unique source hosts', report.sources.size], ['Unique destination hosts', report.destinations.size], ['Most active source', top(report.sources)], ['Most contacted destination', top(report.destinations)], ['Most common protocol', top(report.protocols)], ['Average packet length', report.average === null ? 'Unavailable' : `${report.average.toFixed(1)} bytes (${report.lengths} valid rows)`]];
    $('overview').replaceChildren(...metrics.map(([label, value]) => { const card = el('div', undefined, 'card'); card.append(el('span', label), el('strong', String(value), 'metric')); return card; }));
    for (const [id, map] of [['sources', report.sources], ['destinations', report.destinations]]) {
      table($(id), ['Address', 'Packets', 'Relative activity'], ranked(map).slice(0, 10).map(([host, count]) => [host, count, `${(count / loaded.packets.length * 100).toFixed(1)}%`]));
      const cells = $(id).querySelectorAll('tbody tr'); ranked(map).slice(0, 10).forEach(([host,count], i) => { const bar = el('meter'); bar.min = 0; bar.max = loaded.packets.length; bar.value = count; bar.setAttribute('aria-label', `${host}: ${count} packets`); cells[i].lastChild.append(bar); });
    }
    table($('protocols'), ['Exported protocol', 'Packets'], ranked(report.protocols));
    $('coverage').replaceChildren(...[
      `Port analysis: ${report.portPackets} of ${loaded.packets.length} packets have a source, destination, and usable numeric TCP/UDP port pattern. Other packets cannot contribute to this rule.`,
      'Destination-spread detection counts numeric IPs only; resolved names and non-IP addresses are excluded. Other host counts use address labels as exported.',
      'DNS detection counts DNS-labelled packets, not confirmed queries. ICMP includes ICMPv6. Protocol labels are retained as exported (including TLS versions and application protocols).',
      'Missing source/destination fields disable the rules requiring them. Missing protocol fields disable ICMP, DNS, and port rules. TCP SYN / flag analysis is not implemented.',
      'All counts span the full export. No time-window, traffic-baseline, malware, or attack-certainty analysis is performed.'
    ].map(t => el('li', t)));
    const previous = $('protocol-filter').value; $('protocol-filter').replaceChildren(new Option('All protocols', '')); for (const name of [...report.protocols.keys()].sort()) $('protocol-filter').add(new Option(name, name)); $('protocol-filter').value = previous;
    renderFiltered();
  }
  function renderFiltered() {
    if (!report) return;
    const src = $('source-filter').value.toLowerCase(), dst = $('destination-filter').value.toLowerCase(), proto = $('protocol-filter').value, severity = $('severity-filter').value, search = $('search-filter').value.toLowerCase();
    const base = p => p.source.toLowerCase().includes(src) && p.destination.toLowerCase().includes(dst) && (!proto || (p.protocol || '(Unavailable)') === proto);
    const packets = loaded.packets.filter(p => base(p) && Object.values(p).join(' ').toLowerCase().includes(search));
    const alerts = report.alerts.filter(a => (!severity || a.severity === severity) && a.evidence.some(base) && (Object.entries(a).filter(([k]) => k !== 'evidence').map(([,v]) => v).join(' ').toLowerCase().includes(search) || a.evidence.some(p => base(p) && Object.values(p).join(' ').toLowerCase().includes(search))));
    $('alert-count').textContent = `${alerts.length} of ${report.alerts.length} alerts match. ${report.alerts.length ? 'Review context and benign explanations before drawing conclusions.' : 'No configured rules triggered. This does not establish that the traffic is safe.'}${alerts.length > 200 ? ' Showing first 200; narrow filters to see others.' : ''}`;
    $('alerts').replaceChildren(...alerts.slice(0, 200).map(alertCard));
    $('packet-count').textContent = `${packets.length} packets match; displaying first ${Math.min(packets.length, 200)}. Full-capture counts remain unchanged.`;
    table($('packets'), ['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info'], packets.slice(0, 200).map(p => [p.number, p.time, p.source, p.destination, p.protocol, p.length ?? 'Unavailable', p.info]));
  }
  function accept(text, filename, demo) {
    try { loaded = parseCSV(text); $('warnings').replaceChildren(...loaded.warnings.map(w => el('li', w))); resetFilters(); render(); $('status').textContent = `${demo ? 'Demo Data · ' : ''}${filename} · ${loaded.packets.length} packets loaded · parsed successfully${loaded.warnings.length ? ' with warnings' : ''}.`; }
    catch (error) { clear(); $('status').textContent = `Could not load ${filename}: ${error.message}`; }
  }
  async function upload(files) {
    const token = ++loadToken; clear();
    if (files.length !== 1) { $('status').textContent = 'Please select exactly one CSV file.'; return; }
    const file = files[0];
    if (!/\.csv$/i.test(file.name)) { $('status').textContent = 'Unsupported file type. Choose a .csv file, not PCAP or PCAPNG.'; return; }
    if (file.size > MAX_BYTES) { $('status').textContent = 'File exceeds the 10 MB limit.'; return; }
    $('status').textContent = `Reading ${file.name} locally…`;
    try { const bytes = await file.arrayBuffer(); const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); if (token === loadToken) accept(text, file.name, false); }
    catch (error) { if (token === loadToken) { clear(); $('status').textContent = `Cannot read this file as UTF-8 CSV: ${error.message}`; } }
  }
  $('file').addEventListener('change', e => { const files = [...e.target.files]; if (files.length) upload(files); });
  for (const id of ['normal', 'high', 'mixed']) $(id).addEventListener('click', () => { ++loadToken; clear(); const sample = window.TriageSamples[id]; accept(sample.csv, sample.filename, true); });
  $('clear').addEventListener('click', () => { ++loadToken; clear(); $('status').textContent = 'Data cleared from the application. No file loaded.'; });
  const zone = $('drop-zone');
  for (const type of ['dragover', 'drop']) document.addEventListener(type, e => e.preventDefault());
  zone.addEventListener('dragover', () => zone.classList.add('drag')); zone.addEventListener('dragleave', () => zone.classList.remove('drag'));
  zone.addEventListener('drop', e => { zone.classList.remove('drag'); upload([...e.dataTransfer.files]); });
  $('settings').addEventListener('submit', e => { e.preventDefault(); if (!$('settings').reportValidity()) return; thresholds = Object.fromEntries(Object.keys(defaults).map(k => [k, Number($(`threshold-${k}`).value)])); if (loaded) render(); $('settings-status').textContent = 'Thresholds applied to the full capture.'; });
  $('reset').addEventListener('click', () => { thresholds = { ...defaults }; for (const k of Object.keys(defaults)) $(`threshold-${k}`).value = defaults[k]; if (loaded) render(); $('settings-status').textContent = 'Educational defaults restored.'; });
  for (const id of ['source-filter', 'destination-filter', 'protocol-filter', 'severity-filter', 'search-filter']) $(id).addEventListener('input', renderFiltered);
})();