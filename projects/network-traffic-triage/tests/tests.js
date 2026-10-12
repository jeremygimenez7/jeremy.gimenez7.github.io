'use strict';
(() => {
  const T = window.Triage; let passed = 0, failed = 0;
  const assert = (condition, message = 'Assertion failed') => { if (!condition) throw Error(message); };
  function test(name, fn) { const li = document.createElement('li'); try { fn(); passed++; li.textContent = `PASS: ${name}`; } catch (e) { failed++; li.textContent = `FAIL: ${name}: ${e.message}`; } document.getElementById('test-results').append(li); }
  function rejects(text) { let rejected = false; try { T.parseCSV(text); } catch { rejected = true; } assert(rejected, 'Expected rejection'); }
  const parse = text => T.parseCSV(text).packets;
  const packet = (overrides = {}) => ({ number: '1', time: '0', source: '10.0.0.1', destination: '10.0.0.2', protocol: 'TCP', length: 60, info: '50000 → 443 [ACK]', ...overrides });
  const rows = (n, overrides) => Array.from({ length: n }, () => packet(overrides));
  const has = (packets, rule, thresholds = T.defaults) => T.analyse(packets, thresholds).alerts.some(a => a.rule === rule);
  test('Normal sample: 18 packets, no alerts', () => { const p = parse(TriageSamples.normal.csv); assert(p.length === 18); assert(T.analyse(p).alerts.length === 0); });
  test('High sample: 60 packets, exactly one volume alert', () => { const p = parse(TriageSamples.high.csv), a = T.analyse(p).alerts; assert(p.length === 60 && a.length === 1 && a[0].rule === 'volume'); });
  test('Mixed lab: 176 packets and all six rule types', () => { const p = parse(TriageSamples.mixed.csv), a = T.analyse(p).alerts; assert(p.length === 176); assert(new Set(a.map(x => x.rule)).size === 6); assert(a.length === 7); });
  test('Every alert includes explanations, evidence, and threshold', () => { for (const a of T.analyse(parse(TriageSamples.mixed.csv)).alerts) for (const k of ['name','severity','source','observed','threshold','why','benign','investigation','evidence']) assert(a[k], k); });
  test('Volume boundary: 50 does not trigger, 51 does', () => { assert(!has(rows(50), 'volume')); assert(has(rows(51), 'volume')); });
  test('Configurable volume threshold suppresses 60 packets', () => assert(!has(rows(60), 'volume', { ...T.defaults, volume: 60 })));
  test('Destination boundary: 10 versus 11', () => { const p = Array.from({length:11}, (_,i) => packet({destination:`10.0.1.${i+1}`})); assert(!has(p.slice(0,10),'hosts')); assert(has(p,'hosts')); });
  test('Port boundary: 10 versus 11 on the same destination', () => { const p = Array.from({length:11}, (_,i) => packet({info:`50000 → ${8000+i} [ACK]`})); assert(!has(p.slice(0,10),'ports')); assert(has(p,'ports')); });
  test('Ports are counted separately for each destination', () => { const p = Array.from({length:20}, (_,i) => packet({destination:`10.0.1.${i+1}`,info:`50000 → ${8000+i}`})); assert(!has(p,'ports')); });
  test('ICMP boundary: 30 versus 31; includes ICMPv6', () => { assert(!has(rows(30,{protocol:'ICMP'}),'icmp')); assert(has(rows(31,{protocol:'ICMPV6'}),'icmp')); });
  test('DNS boundary: 30 versus 31', () => { assert(!has(rows(30,{protocol:'DNS'}),'dns')); assert(has(rows(31,{protocol:'DNS'}),'dns')); });
  test('Pair boundary: 40 versus 41', () => { assert(!has(rows(40),'repeat')); assert(has(rows(41),'repeat')); });
  test('Quoted commas, escaped quotes, multiline text, BOM and CRLF', () => { const p = parse('\uFEFFSource,Info\r\n10.0.0.1,"hello, ""student""\r\nnext line"\r\n'); assert(p[0].info === 'hello, "student"\r\nnext line'); });
  test('Header aliases and case variations', () => { const p = parse('ip.src,Source ignored,ip.dst,proto,frame.len,summary\n10.0.0.1,x,10.0.0.2,tcp,64,hello'); assert(p[0].source === '10.0.0.1' && p[0].length === 64 && p[0].protocol === 'TCP'); });
  test('Missing source warns and safely disables source rules', () => { const r = T.parseCSV('Destination,Protocol\n10.0.0.2,DNS'); assert(r.warnings.some(w => w.includes('source'))); assert(T.analyse(r.packets).alerts.length === 0); });
  test('Invalid lengths excluded from average', () => { const r = T.analyse(parse('Source,Length\na,100\na,invalid\na,200\na,-4')); assert(r.average === 150 && r.lengths === 2); });
  test('Unknown addresses cannot trigger IP destination spread', () => assert(!has(Array.from({length:20},(_,i) => packet({destination:`host-${i}`})),'hosts')));
  test('IPv4 and IPv6 validation', () => { assert(T.isIP('192.0.2.1')); assert(T.isIP('2001:db8::1')); assert(!T.isIP('999.0.0.1')); assert(!T.isIP('aa:bb:cc:dd:ee:ff')); });
  test('Port extraction is conservative', () => { assert(T.destinationPort(packet()) === 443); assert(T.destinationPort(packet({info:'123 -> 53'})) === 53); assert(T.destinationPort(packet({info:'123 → 70000'})) === null); assert(T.destinationPort(packet({protocol:'HTTP'})) === null); assert(T.destinationPort(packet({info:'text 123 → 80'})) === null); });
  for (const [name, csv] of [['empty',''],['headers only','Source,Info'],['unclosed quote','Source,Info\na,"oops'],['ragged row','Source,Info\na,b,c'],['stray quote','Source\na"b'],['trailing quoted garbage','Source\n"a"b'],['binary','Source\na\0'],['unknown headings','foo,bar\na,b'],['ambiguous headings','Source,src\na,b']]) test(`Rejects ${name}`, () => rejects(csv));
  test('50,001 rows rejected', () => rejects('Source\n' + '10.0.0.1\n'.repeat(50001)));
  test('File over 10 MB rejected', () => rejects('Source\n' + 'x'.repeat(T.MAX_BYTES)));
  test('Prototype-like host strings safely counted using Map', () => { const r = T.analyse(rows(51,{source:'__proto__'})); assert(r.sources.get('__proto__') === 51); });
  test('CSV HTML remains inert in rendered alerts', () => {
    const payload = '<img src=x onerror="window.triageInjected=true"><script>window.triageInjected=true</script>';
    const csv = 'Source,Destination,Protocol,Info\n' + Array.from({length:51},() => `"${payload.replaceAll('"','""')}",10.0.0.2,TCP,hello`).join('\n');
    const a = T.analyse(parse(csv)).alerts.find(a => a.rule === 'volume'); const card = T.alertCard(a); document.getElementById('fixture').append(card);
    assert(card.textContent.includes(payload)); assert(!card.querySelector('img,script')); assert(!window.triageInjected); card.remove();
  });
  test('Negative thresholds rejected', () => { let rejected = false; try { T.analyse(rows(1),{...T.defaults,volume:-1}); } catch { rejected = true; } assert(rejected); });
  document.getElementById('test-summary').textContent = `${passed} passed; ${failed} failed.`;
  document.body.dataset.testResult = failed ? 'FAIL' : 'PASS';
})();