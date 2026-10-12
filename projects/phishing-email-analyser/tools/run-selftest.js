/* ==========================================================================
 * tools/run-selftest.js
 * --------------------------------------------------------------------------
 * Runs the analyser's built-in self-tests using the JavaScript engine that is
 * already part of Windows (Windows Script Host). Nothing needs to be
 * installed and no network access is used.
 *
 * Run it with tools\run-tests.cmd, or directly:
 *     cscript //nologo tools\run-selftest.js
 * ========================================================================== */

var fso = new ActiveXObject('Scripting.FileSystemObject');
var here = fso.GetParentFolderName(WScript.ScriptFullName);
var root = fso.GetParentFolderName(here);

/* Make the global object available as "window" so that the analyser files can
   use the same idiom they use in a browser. */
window = this;

var files = [
  'js\\rules.js',
  'js\\headers.js',
  'js\\analyser.js',
  'js\\samples.js',
  'js\\selftest.js'
];

for (var i = 0; i < files.length; i++) {
  var full = root + '\\' + files[i];
  if (!fso.FileExists(full)) {
    WScript.Echo('MISSING FILE: ' + full);
    WScript.Quit(2);
  }
  var stream = fso.OpenTextFile(full, 1);
  var source = stream.ReadAll();
  stream.Close();
  try {
    eval(source);
  } catch (e) {
    WScript.Echo('ERROR while loading ' + files[i]);
    WScript.Echo('  ' + e.name + ': ' + e.description);
    if (e.number) { WScript.Echo('  code ' + e.number); }
    WScript.Quit(2);
  }
}

if (typeof PA === 'undefined' || !PA || !PA.runSelfTest) {
  WScript.Echo('The analyser files did not load correctly (PA is undefined).');
  WScript.Quit(2);
}

var summary = PA.runSelfTest();

WScript.Echo('');
WScript.Echo('Phishing Email Analyser -- self-test');
WScript.Echo('====================================');
WScript.Echo('');

for (var r = 0; r < summary.results.length; r++) {
  var item = summary.results[r];
  if (!item.pass) {
    WScript.Echo('FAIL  ' + item.name);
    if (item.detail) { WScript.Echo('      ' + item.detail); }
  }
}

WScript.Echo('');
WScript.Echo('Demonstration email results');
WScript.Echo('---------------------------');
for (var s = 0; s < PA.samples.length; s++) {
  var sample = PA.samples[s];
  var outcome = PA.analyse({ body: sample.body, headers: sample.headers });
  WScript.Echo('  ' + outcome.score + '/100  ' + outcome.band.label
    + '  (' + outcome.findings.length + ' findings)  ' + sample.name);
}

WScript.Echo('');
WScript.Echo('Rules defined : ' + PA.ruleCatalogue().length
  + ' (' + PA.rules.length + ' body, ' + PA.headerRules.length + ' header)');
WScript.Echo('Tests run     : ' + summary.total);
WScript.Echo('Passed        : ' + summary.passed);
WScript.Echo('Failed        : ' + summary.failed);
WScript.Echo('');

if (summary.failed > 0) {
  WScript.Echo('RESULT: FAILURES PRESENT');
  WScript.Quit(1);
}
WScript.Echo('RESULT: ALL TESTS PASSED');
WScript.Quit(0);
