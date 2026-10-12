/* ==========================================================================
 * app.js -- the user interface
 * --------------------------------------------------------------------------
 * This is the only file that touches the page. It reads the two text boxes,
 * hands the text to PA.analyse(), and renders the result.
 *
 * Two rules are followed throughout:
 *   1. No network requests of any kind are made from this file.
 *   2. Email content is only ever written into the page with textContent, so
 *      a message that contains HTML or scripts cannot inject anything.
 * ========================================================================== */

(function () {
  'use strict';

  var PA = window.PA;
  var bodyInput = document.getElementById('email-body');
  var headersInput = document.getElementById('email-headers');
  var analyseBtn = document.getElementById('analyse-btn');
  var clearBtn = document.getElementById('clear-btn');
  var formMessage = document.getElementById('form-message');
  var charCount = document.getElementById('char-count');
  var urlCount = document.getElementById('url-count');
  var sampleButtons = document.getElementById('sample-buttons');
  var emptyState = document.getElementById('empty-state');
  var resultBody = document.getElementById('result-body');
  var rulesCount = document.getElementById('rules-count');
  var ruleCatalogue = document.getElementById('rule-catalogue');

  var selectedSample = null;

  /* ============================ tiny DOM helpers ======================== */

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) { node.className = className; }
    if (text != null) { node.textContent = String(text); }
    return node;
  }

  function clear(node) {
    while (node.firstChild) { node.removeChild(node.firstChild); }
  }

  function num(value) {
    return String(value).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  }

  /* ============================== the samples =========================== */

  function buildSampleButtons() {
    for (var i = 0; i < PA.samples.length; i++) {
      (function (sample) {
        var button = el('button', 'chip', sample.name);
        button.type = 'button';
        button.setAttribute('aria-pressed', 'false');
        button.title = sample.blurb;
        button.addEventListener('click', function () { loadSample(sample); });
        sampleButtons.appendChild(button);
      })(PA.samples[i]);
    }
  }

  function loadSample(sample) {
    bodyInput.value = sample.body;
    headersInput.value = sample.headers;

    var details = document.getElementById('advanced-headers');
    if (details && sample.headers) { details.open = true; }

    var buttons = sampleButtons.querySelectorAll('button');
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].setAttribute('aria-pressed',
        buttons[i].textContent === sample.name ? 'true' : 'false');
    }

    selectedSample = sample;
    updateCounts();
    runAnalysis();
  }

  /* ============================== counters ============================== */

  function updateCounts() {
    var text = bodyInput.value;
    charCount.textContent = num(text.length) + (text.length === 1 ? ' character' : ' characters');
    var links = text ? PA.extractLinks(text).length : 0;
    urlCount.textContent = links + (links === 1 ? ' link found' : ' links found');
  }

  /* ============================== analysis ============================== */

  function runAnalysis() {
    var text = bodyInput.value;

    if (!PA.util.trim(text) && !PA.util.trim(headersInput.value)) {
      formMessage.textContent = 'Paste the email text (or raw headers) first.';
      return;
    }
    formMessage.textContent = '';

    var result;
    try {
      result = PA.analyse({ body: text, headers: headersInput.value });
    } catch (err) {
      formMessage.textContent = 'Something went wrong while analysing that text. Please try again.';
      return;
    }

    renderResult(result);
    emptyState.hidden = true;
    resultBody.hidden = false;
    rulesCount.textContent = 'Ran ' + result.checksRun + ' of ' + result.checksTotal + ' checks';

    if (window.matchMedia && window.matchMedia('(max-width: 1000px)').matches) {
      resultBody.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }

  /* ============================== rendering ============================= */

  function metric(label, value) {
    var span = el('span');
    span.appendChild(el('b', null, String(value)));
    span.appendChild(document.createTextNode(' ' + label));
    return span;
  }

  function renderResult(result) {
    clear(resultBody);

    resultBody.appendChild(renderVerdict(result));
    resultBody.appendChild(renderFindings(result));
    if (result.notChecked.length) { resultBody.appendChild(renderNotChecked(result)); }
    resultBody.appendChild(renderBreakdown(result));
    if (result.headerFacts.length) { resultBody.appendChild(renderHeaderFacts(result)); }
    if (result.notes.length) { resultBody.appendChild(renderNotes(result)); }
    resultBody.appendChild(renderRecommendations(result));
    resultBody.appendChild(renderReminder());
    if (selectedSample && selectedSample.steps && selectedSample.steps.length) {
      resultBody.appendChild(renderSampleNotes(selectedSample));
    }
  }

  /* -------------------------- teaching notes --------------------------- */

  function renderSampleNotes(sample) {
    var section = el('section', 'result-section');
    var details = el('details', 'advanced');

    var summary = el('summary');
    summary.appendChild(el('span', 'advanced-title', 'Teaching notes for this example'));
    summary.appendChild(el('span', 'advanced-sub', sample.blurb));
    details.appendChild(summary);

    var box = el('div', 'advanced-body');
    box.appendChild(el('p', null,
      'The warning signs this example was written to contain. Compare them with the findings above, '
      + 'and notice which ones your reading of the message spotted.'));

    var ul = el('ul', 'evidence');
    for (var i = 0; i < sample.steps.length; i++) {
      ul.appendChild(el('li', null, sample.steps[i]));
    }
    box.appendChild(ul);

    details.appendChild(box);
    section.appendChild(details);
    return section;
  }

  /* ------------------------------ verdict ------------------------------ */

  function renderVerdict(result) {
    var card = el('div', 'verdict-card');
    card.setAttribute('data-band', result.band.key);

    var wrap = el('div', 'score-ring-wrap');
    wrap.setAttribute('role', 'img');
    wrap.setAttribute('aria-label', 'Risk score ' + result.score + ' out of 100. Band: ' + result.band.label);

    /* Constant, developer-written markup -- no email content is placed here. */
    wrap.innerHTML =
      '<svg class="score-ring" viewBox="0 0 138 138" aria-hidden="true">' +
      '<circle class="ring-track" cx="69" cy="69" r="57"></circle>' +
      '<circle class="ring-value" cx="69" cy="69" r="57" fill="none"></circle>' +
      '</svg>';

    var numberBox = el('div', 'score-number');
    numberBox.appendChild(el('strong', null, result.score));
    numberBox.appendChild(el('small', null, 'out of 100'));
    wrap.appendChild(numberBox);

    var circumference = 2 * Math.PI * 57;
    var ring = wrap.querySelector('.ring-value');
    ring.setAttribute('stroke-dasharray', circumference.toFixed(2));
    ring.setAttribute('stroke-dashoffset', (circumference * (1 - result.score / 100)).toFixed(2));

    var textBox = el('div', 'verdict-text');
    var badge = el('span', 'band-badge', result.band.label);
    badge.setAttribute('data-band', result.band.key);
    textBox.appendChild(badge);
    textBox.appendChild(el('p', null, result.verdict));

    var metrics = el('div', 'metrics');
    metrics.appendChild(metric('warning signs found:', result.findings.length));
    metrics.appendChild(metric('checks run:', result.checksRun + ' of ' + result.checksTotal));
    metrics.appendChild(metric('links inspected:', result.links.length));
    metrics.appendChild(metric('attachment names seen:', result.attachments.length));
    metrics.appendChild(metric('points before the 100 cap:', result.rawTotal));
    textBox.appendChild(metrics);

    card.appendChild(wrap);
    card.appendChild(textBox);
    return card;
  }

  /* ------------------------------ findings ----------------------------- */

  function renderFindings(result) {
    var section = el('section', 'result-section');
    var heading = el('h3');
    heading.appendChild(document.createTextNode('Every warning sign that scored'));
    heading.appendChild(el('span', 'count', result.findings.length));
    section.appendChild(heading);

    if (!result.findings.length) {
      section.appendChild(el('p', null,
        'None of the checks matched. That means this text does not contain the patterns the analyser '
        + 'knows about -- it does not prove the message is genuine.'));
      return section;
    }

    section.appendChild(el('p', null,
      'Sorted from the strongest indicator down. The points column is exactly what was added to the score.'));

    var list = el('div', 'findings');

    for (var i = 0; i < result.findings.length; i++) {
      var f = result.findings[i];
      var card = el('div', 'finding');
      card.setAttribute('data-severity', f.severity.key);

      var head = el('div', 'finding-head');
      head.appendChild(el('span', 'finding-title', f.title));
      head.appendChild(el('span', 'points-pill', '+' + f.points));
      card.appendChild(head);

      card.appendChild(el('div', 'finding-meta', f.severity.label + ' \u00b7 ' + f.category));
      card.appendChild(el('p', 'finding-why', f.why));

      var ul = el('ul', 'evidence');
      for (var e = 0; e < f.evidence.length; e++) {
        ul.appendChild(el('li', null, f.evidence[e]));
      }
      card.appendChild(ul);

      list.appendChild(card);
    }

    section.appendChild(list);
    return section;
  }

  /* ---------------------------- not checked ---------------------------- */

  function renderNotChecked(result) {
    var section = el('section', 'result-section');
    var heading = el('h3');
    heading.appendChild(document.createTextNode('Checks that could not run'));
    heading.appendChild(el('span', 'count', result.notChecked.length));
    section.appendChild(heading);

    var reason = 'These checks need the raw email headers. Paste them into the "Advanced" box to run them. '
      + 'They are listed here as not checked -- never as passed.';
    if (result.headerReason === 'unrecognised') {
      reason = 'The text in the Advanced box did not look like an email header block, so these checks were '
        + 'skipped. Copy everything above the first blank line from "Show original".';
    }
    section.appendChild(el('p', null, reason));

    var list = el('div', 'not-checked-list');
    for (var i = 0; i < result.notChecked.length; i++) {
      var item = result.notChecked[i];
      list.appendChild(el('span', 'not-checked-item', item.title + ' (worth ' + item.points + ')'));
    }
    section.appendChild(list);
    return section;
  }

  /* ---------------------------- the maths ------------------------------ */

  function renderBreakdown(result) {
    var section = el('section', 'result-section');
    section.appendChild(el('h3', null, 'How the score was reached'));

    var scroll = el('div', 'table-scroll');
    var table = el('table', 'data-table');

    table.appendChild(el('caption', null,
      'Every rule has a fixed weight. The weights of the rules that fired were added together'
      + (result.capped ? ', then capped at 100.' : '.')));

    var thead = el('thead');
    var headRow = el('tr');
    headRow.appendChild(el('th', null, 'Indicator'));
    headRow.appendChild(el('th', null, 'Type'));
    headRow.appendChild(el('th', null, 'Points'));
    thead.appendChild(headRow);
    table.appendChild(thead);

    var tbody = el('tbody');

    if (!result.findings.length) {
      var emptyRow = el('tr');
      emptyRow.setAttribute('data-info', 'true');
      var cell = el('td', null, 'Nothing matched the checks that ran');
      cell.colSpan = 3;
      emptyRow.appendChild(cell);
      tbody.appendChild(emptyRow);
    }

    for (var i = 0; i < result.findings.length; i++) {
      var f = result.findings[i];
      var row = el('tr');
      var nameCell = el('td');
      nameCell.appendChild(document.createTextNode(f.title));
      nameCell.appendChild(el('div', 'cat', f.category));
      row.appendChild(nameCell);
      row.appendChild(el('td', null, f.severity.label));
      row.appendChild(el('td', 'num', '+' + f.points));
      tbody.appendChild(row);
    }

    var totalRow = el('tr');
    var totalLabel = el('td');
    totalLabel.appendChild(el('strong', null, result.capped ? 'Total (capped)' : 'Total'));
    totalRow.appendChild(totalLabel);
    totalRow.appendChild(el('td', null, result.rawTotal + ' points of evidence'));
    totalRow.appendChild(el('td', 'num', String(result.score)));
    tbody.appendChild(totalRow);

    table.appendChild(tbody);
    scroll.appendChild(table);
    section.appendChild(scroll);
    return section;
  }

  /* ---------------------------- header facts --------------------------- */

  function renderHeaderFacts(result) {
    var section = el('section', 'result-section');
    section.appendChild(el('h3', null, 'What the email headers said'));
    section.appendChild(el('p', null,
      'These values are taken from the headers you pasted. Passing authentication only means the sending '
      + 'domain is set up correctly -- it does not prove the sender is honest.'));

    var scroll = el('div', 'table-scroll');
    var table = el('table', 'data-table');

    var thead = el('thead');
    var headRow = el('tr');
    headRow.appendChild(el('th', null, 'Header'));
    headRow.appendChild(el('th', null, 'Value'));
    thead.appendChild(headRow);
    table.appendChild(thead);

    var tbody = el('tbody');
    for (var i = 0; i < result.headerFacts.length; i++) {
      var fact = result.headerFacts[i];
      var row = el('tr');
      row.appendChild(el('td', null, fact.label));
      row.appendChild(el('td', null, fact.value));
      tbody.appendChild(row);
    }
    table.appendChild(tbody);
    scroll.appendChild(table);
    section.appendChild(scroll);
    return section;
  }

  /* ------------------------------- notes ------------------------------- */

  function renderNotes(result) {
    var section = el('section', 'result-section');
    section.appendChild(el('h3', null, 'Limits of this result'));
    var list = el('div', 'notes');
    for (var i = 0; i < result.notes.length; i++) {
      list.appendChild(el('div', 'note', result.notes[i]));
    }
    section.appendChild(list);
    return section;
  }

  /* -------------------------- what to do next -------------------------- */

  function renderRecommendations(result) {
    var section = el('section', 'result-section');
    var heading = el('h3');
    heading.appendChild(document.createTextNode('What to do next'));
    heading.appendChild(el('span', 'count', result.recommendations.length));
    section.appendChild(heading);

    var list = el('div', 'recs');
    for (var i = 0; i < result.recommendations.length; i++) {
      var rec = result.recommendations[i];
      var card = el('div', 'rec');
      card.setAttribute('data-level', rec.level);

      var head = el('div', 'rec-head');
      var tagText = 'Good to know';
      if (rec.level === 'now') { tagText = 'Do now'; }
      else if (rec.level === 'verify') { tagText = 'Verify'; }
      head.appendChild(el('span', 'rec-tag', tagText));
      head.appendChild(el('span', 'rec-title', rec.title));
      card.appendChild(head);

      card.appendChild(el('p', null, rec.text));
      list.appendChild(card);
    }
    section.appendChild(list);
    return section;
  }

  function renderReminder() {
    var section = el('section', 'result-section');
    var list = el('div', 'notes');
    list.appendChild(el('div', 'note',
      'Reminder: this is an educational triage tool. It highlights warning signs and it cannot prove that an '
      + 'email is malicious or that it is safe. Do not click links or open attachments to test them, and '
      + 'verify anything important using the organisation\'s official app, website or a phone number you '
      + 'already trust.'));
    section.appendChild(list);
    return section;
  }

  /* --------------------------- rule catalogue -------------------------- */

  function renderRuleCatalogue() {
    var rows = PA.ruleCatalogue();

    var table = el('table', 'data-table');
    table.appendChild(el('caption', null,
      'All ' + rows.length + ' checks, with their fixed weights. Header checks only run when raw headers '
      + 'are pasted.'));

    var thead = el('thead');
    var headRow = el('tr');
    headRow.appendChild(el('th', null, 'Check'));
    headRow.appendChild(el('th', null, 'Group'));
    headRow.appendChild(el('th', null, 'Reads'));
    headRow.appendChild(el('th', null, 'Points'));
    thead.appendChild(headRow);
    table.appendChild(thead);

    var tbody = el('tbody');
    for (var i = 0; i < rows.length; i++) {
      var row = el('tr');
      row.appendChild(el('td', null, rows[i].title));
      row.appendChild(el('td', null, rows[i].category));
      row.appendChild(el('td', null, rows[i].needs === 'headers' ? 'headers' : 'email text'));
      row.appendChild(el('td', 'num', '+' + rows[i].points));
      tbody.appendChild(row);
    }
    table.appendChild(tbody);

    clear(ruleCatalogue);
    ruleCatalogue.appendChild(table);
  }

  /* ============================== wiring ================================ */

  bodyInput.addEventListener('input', function () {
    updateCounts();
    formMessage.textContent = '';
    /* The text no longer matches the example that was loaded, so drop the
       teaching notes rather than showing notes about the wrong message. */
    if (selectedSample) {
      selectedSample = null;
      var chips = sampleButtons.querySelectorAll('button');
      for (var i = 0; i < chips.length; i++) {
        chips[i].setAttribute('aria-pressed', 'false');
      }
    }
  });
  headersInput.addEventListener('input', function () { formMessage.textContent = ''; });

  analyseBtn.addEventListener('click', runAnalysis);

  clearBtn.addEventListener('click', function () {
    bodyInput.value = '';
    headersInput.value = '';
    formMessage.textContent = '';
    selectedSample = null;
    resultBody.hidden = true;
    emptyState.hidden = false;
    rulesCount.textContent = '';
    clear(resultBody);
    var buttons = sampleButtons.querySelectorAll('button');
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].setAttribute('aria-pressed', 'false');
    }
    updateCounts();
    bodyInput.focus();
  });

  /* Ctrl+Enter (or Cmd+Enter) analyses from the keyboard. */
  function handleShortcut(event) {
    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
      event.preventDefault();
      runAnalysis();
    }
  }
  bodyInput.addEventListener('keydown', handleShortcut);
  headersInput.addEventListener('keydown', handleShortcut);

  buildSampleButtons();
  renderRuleCatalogue();
  updateCounts();
})();
