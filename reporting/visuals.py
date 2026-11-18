from html import escape
import json

VISUAL_STYLES = '''
.decision-explanation {border:1px solid #cdd7e4;border-radius:8px;padding:14px;margin:12px 0;background:#f8fafc;overflow-wrap:anywhere}
.decision-summary {line-height:1.65;margin-top:0}
.decision-tree,.decision-tree ul {list-style:none;padding-left:18px}
.decision-tree {padding-left:0}
.decision-tree li {margin:8px 0}
.decision-tree ul {border-left:2px solid #94a3b8;margin-left:8px}
.decision-tree li>span {display:inline-block;background:white;border:1px solid #dbe3ec;border-radius:5px;padding:7px 10px;max-width:100%;box-sizing:border-box}
.decision-chain>summary,.recorded-evaluation>summary {cursor:pointer;font-weight:600}
@media(max-width:650px) {.decision-tree ul {padding-left:9px;margin-left:3px}.decision-explanation {padding:9px}}
:root {--muted:#566477;--line:#cdd7e4}
h2 {color:#173b63;border-bottom:2px solid #dbe7f4;padding-bottom:10px}
h3,h4,h5,caption {color:#214e78} caption {font-weight:700;text-align:left;padding:10px 0}
#passport .value,#passport td {color:var(--muted)}
.badge {display:inline-block;border:1px solid;padding:2px 9px;border-radius:6px;font:600 13px/1.5 system-ui;white-space:normal}
.tone-neutral {color:#4b5563;background:#f1f3f5;border-color:#c1c9d2}
.tone-match {color:#075985;background:#e0f2fe;border-color:#7db5d3}
.tone-unmatch,.tone-warning {color:#854d0e;background:#fff7df;border-color:#d4af56}
.tone-good {color:#166534;background:#ecfdf3;border-color:#86bc99}
.tone-error {color:#991b1b;background:#fff0f0;border-color:#dba0a0}
.visual-metrics {display:flex;flex-wrap:wrap;gap:12px;margin:16px 0}
.visual-metric {flex:1 1 150px;border:1px solid var(--line);border-radius:8px;padding:14px;background:#f8fafc}
.visual-metric strong {display:block;font-size:26px;color:#173b63}
.trace {border:1px solid var(--line);border-radius:8px;padding:14px;margin:16px 0;background:#fafcff}
.trace-row {display:grid;grid-template-columns:minmax(0,1fr) auto minmax(0,1fr) auto minmax(0,1fr);gap:10px;align-items:center;margin:10px 0}
.trace-node {border:1px solid var(--line);border-radius:6px;padding:10px;background:white;min-width:0;overflow-wrap:anywhere}
.trace-node small {display:block;color:var(--muted);font-weight:600;margin-bottom:6px}
.trace-arrow {color:#587798;font-size:22px}.trace code {white-space:pre-wrap;overflow-wrap:anywhere}
.trace-note {color:var(--muted);font-size:14px}
.compare-table {width:100%;border-collapse:collapse;table-layout:fixed}
.compare-table th,.compare-table td {padding:10px;vertical-align:top;overflow-wrap:anywhere}
.compare-table pre {white-space:pre-wrap;overflow-wrap:anywhere;margin:0}
.compare-table tr.changed {background:#fff9eb}.compare-table th {color:#214e78}
@media(max-width:650px) {.trace-row {grid-template-columns:minmax(0,1fr)}.trace-arrow {transform:rotate(90deg);justify-self:center}.compare-table {table-layout:auto}}
@media print {.badge {border:1px solid currentColor}.trace {break-inside:avoid}.back-to-top {display:none}}
'''
TONES = {
    'Match': 'match',
    'Unmatch': 'unmatch',
    'Skipped': 'neutral',
    'met': 'good',
    'not_met': 'error',
    'improved': 'good',
    'regressed': 'error',
    'unchanged_met': 'good',
    'unchanged_not_met': 'error',
    'insufficient_data': 'warning',
    'sufficient': 'good',
    'not_assessed': 'neutral',
    'error': 'error',
    'failed': 'error',
    'completed': 'neutral',
}

def badge(value):
    label = str(value) if value is not None else 'Not assessed'

    return f"""<span class="badge tone-{TONES.get(label, 'neutral')}">{escape(label)}</span>"""

def decision(value):
    return badge('Match' if value is True else 'Unmatch' if value is False else 'Skipped')

def literal(value):
    return '<code>' + escape(json.dumps(value, ensure_ascii=False, default=str)) + '</code>'

def metrics(counts):
    if not isinstance(counts, dict):
        return ''

    return '<div class="visual-metrics">' + ''.join(
        ('<div class="visual-metric">' + badge(key) + '<strong>' + escape(str(value)) + '</strong></div>' for key, value in counts.items() if type(value) in (int, float)),
    ) + '</div>'

def legend():
    return '<p class="trace-note">' + ' '.join(
        (badge(s) for s in ('Match', 'Unmatch', 'Skipped', 'met', 'not_met', 'insufficient_data', 'error')),
    ) + '<br>Match / Unmatch describe rule decisions. met / not_met describe test expectations. Insufficient data is not a test failure. Arrows show evaluation dependencies, not causality.</p>'

def evaluation_trace(evaluation):
    checks = evaluation.get('Checks')

    if not isinstance(checks, dict) or not checks:
        return '<p class="trace-note">No field evaluation trace was recorded.</p>'

    parts = [
        '<div class="trace"><h4>Evaluation relationships</h4>',
        '<p class="trace-note">Field checks feed named blocks; the condition combines those blocks. Negation and alternative branches can change how a block affects the final decision.</p>',
    ]

    for block, fields in checks.items():
        if not isinstance(fields, dict):
            continue

        parts.append(
            '<details><summary>Block: ' + escape(str(block)) + ' — ' + decision(evaluation.get('Block Results', {}).get(block)) + '</summary>',
        )

        for name, check in fields.items():
            if not isinstance(check, dict):
                continue

            parts.append(
                '<div class="trace-row"><div class="trace-node"><small>Event field</small>' + escape(str(check.get('Field', name))) + '<br>' + literal(check.get('Actual')) + '</div><span class="trace-arrow" aria-hidden="true">→</span>' + '<div class="trace-node"><small>Rule check</small>' + escape(str(name)) + '<br>Expected: ' + literal(check.get('Expected')) + '</div><span class="trace-arrow" aria-hidden="true">→</span>' + '<div class="trace-node"><small>Check result</small>' + decision(check.get('Matched')) + '<br>' + escape(str(check.get('Reason', 'No reason recorded.'))) + '</div></div>',
            )

        parts.append('</details>')

    parts.append(
        '<div class="trace-row"><div class="trace-node"><small>Block results</small>' + '<br>'.join(
            (escape(str(k)) + ': ' + decision(v) for k, v in evaluation.get('Block Results', {}).items()),
        ) + '</div><span class="trace-arrow" aria-hidden="true">→</span>' + '<div class="trace-node"><small>Condition (exact expression)</small>' + literal(evaluation.get('Condition')) + '</div><span class="trace-arrow" aria-hidden="true">→</span>' + '<div class="trace-node"><small>Event decision</small>' + decision(evaluation.get('Selection')) + '</div></div></div>',
    )

    return ''.join(parts)
_MISSING = object()

def differences(before, after, path=()):
    if isinstance(before, dict) and isinstance(after, dict):
        for key in sorted(before.keys() | after.keys(), key=str):
            yield from differences(before.get(key, _MISSING), after.get(key, _MISSING), path + (key,))
    elif type(before) is not type(after) or before != after:
        yield (path, before, after)

def comparison_table(before, after, title):
    rows = []

    for path, left, right in differences(before, after):
        display = lambda value: '<em>Absent</em>' if value is _MISSING else literal(value)
        rows.append(
            '<tr class="changed"><th scope="row">' + literal(list(path)) + '</th><td>' + display(left) + '</td><td>' + display(right) + '</td></tr>',
        )

    return '<div class="trace"><h4>' + escape(title) + '</h4>' + ('<div class="checks-scroll"><table class="compare-table"><thead><tr><th>Field path</th><th>Baseline</th><th>Candidate</th></tr></thead><tbody>' + ''.join(rows) + '</tbody></table></div>' if rows else '<p>No recorded values changed.</p>') + '</div>'
