from reporting.atomic_view import render_lifecycle
from reporting.explanation import explain_evaluation, render_explanation
from html import escape
from pathlib import Path
import json
from reporting.context_view import CONTEXT_STYLES, source_view, render_detection_tree
from reporting.visuals import (
    VISUAL_STYLES,
    badge,
    decision,
    metrics,
    legend,
    evaluation_trace,
)

def render_value(value, *, semantic=False):
    if value is None:
        return '<span class="missing">Not set</span>'

    if isinstance(value, bool):
        return 'Yes' if value else 'No'

    if isinstance(value, dict):
        if not value:
            return '<span class="empty">Empty object</span>'

        rows = []

        for key, nested_value in value.items():
            safe_key = escape(str(key), quote=True)
            rendered_value = badge(nested_value) if (
                semantic
                and (key in {'status', 'telemetry_status', 'Result', 'Comparison'})
                and (isinstance(nested_value, str) or nested_value is None)
            ) else render_value(nested_value, semantic=semantic)
            rows.append(f'<tr><th scope="row">{safe_key}</th><td>{rendered_value}</td></tr>')

        return '<table class="fields"><tbody>' + ''.join(rows) + '</tbody></table>'

    if isinstance(value, list):
        if not value:
            return '<span class="empty">Empty list</span>'

        items = []

        for item in value:
            items.append(f'<li>{render_value(item, semantic=semantic)}</li>')

        return '<ol class="values">' + ''.join(items) + '</ol>'

    safe_text = escape(str(value), quote=True)

    if safe_text == '':
        return '<span class="empty">Empty string</span>'

    return f'<pre class="value">{safe_text}</pre>'

def build_html_report(report):
    sections = [
        (
            'passport',
            '1. Test Overview',
            {
                'Report ID': report.get('Report ID'),
                'Session': report.get('Session'),
                'Analysis': report.get('Analysis'),
                'Telemetry Readiness': report.get('Telemetry Readiness'),
            },
        ),
        (
            'evaluation',
            '2. Evaluation Summary and Reasons',
            {
                'Events Summary': report.get('Events Summary'),
                'Session Expectation Evaluation': report.get('Expectation Evaluation'),
                'Selected Evidence Evaluation': {key: value for key, value in report['Test Case Evaluation'].items() if key != 'telemetry'} if report.get('Test Case Evaluation') is not None else None,
                'Session Conclusion': report.get('Conclusion'),
                'Rule': report.get('Rule'),
            },
        ),
        ('events', '3. Events with Context', report.get('Event Review')),
        ('details', '4. Detailed Event Cards', report.get('Event Evidence')),
        (
            'manual-test',
            '5. Manual Test Context',
            {
                'Collection Context': report.get('Manual Test Context'),
                'Test Case': report.get('Test Case'),
            },
        ),
    ]
    navigation = []
    content = []
    event_explanations = build_event_explanations(report.get('Event Review'))
    test_case = report.get('Test Case')
    selected_evidence_ids = None if test_case is None else set(test_case['evidence']['record_ids'])

    for section_id, title, data in sections:
        safe_id = escape(section_id, quote=True)
        safe_title = escape(title, quote=True)
        navigation.append(f'<li><a href="#{safe_id}">{safe_title}</a></li>')

        if section_id == 'details':
            section_body = render_event_cards(data, event_explanations, selected_evidence_ids)
        elif section_id == 'events':
            section_body = render_detection_tree(report.get('Detection Context'), event_anchor) + render_event_review(data, report.get('Event Evidence'))
        else:
            section_body = render_value(data, semantic=section_id == 'evaluation')

        if section_id == 'evaluation' and report.get('Test Case Evaluation') is not None:
            section_body = '<p>Selected evidence evaluation applies only to the selected events. Telemetry checks cover declared requirements in prepared fields; they do not prove complete collection or causal attribution.</p>' + render_telemetry_review(report['Test Case Evaluation'], report.get('Event Evidence')) + section_body

        if section_id == 'passport' and report.get('Atomic Lifecycle'):
            section_body += render_lifecycle(report['Atomic Lifecycle'])

        if section_id == 'evaluation':
            section_body = metrics(report.get('Events Summary')) + legend() + section_body

        content.append(f'<section id="{safe_id}"><h2>{safe_title}</h2>{section_body}</section>')

    navigation_html = '\n'.join(navigation)
    category_navigation = render_category_navigation(report.get('Event Review'), event_explanations)
    navigation_block = f'<nav class="report-navigation" aria-labelledby="report-navigation-title"><h2 id="report-navigation-title">Report navigation</h2><ol>{navigation_html}</ol>{category_navigation}</nav>'
    content_html = '\n'.join([content[0], navigation_block, render_event_search(), *content[1:]])

    return f'<!doctype html>\n<html lang="en">\n<head>\n    <meta charset="utf-8">\n    <meta name="viewport" content="width=device-width, initial-scale=1">\n    <title>TOTENKAHN — Report</title>\n        \n    <style>\n        body {{\n            margin: 0;\n            background: #f3f5f8;\n            color: #172033;\n            font-family: system-ui, sans-serif;\n            line-height: 1.5;\n        }}\n        main {{\n            max-width: 1200px;\n            margin: auto;\n            padding: 24px;\n        }}\n        .report-navigation {{\n            background: white;\n            border: 1px solid #dce2ea;\n            border-radius: 8px;\n            padding: 20px;\n            margin-bottom: 24px;\n        }}\n        .report-navigation ol {{\n            display: grid;\n            grid-template-columns: repeat(\n                auto-fit, minmax(min(100%, 240px), 1fr)\n            );\n            gap: 12px 24px;\n            margin: 0;\n            padding-left: 24px;\n        }}\n        .back-to-top {{\n            position: fixed;\n            right: 16px;\n            bottom: 16px;\n            z-index: 10;\n            padding: 10px 16px;\n            border-radius: 6px;\n            background: #174ea6;\n            color: white;\n            text-decoration: none;\n            box-shadow: 0 2px 8px #0003;\n        }}\n        a:focus-visible {{\n            outline: 3px solid #b45309;\n            outline-offset: 4px;\n        }}\n        body {{\n            padding-bottom: 80px;\n        }}\n        @media print {{\n            .report-navigation,\n            .back-to-top {{\n                display: none;\n            }}\n        }}\n        a {{\n            color: #174ea6;\n        }}\n        section {{\n            background: white;\n            border: 1px solid #dce2ea;\n            border-radius: 8px;\n            padding: 20px;\n            margin-bottom: 24px;\n        }}\n        h2 {{\n            margin-top: 0;\n        }}\n        .fields {{\n            width: 100%;\n            border-collapse: collapse;\n        }}\n        .fields th, .fields td {{\n            border: 1px solid #dce2ea;\n            padding: 8px;\n            text-align: left;\n            vertical-align: top;\n            overflow-wrap: anywhere;\n        }}\n        .fields th {{\n            background: #f7f9fc;\n        }}\n        .value {{\n            margin: 0;\n            white-space: pre-wrap;\n            overflow-wrap: anywhere;\n            font-family: ui-monospace, monospace;\n        }}\n        .missing, .empty {{\n            color: #596579;\n            font-style: italic;\n        }}\n        .values {{\n            padding-left: 24px;\n        }}\n        .event-card \n        {{\n            border: 1px solid #dce2ea;\n            border-radius: 6px;\n            padding: 16px;\n            margin-bottom: 20px;\n            scroll-margin-top: 16px;\n        }}\n        .event-card h3 {{\n            margin-top: 0;\n            overflow-wrap: anywhere;\n        }}\n        .event-card:target {{\n            border-color: #174ea6;\n        }}\n        .raw-xml {{\n            margin-top: 16px;\n        }}\n        .raw-xml summary {{\n            cursor: pointer;\n            font-weight: 600;\n            margin-bottom: 8px;\n        }}\n        .event-summary {{\n            margin: 12px 0;\n            padding-left: 24px;\n            overflow-wrap: anywhere;\n        }}\n        .event-details {{\n            margin-top: 12px;\n            border-top: 1px solid #dce2ea;\n            padding-top: 12px;\n        }}\n        .event-details > summary {{\n            cursor: pointer;\n            font-weight: 600;\n        }}\n        .event-details[open] > summary {{\n            margin-bottom: 12px;\n        }}\n        summary:focus-visible {{\n            outline: 3px solid #b45309;\n            outline-offset: 4px;\n        }}\n        .evaluation-group + .evaluation-group {{\n            margin-top: 24px;\n            padding-top: 16px;\n            border-top: 2px solid #dce2ea;\n        }}\n        .checks-scroll {{\n            max-width: 100%;\n            overflow-x: auto;\n            margin: 12px 0;\n        }}\n        .checks-table {{\n            min-width: 760px;\n        }}\n        .checks-table > caption {{\n            text-align: left;\n            font-weight: 600;\n            padding-bottom: 8px;\n        }}\n        .checks-table > tbody > tr > th {{\n            min-width: 140px;\n        }}\n        .checks-table > tbody > tr > td > details {{\n            margin-top: 12px;\n        }}\n        .event-details > .fields > tbody > tr > th {{\n            width: 24%;\n            min-width: 120px;\n        }}\n        .event-group + .event-group {{\n            margin-top: 24px;\n            padding-top: 20px;\n            border-top: 2px solid #dce2ea;\n        }}\n        [hidden] {{\n            display: none !important;\n        }}\n        #event-search-panel {{\n            background: white;\n            border: 1px solid #dce2ea;\n            border-radius: 8px;\n            padding: 20px;\n            margin-bottom: 24px;\n        }}\n        #event-search-panel label {{\n            display: block;\n            margin-top: 12px;\n        }}\n        #event-search-panel input,\n        #event-search-panel select {{\n            box-sizing: border-box;\n            width: 100%;\n            padding: 8px;\n            margin-top: 4px;\n        }}\n        #clear-event-filters {{\n            margin-top: 12px;\n            padding: 8px 12px;\n            cursor: pointer;\n        }}\n        @media print {{\n            #event-search-panel {{\n                display: none;\n            }}\n        }}\n    {VISUAL_STYLES}\n    {CONTEXT_STYLES}\n    </style>\n</head>\n<body>\n    <main id="report-top">\n        <h1>TOTENKAHN — Report</h1>\n        {content_html}\n    </main>\n    <a class="back-to-top" href="#report-top">Back to top</a>\n</body>\n</html>\n'

def save_report_html(report, output_path: Path):
    html_document = build_html_report(report)
    temporary_path = output_path.with_suffix(output_path.suffix + '.tmp')

    with temporary_path.open('w', encoding='utf-8') as file:
        file.write(html_document)

    temporary_path.replace(output_path)

def event_anchor(record_id):
    return 'event-' + record_id.encode('utf-8').hex()

def render_event_cards(evidence, event_explanations, selected_evidence_ids=None):
    if evidence is None:
        return '<p>Full event evidence is unavailable in this report.</p>'

    if not isinstance(evidence, dict):
        raise ValueError('Event Evidence must be an object')

    if not evidence:
        return '<p>No events were collected.</p>'

    cards = []

    for record_id, event in evidence.items():
        if not isinstance(record_id, str) or not record_id:
            raise ValueError('Event evidence ID must be a non-empty string')

        if not isinstance(event, dict):
            raise ValueError('Event evidence must be an object')

        if event.get('record_id') != record_id:
            raise ValueError('Event evidence key does not match record_id')

        anchor = event_anchor(record_id)
        safe_record_id = escape(record_id, quote=True)

        if selected_evidence_ids is None:
            evidence_label = ''
        elif record_id in selected_evidence_ids:
            evidence_label = '<p class="evidence-membership"><strong>Selected test evidence</strong></p>'
        else:
            evidence_label = '<p class="evidence-membership">Outside selected evidence</p>'

        explanations = event_explanations.get(record_id, [])
        categories = list(dict.fromkeys((explanation['Result'] for explanation in explanations)))
        search_text = json.dumps({'Event': event, 'Evaluations': explanations}, ensure_ascii=False)
        categories_json = json.dumps(categories, ensure_ascii=False)
        safe_search_text = escape(search_text, quote=True)
        safe_categories = escape(categories_json, quote=True)
        evaluation_html = render_event_evaluation(explanations)
        fields = {key: value for key, value in event.items() if key != 'raw_xml'}
        raw_xml = event.get('raw_xml')

        if raw_xml is None:
            xml_block = '<p>Raw XML is unavailable.</p>'
        else:
            xml_block = f'<details class="raw-xml"><summary>Raw XML</summary>{render_value(raw_xml)}</details>'

        cards.append(
            f'<article class="event-card" id="{anchor}" data-search="{safe_search_text}" data-results="{safe_categories}"><h3>Event {safe_record_id}</h3>{evidence_label}{source_view(event)}<section class="event-evaluation"><h4>Rule evaluation</h4>{evaluation_html}</section><details class="event-details"><summary>Event fields</summary>{render_event_fields(fields)}</details>{xml_block}</article>',
        )

    return '\n'.join(cards)

def render_event_reference(reference, evidence):
    if not isinstance(reference, dict):
        raise ValueError('Event reference must be an object')

    record_id = reference.get('Log Record ID')
    reference_fields = render_value(reference)

    if (
        (not isinstance(record_id, str))
        or (not record_id)
        or (not isinstance(evidence, dict))
        or (record_id not in evidence)
    ):
        return reference_fields + '<p class="missing">Full event evidence is unavailable.</p>'

    anchor = event_anchor(record_id)

    return reference_fields + f'<p><a href="#{anchor}">View full event</a></p>'

def render_event_review(review, evidence):
    if review is None:
        return '<p>Event review is unavailable.</p>'

    if not isinstance(review, dict):
        raise ValueError('Event Review must be an object')

    if not review:
        return '<p>No event results are available.</p>'

    categories = []

    for category, groups in review.items():
        if not isinstance(groups, list):
            raise ValueError('Event review groups must be a list')

        safe_category = escape(str(category), quote=True)
        group_blocks = []

        for group in groups:
            if not isinstance(group, dict):
                raise ValueError('Event review group must be an object')

            references = group.get('References', [])

            if not isinstance(references, list):
                raise ValueError('Group References must be a list')

            group_fields = {key: value for key, value in group.items() if key not in ('References', 'Evidence')}
            group_explanations = [
                {
                    'Result': category,
                    'Group Reference': group.get('Group Reference'),
                    'Evaluation': group.get('Evidence'),
                },
            ]
            reference_items = [f'<li>{render_event_reference(reference, evidence)}</li>' for reference in references]
            references_html = '<ol class="values">' + ''.join(reference_items) + '</ol>' if reference_items else '<p>No event references are available.</p>'
            group_blocks.append(
                f'<div class="event-group">{render_value(group_fields)}{render_event_summary(group_explanations)}<details class="event-details"><summary>Rule evaluation</summary>{render_event_evaluation(group_explanations)}</details><details class="event-details"><summary>Event references</summary>{references_html}</details></div>',
            )

        groups_html = '\n'.join(group_blocks) if group_blocks else '<p>No event groups in this category.</p>'
        anchor = category_anchor(category)
        categories.append(f'<h3 id="{anchor}">{safe_category}</h3>{groups_html}')

    return '\n'.join(categories)

def build_event_explanations(review):
    explanations = {}

    if review is None:
        return explanations

    if not isinstance(review, dict):
        raise ValueError('Event Review must be an object')

    for category, groups in review.items():
        if not isinstance(groups, list):
            raise ValueError('Event review groups must be a list')

        for group in groups:
            if not isinstance(group, dict):
                raise ValueError('Event review group must be an object')

            references = group.get('References', [])

            if not isinstance(references, list):
                raise ValueError('Group References must be a list')

            explanation = {
                'Result': category,
                'Group Reference': group.get('Group Reference'),
                'Evaluation': group.get('Evidence'),
            }
            seen_ids = set()

            for reference in references:
                if not isinstance(reference, dict):
                    raise ValueError('Event reference must be an object')

                record_id = reference.get('Log Record ID')

                if not isinstance(record_id, str) or not record_id:
                    continue

                if record_id in seen_ids:
                    continue

                seen_ids.add(record_id)
                explanations.setdefault(record_id, []).append(explanation)

    return explanations

def category_anchor(category):
    return 'category-' + category.encode('utf-8').hex()

def render_category_navigation(review, event_explanations):
    if not review:
        return ''

    links = []

    for category in review:
        if not isinstance(category, str):
            raise ValueError('Event review category must be a string')

        event_count = sum(
            (1 for explanations in event_explanations.values() if any((explanation['Result'] == category for explanation in explanations))),
        )
        anchor = category_anchor(category)
        safe_category = escape(category, quote=True)
        links.append(
            f'<li><a href="#{anchor}">{safe_category} — {event_count} unique events</a></li>',
        )

    return '<h3>Results by category</h3><p>Counts use unique event IDs within each category.</p><ul>' + ''.join(links) + '</ul>'

def render_event_summary(explanations):
    if not explanations:
        return '<p>No rule evaluation is recorded for this event.</p>'

    items = []
    seen = set()

    for explanation in explanations:
        result = str(explanation.get('Result', 'Unknown'))
        evaluation = explanation.get('Evaluation')
        reason = explain_evaluation(evaluation)['summary'] if isinstance(evaluation, dict) else None

        if not isinstance(reason, str) or not reason.strip():
            reason = 'No explanation was recorded.'

        summary_key = (result, reason)

        if summary_key in seen:
            continue

        seen.add(summary_key)
        items.append(f'<li>{badge(result)}: {escape(reason, quote=True)}</li>')

    return '<ul class="event-summary">' + ''.join(items) + '</ul>'

def render_field_checks(checks):
    if checks is None:
        return '<p>Field checks are unavailable.</p>'

    if not isinstance(checks, dict):
        raise ValueError('Field checks must be an object')

    if not checks:
        return '<p>No field checks were recorded.</p>'

    blocks = []

    for block_name, block_checks in checks.items():
        if not isinstance(block_checks, dict):
            raise ValueError('Block checks must be an object')

        rows = []

        for check_name, check in block_checks.items():
            if not isinstance(check, dict):
                raise ValueError('Field check must be an object')

            safe_name = escape(str(check_name), quote=True)
            displayed_keys = {'Actual', 'Expected', 'Matched', 'Reason'}
            extra = {key: value for key, value in check.items() if key not in displayed_keys}
            extra_html = f'<details><summary>Details</summary>{render_value(extra)}</details>' if extra else ''
            rows.append(
                f"""<tr><th scope="row">{safe_name}</th><td>{render_value(check.get('Actual'))}</td><td>{render_value(check.get('Expected'))}</td><td>{decision(check.get('Matched'))}</td><td>{render_value(check.get('Reason'))}{extra_html}</td></tr>""",
            )

        safe_block = escape(str(block_name), quote=True)

        if rows:
            block_html = f'<div class="checks-scroll"><table class="fields checks-table"><caption>Block: {safe_block}</caption><thead><tr><th scope="col">Field check</th><th scope="col">Actual</th><th scope="col">Expected</th><th scope="col">Result</th><th scope="col">Reason</th></tr></thead><tbody>' + ''.join(rows) + '</tbody></table></div>'
        else:
            block_html = f'<p>Block: {safe_block}. No field checks were recorded.</p>'

        blocks.append(block_html)

    return '\n'.join(blocks)

def render_event_evaluation(explanations):
    blocks = []

    for explanation in explanations:
        evaluation = explanation.get('Evaluation')
        metadata = {key: value for key, value in explanation.items() if key != 'Evaluation'}

        if isinstance(evaluation, dict):
            context = {key: value for key, value in evaluation.items() if key != 'Checks'}
            evaluation_html = f"""{render_explanation(evaluation)}<details class="recorded-evaluation"><summary>Recorded evaluation details</summary>{evaluation_trace(evaluation)}{render_value(context, semantic=True)}<h5>Field checks</h5>{render_field_checks(evaluation.get('Checks'))}</details>"""
        else:
            evaluation_html = render_value(evaluation)

        blocks.append(
            f'<div class="evaluation-group">{render_value(metadata)}{evaluation_html}</div>',
        )

    if not blocks:
        return '<p>No rule evaluation is recorded for this event.</p>'

    return '\n'.join(blocks)

def render_event_fields(fields):
    scalar_fields = {key: value for key, value in fields.items() if not isinstance(value, (dict, list))}
    blocks = []

    if scalar_fields:
        blocks.append(render_value(scalar_fields))

    for key, value in fields.items():
        if not isinstance(value, (dict, list)):
            continue

        safe_key = escape(str(key), quote=True)
        blocks.append(
            f'<details class="event-details"><summary>{safe_key}</summary>{render_value(value)}</details>',
        )

    if not blocks:
        return '<p>No event fields are available.</p>'

    return '\n'.join(blocks)

def render_event_search():
    return '''
<div id="event-search-panel" hidden>
    <h3>Search events</h3>
    <p>Filters apply to detailed event cards only.
       Analysis totals remain unchanged.</p>

    <label for="event-query">Search event data and explanations</label>
    <input id="event-query" type="search">

    <label for="event-category">Result</label>
    <select id="event-category">
        <option value="">All results</option>
    </select>

    <button id="clear-event-filters" type="button">Clear filters</button>
    <p id="event-search-count" role="status"></p>
    <a href="#details">View filtered event cards</a>
</div>

<script>
document.addEventListener("DOMContentLoaded", () => {

    const panel = document.getElementById("event-search-panel");
    const query = document.getElementById("event-query");
    const category = document.getElementById("event-category");
    const counter = document.getElementById("event-search-count");
    const clear = document.getElementById("clear-event-filters");

    const entries = Array.from(
        document.querySelectorAll(".event-card")
    ).map(card => ({
        card,
        text: card.dataset.search.toLowerCase(),
        results: JSON.parse(card.dataset.results)
    }));

    if (!entries.length) return;

    const categories = new Set(
        entries.flatMap(entry => entry.results)
    );

    for (const result of categories) {
        const option = document.createElement("option");

        option.value = JSON.stringify(result);
        option.textContent = result;
        category.append(option);
    }

    function applyFilters() {

        const term = query.value.trim().toLowerCase();
        const selected = category.value === ""
            ? null
            : JSON.parse(category.value);

        let visible = 0;

        for (const entry of entries) {
            const matchesText = entry.text.includes(term);
            const matchesCategory = selected === null
                || entry.results.includes(selected);

            entry.card.hidden = !(matchesText && matchesCategory);
            if (!entry.card.hidden) visible++;
        }

        counter.textContent =
            `Showing ${visible} of ${entries.length} events`;
    }

    function clearFilters() {
        query.value = "";
        category.value = "";
        applyFilters();
    }

    function revealLinkedCard() {

        const target = document.getElementById(
            window.location.hash.slice(1)
        );

        if (!target || !target.classList.contains("event-card")) return;

        clearFilters();

        for (const child of target.children) {
            if (child.matches("details.event-details")) {
                child.open = true;
            }
        }

        target.scrollIntoView({block: "start"});
    }

    query.addEventListener("input", applyFilters);
    category.addEventListener("change", applyFilters);
    clear.addEventListener("click", clearFilters);
    window.addEventListener("hashchange", revealLinkedCard);

    document.addEventListener("click", event => {
        const link = event.target.closest("a[href]");
        if (link && link.getAttribute("href") === window.location.hash) {
            revealLinkedCard();
        }
    });

    panel.hidden = false;
    applyFilters();
    revealLinkedCard();
});
</script>
'''

def render_telemetry_review(evaluation, evidence):
    telemetry = evaluation.get('telemetry')

    if telemetry is None:
        return '<p>Telemetry sufficiency has not been assessed.</p>'

    blocks = [
        '<h3>Telemetry requirements</h3>',
        render_value({key: value for key, value in telemetry.items() if key != 'requirements'}),
    ]

    for requirement in telemetry.get('requirements', []):
        blocks.append('<details class="event-details">')
        blocks.append(
            '<summary>' + escape(str(requirement['id']), quote=True) + ' — ' + badge(requirement['status']) + '</summary>',
        )
        blocks.append(
            render_value(
                {key: value for key, value in requirement.items() if key not in {'matched_record_ids', 'field_issues', 'rejected_events'}},
            ),
        )
        blocks.append('<h4>Matching evidence</h4>')

        for record_id in requirement.get('matched_record_ids', []):
            blocks.append(render_event_reference({'Log Record ID': record_id}, evidence))

        if not requirement.get('matched_record_ids'):
            blocks.append('<p>No selected events matched this requirement.</p>')

        if requirement.get('rejected_events'):
            blocks.append('<h4>Events excluded by selector</h4>')
            blocks.append(
                '<p>These selected events did not satisfy the selector. Required-field checks were not run on them.</p>',
            )

            for rejection in requirement['rejected_events']:
                blocks.append('<details class="event-details">')
                blocks.append(
                    '<summary>Event ' + escape(str(rejection['record_id']), quote=True) + '</summary>',
                )
                blocks.append(
                    render_event_reference({'Log Record ID': rejection['record_id']}, evidence),
                )

                for check in rejection['checks']:
                    blocks.append(
                        render_value(
                            {
                                'Field path': check['path'],
                                'Field present': check['field_present'],
                                'Expected': check['expected'],
                                'Expected type': check['expected_type'],
                                'Actual': check['actual'],
                                'Actual type': check['actual_type'],
                                'Reason': check['reason'],
                            },
                        ),
                    )

                blocks.append('</details>')

        if requirement.get('field_issues'):
            blocks.append('<h4>Field issues</h4>')

            for issue in requirement['field_issues']:
                blocks.append(render_value({'Field path': issue['path'], 'Reason': issue['reason']}))
                blocks.append(render_event_reference({'Log Record ID': issue['record_id']}, evidence))

        blocks.append('</details>')

    return ''.join(blocks)
