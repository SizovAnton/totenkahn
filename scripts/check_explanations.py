import copy
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from html.parser import HTMLParser
from rich.console import Console

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from handlers.matching import report_handler
from reporting.explanation import (
    explain_evaluation,
    render_explanation,
    terminal_explanation,
    regression_terminal_explanations,
)
from reporting.html_report import build_html_report, render_event_evaluation
from reporting.report import build_rule_report
from reporting.regression import run_regression, build_regression_html
from displaying.reviw import build_event_review_view
from displaying.console import configure_standard_streams, create_console

ROOT = Path(__file__).resolve().parents[1]


def fixture(condition="selection", fields=None, blocks=None, source="windows"):
    rule = {
        "title": "Synthetic explanation demo",
        "id": "explanation-demo",
        "logsource": {"product": "windows"},
        "detection": blocks or {"selection": {"CommandLine|contains": "--example-flag"}},
    }
    rule["detection"] = {**rule["detection"], "condition": condition}
    event = {
        "record_id": "event-42",
        "event_id": "1",
        "computer": "demo-host",
        "channel": "Synthetic",
        "provider": "Synthetic",
        "system_time": "2026-11-15T10:00:00Z",
        "source": {"product": source},
        "data_fields": {"CommandLine": "example.exe --help"} if fields is None else fields,
    }
    result = report_handler([event], rule)[0]

    return (rule, event, result)


def terminal(value):
    out = io.StringIO()
    Console(file=out, width=160, color_system=None).print(value)

    return out.getvalue()


class ExplanationTests(unittest.TestCase):

    def model(self, **kwargs):
        return explain_evaluation(fixture(**kwargs)[2])

    def test_contains_negative(self):
        model = self.model()
        self.assertTrue(model["complete"])

        for text in (
            "CommandLine is present",
            "contains",
            "--example-flag",
            "Block selection: False",
            "Event decision: Unmatch",
        ):
            self.assertIn(text, model["summary"])

    def test_contains_positive_case_insensitive(self):
        model = self.model(fields={"CommandLine": "example.EXE --EXAMPLE-FLAG"})
        self.assertIn("Event decision: Match", model["summary"])

    def test_missing_null_empty_are_distinct(self):
        for fields, message in [
            ({}, "is absent"),
            ({"CommandLine": None}, "null value"),
            ({"CommandLine": ""}, "empty string"),
        ]:
            with self.subTest(fields=fields):
                self.assertIn(message, self.model(fields=fields)["summary"])

    def test_exists_false_can_match_absent_field(self):
        model = self.model(fields={}, blocks={"selection": {"CommandLine|exists": False}})
        self.assertIn("is absent", model["summary"])
        self.assertIn("Check exists against false: True", model["summary"])
        self.assertIn("Event decision: Match", model["summary"])

    def test_any_list(self):
        model = self.model(blocks={"selection": {"CommandLine|contains": ["--missing", "--help"]}})
        self.assertIn("any expected value sufficient", model["summary"])
        self.assertIn("Event decision: Match", model["summary"])

    def test_all_list(self):
        model = self.model(
            blocks={"selection": {"CommandLine|contains|all": ["example", "--missing"]}}
        )
        self.assertIn("all expected values required", model["summary"])
        self.assertIn("Event decision: Unmatch", model["summary"])

    def test_or_false_branch_does_not_imply_unmatch(self):
        model = self.model(
            condition="selection or alternative",
            blocks={
                "selection": {"CommandLine|contains": "--missing"},
                "alternative": {"CommandLine|contains": "--help"},
            },
        )
        self.assertIn("OR(False, True): True", model["summary"])
        self.assertIn("Event decision: Match", model["summary"])
        self.assertTrue(model["complete"])

    def test_and_and_not(self):
        model = self.model(
            condition="selection and not filter",
            blocks={
                "selection": {"CommandLine|contains": "--help"},
                "filter": {"CommandLine|contains": "--missing"},
            },
        )
        self.assertTrue(model["complete"])
        text = terminal(terminal_explanation(fixture(condition="not selection")[2]))
        self.assertIn("NOT: False → True", text)
        self.assertIn("Event decision: Match", text)

    def test_both_fields_required_in_block(self):
        model = self.model(
            blocks={"selection": {"CommandLine|contains": "--help", "Image|endswith": "other.exe"}},
            fields={"CommandLine": "example.exe --help", "Image": "example.exe"},
        )
        self.assertIn("Block selection: False", model["summary"])
        self.assertIn("Event decision: Unmatch", model["summary"])

    def test_logsource_skipped_not_negative(self):
        model = self.model(source="linux")
        self.assertIn("Skipped, not Unmatch", model["summary"])
        self.assertNotIn("CommandLine is absent", model["summary"])
        self.assertIn("logsource", model["summary"])

    def test_legacy_missing_tree(self):
        result = fixture()[2]
        result.pop("Condition Explanation")
        model = explain_evaluation(result)
        self.assertFalse(model["complete"])
        self.assertIn("cannot be reconstructed", model["summary"])
        self.assertIn("Recorded event decision: Unmatch", model["summary"])

    def test_legacy_missing_presence(self):
        result = fixture()[2]
        result["Checks"]["selection"]["CommandLine|contains"].pop("Field Present")
        self.assertIn("presence was not recorded", explain_evaluation(result)["summary"])

    def test_absent_evaluation(self):
        self.assertFalse(explain_evaluation(None)["complete"])
        self.assertIn(
            "not a confirmed negative",
            explain_evaluation({"Selection": None})["summary"],
        )

    def test_inconsistent_condition_not_explained_as_fact(self):
        result = fixture()[2]
        result["Condition Explanation"]["Result"] = True
        model = explain_evaluation(result)
        self.assertFalse(model["complete"])
        self.assertIn("cannot be reconstructed", model["summary"])

    def test_inconsistent_field_results_detected(self):
        result = fixture()[2]
        result["Checks"]["selection"]["CommandLine|contains"]["Matched"] = True
        self.assertFalse(explain_evaluation(result)["complete"])

    def test_deep_legacy_tree_is_bounded(self):
        result = fixture()[2]

        for _ in range(50):
            result["Condition Explanation"] = {
                "Type": "not",
                "Result": False,
                "Operand": result["Condition Explanation"],
            }

        self.assertFalse(explain_evaluation(result)["complete"])

    def test_html_and_terminal_escape_event_content(self):
        result = fixture(fields={"CommandLine": "<script>alert(1)</script>[red]payload[/red]"})[2]
        html = render_explanation(result)
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("[red]payload[/red]", terminal(terminal_explanation(result)))

    def test_rendering_does_not_mutate_or_recalculate_inputs(self):
        result = fixture()[2]
        before = copy.deepcopy(result)
        render_explanation(result)
        terminal(terminal_explanation(result))
        self.assertEqual(result, before)

    def test_details_preserve_full_values(self):
        result = fixture(fields={"CommandLine": "x" * 500})[2]
        html = render_event_evaluation([{"Result": "Unmatch", "Evaluation": result}])
        self.assertIn("see recorded details", html)
        self.assertIn("x" * 500, html)
        self.assertIn("Recorded evaluation details", html)

    def test_full_report_and_cli_group_links(self):
        rule, event, result = fixture()
        report = build_rule_report(rule, [result], [])
        report["Event Evidence"] = {event["record_id"]: event}
        html = build_html_report(report)
        self.assertIn("Why this decision", html)
        self.assertIn('class="event-evaluation"', html)
        cli = terminal(build_event_review_view(report))
        self.assertIn("event-42", cli)
        self.assertIn("CommandLine is present", cli)
        self.assertIn("Event decision: Unmatch", cli)

    def test_regression_both_rules_and_expectation_separate(self):
        root = ROOT / "examples/regression"
        report = run_regression(
            root / "suite.json", root / "baseline.yaml", root / "candidate.yaml"
        )
        html = build_regression_html(report)
        self.assertIn("Baseline rule evaluation", html)
        self.assertIn("Candidate rule evaluation", html)
        self.assertIn("Why this decision", html)
        self.assertIn("insufficient_data", html)
        session = next(iter(report["sessions"].values()))
        cli = terminal(regression_terminal_explanations(session, limit=1))
        self.assertIn("Baseline — event", cli)
        self.assertIn("Candidate — event", cli)
        self.assertIn("additional event explanations", cli)

    def test_legacy_complete_views_with_missing_optional_details(self):
        rule, event, result = fixture()
        report = build_rule_report(rule, [result], [])
        report["Event Evidence"] = {event["record_id"]: event}
        evidence = report["Event Review"]["Unmatch"][0]["Evidence"]
        evidence.pop("Condition Explanation")
        evidence["Checks"]["selection"]["CommandLine|contains"].pop("Field Present")
        self.assertIn("cannot be reconstructed", build_html_report(report))
        self.assertIn("cannot be reconstructed", terminal(build_event_review_view(report)))

    def test_boolean_truth_tables_from_real_matcher(self):
        for operator in ("and", "or"):
            for a in (False, True):
                for b in (False, True):
                    with self.subTest(operator=operator, a=a, b=b):
                        model = self.model(
                            condition="a " + operator + " b",
                            fields={"A": "yes" if a else "no", "B": "yes" if b else "no"},
                            blocks={"a": {"A": "yes"}, "b": {"B": "yes"}},
                        )
                        self.assertTrue(model["complete"])
                        expected = a and b if operator == "and" else a or b
                        self.assertIn(
                            "Event decision: " + ("Match" if expected else "Unmatch"),
                            model["summary"],
                        )

    def test_nested_condition_preserves_branch_results(self):
        rule, event, result = fixture(
            condition="(a or b) and not c",
            blocks={
                "a": {"CommandLine|contains": "missing"},
                "b": {"CommandLine|contains": "--help"},
                "c": {"CommandLine|contains": "blocked"},
            },
        )
        text = terminal(terminal_explanation(result))

        for part in ("OR(False, True): True", "NOT: False → True", "AND(True, True): True"):
            self.assertIn(part, text)

    def test_other_operators_and_normalized_event_id(self):
        for key, expected in [
            ("CommandLine|startswith", "example"),
            ("CommandLine|endswith", "--help"),
            ("CommandLine", "example*"),
            ("EventID", "1"),
        ]:
            with self.subTest(key=key):
                self.assertIn(
                    "Event decision: Match",
                    self.model(blocks={"selection": {key: expected}})["summary"],
                )

    def test_redirected_cp1252_streams_become_utf8(self):
        output, error = (io.BytesIO(), io.BytesIO())
        stdout = io.TextIOWrapper(output, encoding="cp1252")
        stderr = io.TextIOWrapper(error, encoding="cp1252")

        with patch.object(sys, "stdout", stdout), patch.object(sys, "stderr", stderr):
            configure_standard_streams()
            print("False → True; доказ")
            print("Error → діагностика", file=sys.stderr)
            stdout.flush()
            stderr.flush()

        self.assertIn("False → True; доказ", output.getvalue().decode("utf-8"))
        self.assertIn("Error → діагностика", error.getvalue().decode("utf-8"))
        stdout.detach()
        stderr.detach()

    def test_redirected_rich_not_tree_completes(self):
        output = io.BytesIO()
        stdout = io.TextIOWrapper(output, encoding="cp1252")

        with patch.object(sys, "stdout", stdout):
            console = create_console()
            self.assertFalse(console.legacy_windows)
            self.assertFalse(console.is_terminal)
            console.print(terminal_explanation(fixture(condition="not selection")[2]))
            stdout.flush()

        text = output.getvalue().decode("utf-8")
        self.assertIn("NOT: False → True", text)
        self.assertIn("test expectations are evaluated separately", text)
        self.assertNotIn("\x1b[", text)
        stdout.detach()

    def test_legacy_terminal_keeps_encoding_with_safe_errors(self):

        class Terminal(io.TextIOWrapper):

            def isatty(self):
                return True

        output = io.BytesIO()
        stdout = Terminal(output, encoding="cp1252")

        with patch.object(sys, "stdout", stdout):
            configure_standard_streams()
            self.assertEqual(stdout.encoding, "cp1252")
            print("NOT: False → True")
            stdout.flush()

        self.assertIn("\\u2192", output.getvalue().decode("cp1252"))
        stdout.detach()

    def test_embedded_stringio_stream_is_supported(self):
        stdout = io.StringIO()

        with patch.object(sys, "stdout", stdout):
            create_console().print("False → True")

        self.assertIn("False → True", stdout.getvalue())

    def test_html_tags_are_balanced(self):

        class Parser(HTMLParser):

            def __init__(self):
                super().__init__()
                self.stack = []

            def handle_starttag(self, tag, attrs):
                if tag not in {"br", "hr", "input", "meta", "link", "img"}:
                    self.stack.append(tag)

            def handle_endtag(self, tag):
                if not self.stack or self.stack.pop() != tag:
                    raise AssertionError("Unbalanced " + tag)

        html = render_event_evaluation([{"Result": "Unmatch", "Evaluation": fixture()[2]}])
        parser = Parser()
        parser.feed(html)
        self.assertEqual(parser.stack, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
