import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
from rich.console import Console

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from displaying.results import emit_result, render_result, value_text, clean
from displaying.console import show_startup_banner
from handlers.cli_result import run_cli


class Terminal(io.StringIO):

    def isatty(self):
        return True


class TerminalTests(unittest.TestCase):

    def test_redirected_result_preserves_json(self):
        stream = io.StringIO()
        value = {"status": "passed", "name": "тест", "count": 3}
        emit_result(value, stream=stream)
        self.assertEqual(json.loads(stream.getvalue()), value)
        self.assertNotIn("\x1b", stream.getvalue())

    def test_explicit_json_even_in_terminal(self):
        stream = Terminal()
        value = {"status": "error", "reason": "fixture"}
        emit_result(value, json_output=True, stream=stream, human_payload={"different": True})
        self.assertEqual(json.loads(stream.getvalue()), value)

    def test_interactive_result_is_readable_not_json(self):
        stream = Terminal()

        with patch.dict(
            os.environ, {"NO_COLOR": "1", "TERM": "xterm-256color", "FORCE_COLOR": "1"}
        ):
            emit_result(
                {
                    "status": "passed",
                    "counts": {"match": 1, "no_match": 2},
                    "report": "C:\\Test Env\\report.json",
                },
                "Hunting",
                stream=stream,
            )

        text = stream.getvalue()
        self.assertIn("Hunting", text)
        self.assertIn("PASS", text)
        self.assertIn("Counts", text)
        self.assertNotIn('"status":', text)
        self.assertNotIn("\x1b", text)
        self.assertIn("C:\\Test Env\\report.json", text)

    def test_status_styles_distinguish_decision_from_failure(self):
        self.assertEqual(value_text("match", "decision").style, "bold green")
        self.assertEqual(value_text("no_match", "decision").style, "bold yellow")
        self.assertEqual(value_text("error", "status").style, "bold red")
        self.assertEqual(value_text("met", "status").style, "bold green")
        self.assertEqual(value_text("insufficient_data", "status").style, "bold yellow")
        self.assertEqual(value_text("NO MATCH", "Status").style, "bold yellow")

    def test_untrusted_markup_and_control_sequences_are_not_executed(self):
        stream = io.StringIO()
        console = Console(file=stream, force_terminal=False, width=100, markup=False)
        render_result(
            {"status": "passed", "raw": "[red]literal[/red]\x1b[31m\u202e"},
            "Evidence",
            console,
        )
        text = stream.getvalue()
        self.assertIn("[red]literal[/red]", text)
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\u202e", text)
        self.assertIn("\\u001b", text)

    def test_nested_checks_and_links_have_labels(self):
        stream = io.StringIO()
        console = Console(file=stream, force_terminal=False, width=100)
        render_result(
            {
                "status": "needs_verification",
                "compatibility": {"fields": {"CommandLine": {"present": False}}},
                "source": {"sha256": "abc"},
                "locator": {"line": 3},
                "mappings": {"host": ["host"]},
            },
            "Evidence",
            console,
        )
        text = stream.getvalue()
        self.assertIn("Evidence compatibility", text)
        self.assertIn("Original record location", text)
        self.assertIn("Mapping paths (not event values)", text)
        self.assertIn("UNKNOWN is not NO MATCH", text)

    def test_summary_limits_are_explicit(self):
        stream = io.StringIO()
        console = Console(file=stream, force_terminal=False, width=120)
        render_result(
            {"status": "passed", "items": [{"value": "x" * 1500}] * 20},
            "Records",
            console,
        )
        text = stream.getvalue()
        self.assertIn("8 more entries", text)
        self.assertIn("more characters", text)
        self.assertIn("--json", text)

    def test_narrow_terminal_does_not_raise(self):
        stream = io.StringIO()
        render_result(
            {
                "status": "failed",
                "jobs": [{"id": "a-long-job", "violations": ["not_met=1 exceeds 0"]}],
            },
            "CI",
            Console(file=stream, width=32),
        )
        self.assertTrue(stream.getvalue())

    def test_cp1252_stream_is_safe(self):
        data = io.BytesIO()
        stream = io.TextIOWrapper(data, encoding="cp1252", errors="backslashreplace")
        render_result(
            {"status": "passed", "name": "Подія → правило"},
            "Evidence",
            Console(file=stream, legacy_windows=False, force_terminal=False, width=80),
        )
        stream.flush()
        self.assertTrue(data.getvalue())
        stream.detach()

    def test_exception_remains_json_for_automation(self):
        output = io.StringIO()

        def fail():
            raise ValueError("fixture error")

        with patch("sys.stdout", output):
            code = run_cli(fail)

        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "error")

    def test_exception_readable_in_terminal(self):
        output = Terminal()

        def fail():
            raise ValueError("fixture error")

        with (
            patch("sys.stdout", output),
            patch("sys.argv", ["totenkahn"]),
            patch.dict(os.environ, {"NO_COLOR": "1"}),
        ):
            code = run_cli(fail)

        self.assertEqual(code, 2)
        self.assertIn("ERROR", output.getvalue())
        self.assertIn("fixture error", output.getvalue())

    def test_banner_suppressed_with_redirected_stdout(self):
        error = Terminal()

        with patch("sys.stdout", io.StringIO()):
            show_startup_banner([], error)

        self.assertEqual(error.getvalue(), "")

    def test_cli_json_is_still_parseable(self):
        for command in (["dump", "profiles", "--json"], ["dump", "profiles"]):
            process = subprocess.run(
                [sys.executable, "-B", str(ROOT / "main.py"), *command],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=30,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertEqual(json.loads(process.stdout)["status"], "passed")
            self.assertNotIn("T  O  T  E  N  K  A  H  N", process.stderr)

    def test_builder_bootstraps_without_site_packages(self):
        process = subprocess.run(
            [
                sys.executable,
                "-S",
                "-B",
                str(ROOT / "scripts/build_windows_acceptance.py"),
                "--help",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertIn("--source-commit", process.stdout)

    def test_bootstrap_error_and_interrupt_without_rich(self):
        code = "from handlers.cli_result import run_cli; print(run_cli(lambda: 0)); print(run_cli(lambda: (_ for _ in ()).throw(ValueError('fixture')))); print(run_cli(lambda: (_ for _ in ()).throw(KeyboardInterrupt())))"
        process = subprocess.run(
            [sys.executable, "-S", "-B", "-c", code],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertIn('"status": "error"', process.stdout)
        self.assertIn('"status": "interrupted"', process.stdout)
        self.assertTrue(process.stdout.rstrip().endswith("130"))

    def test_no_color_banner_has_no_ansi_even_if_color_forced(self):
        stream = Terminal()

        with (
            patch.dict(os.environ, {"NO_COLOR": "1", "TERM": "xterm-256color", "FORCE_COLOR": "1"}),
            patch("sys.stdout", stream),
        ):
            show_startup_banner(["dump", "list"], stream)

        self.assertEqual(stream.getvalue(), "\n    T  O  T  E  N  K  A  H  N\n             v0.1.0\n\n")
        self.assertNotIn("\x1b", stream.getvalue())

    def test_no_color_legacy_console_has_no_styles(self):
        from displaying.console import create_console

        stream = Terminal()

        with (
            patch.dict(os.environ, {"NO_COLOR": "1", "TERM": "xterm-256color", "FORCE_COLOR": "1"}),
            patch("sys.stdout", stream),
        ):
            create_console().print("Example", style="bold red")

        self.assertEqual(stream.getvalue().strip(), "Example")


if __name__ == "__main__":
    unittest.main()
