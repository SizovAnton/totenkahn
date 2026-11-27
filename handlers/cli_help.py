import argparse
from typing import NoReturn

SCENARIOS = {
    "self-test": "self-test operations --events 5000\n  self-test offline\n  self-test offline --stage 3 --output-dir NEW_DIRECTORY",
    "test": "test auto --rule RULE.yaml --technique T1033 8\n  test manual --rule RULE.yaml\n  test replay --rule RULE.yaml --session SESSION_DIR",
    "dependencies": "dependencies status\n  dependencies prepare\n  dependencies prepare-test --technique T1033 8\n  dependencies remove --dry-run",
    "telemetry": "telemetry check --rule RULE.yaml\n  telemetry prepare --rule RULE.yaml\n  telemetry restore --dry-run",
    "dump": "dump import events.evtx --name investigation\n  dump analyze investigation --rule RULE.yaml\n  dump recover DATASET --output-dir NEW_DIRECTORY",
    "case": 'case create --name investigation --title "Server investigation"\n  case add investigation --dataset DATASET\n  case timeline investigation',
    "hunt": "hunt define CASE --name hypothesis --author ENGINEER --spec hunt.json\n  hunt run CASE --name hypothesis",
    "finding": "finding list CASE\n  finding export CASE --name FINDING --baseline baseline.yaml --candidate candidate.yaml --output-dir NEW_DIRECTORY",
    "ci": "ci --config pipeline.json --output-dir NEW_DIRECTORY\n  ci revisions --repo REPOSITORY --baseline FULL_SHA --candidate FULL_SHA --output-dir NEW_DIRECTORY",
}


def examples(prog):
    if "test auto" in prog:
        return "test auto --rule RULE.yaml --technique T1033 8 --input whoami_args=/all"

    if "test manual" in prog:
        return "test manual --rule RULE.yaml"

    if "test replay" in prog:
        return "test replay --rule RULE.yaml --session SESSION_DIR"

    for name, text in SCENARIOS.items():
        if name in prog.split()[1:]:
            return text

    return SCENARIOS["test"]


class HelpfulParser(argparse.ArgumentParser):

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("formatter_class", argparse.RawDescriptionHelpFormatter)
        kwargs.setdefault("usage", "%(prog)s [options] — see scenarios below")
        super().__init__(*args, **kwargs)

        if self.epilog is None:
            self.epilog = "Examples:\n  totenkahn " + examples(self.prog)

    def error(self, message) -> NoReturn:
        hint = ""

        if "--technique" in message or "--test-number" in message:
            hint = "\n--technique expects TWO values: technique ID and positive test number. Example: --technique T1033 8\n"

        self.exit(
            2,
            f"\nCommand error: {message}\n{hint}\nExamples:\n  totenkahn {examples(self.prog)}\n\nDetails: {self.prog} --help\n",
        )


def show_overview():
    print("TOTENKAHN — choose the engineering task\n")
    print("Live automatic test: test auto --rule RULE.yaml --technique T1033 8")
    print("Live manual action:  test manual --rule RULE.yaml")
    print("Saved-session replay: test replay --rule RULE.yaml --session SESSION_DIR\n")
    print(
        "Live tests check readiness and ask before installing dependencies or changing audit settings."
    )
    print("Auto additionally asks before executing Atomic. Manual/replay do not install Atomic.")
    print("Use -y / --yes to approve scenario confirmations, including dependencies, telemetry and selected Atomic execution.")
    print("Prerequisite installation, cleanup and Sysmon EULA acceptance remain separate options. Plan/dry-run never execute changes.")
    print("Paths are relative to the current terminal directory; quote paths containing spaces.\n")
    print(
        "Dump analysis: dump import -> dump analyze; investigation: case -> hunt -> finding; regression: ci"
    )
    print(
        "Local five-stage acceptance: self-test offline (generated synthetic evidence; no external services)"
    )
    print(
        "Operational acceptance: self-test operations --events 5000; recovery: dump recover DATASET --output-dir NEW_DIRECTORY"
    )
    print("Diagnostics: dependencies, telemetry, doctor. Saved reports: reports --open")
    print("Use: totenkahn test auto --help (inputs, approvals, examples).")
    print("Existing --auto / --manual / --session commands remain supported.")
