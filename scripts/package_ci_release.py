import argparse
from hashlib import sha256
import json
from pathlib import Path
import shutil
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from handlers.release_manifest import verify_release
from handlers.cli_result import run_cli


def package(build, output):
    build, output = (Path(build).resolve(), Path(output).resolve())
    report = json.loads((build / "build-report.json").read_text(encoding="utf-8"))

    if (report.get("build_status") != "passed") or (
        report.get("status") not in ("passed", "passed_with_warnings")
    ):
        raise ValueError("Build/core acceptance did not pass")

    acceptance = json.loads((build / "acceptance/report.json").read_text(encoding="utf-8"))

    if (report.get("acceptance_status") != acceptance["status"]) or (
        report["status"] != acceptance["status"]
    ):
        raise ValueError("Build/acceptance status mismatch")

    ci = json.loads((build / "ci/report.json").read_text(encoding="utf-8"))

    if ci.get("status") != "passed":
        raise ValueError("Executable CI gate did not pass")

    release = build / "release"

    if verify_release(release)["status"] != "passed":
        raise ValueError("Release integrity failed")

    output.mkdir(parents=True, exist_ok=False)
    archive = output / "totenkahn-windows-candidate.zip"

    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for path in sorted(release.rglob("*")):
            if path.is_file():
                bundle.write(path, path.relative_to(release).as_posix())

    if verify_release(release)["status"] != "passed":
        raise ValueError("Release changed during export")

    with zipfile.ZipFile(archive) as bundle:
        for name in bundle.namelist():
            if sha256(bundle.read(name)).digest() != sha256((release / name).read_bytes()).digest():
                raise ValueError("Archive content mismatch: " + name)

    shutil.copy2(build / "build-report.json", output / "build-report.json")
    shutil.copytree(
        build / "acceptance",
        output / "acceptance",
        ignore=shutil.ignore_patterns("user-data", "installed"),
    )
    shutil.copytree(build / "ci", output / "ci")

    for name in (
        "operations-smoke",
        "evidence-smoke",
        "evidence-selection",
        "evidence-analysis",
        "case-smoke",
        "case-timeline",
        "hunt-smoke",
        "finding-evidence",
        "finding-case",
        "finding-bundle",
        "finding-ci",
        "finding-negative-ci",
        "source-windows",
        "source-splunk",
        "source-conflict",
        "source-windows-preflight",
        "source-windows-analysis",
        "source-splunk-preflight",
        "source-splunk-analysis",
        "source-conflict-preflight",
        "source-conflict-analysis",
    ):
        if (build / name).is_dir():
            shutil.copytree(build / name, output / name)

    for path in sorted(build.glob("input-*")):
        if path.is_dir():
            shutil.copytree(path, output / path.name)

    (output / "SHA256SUMS").write_text(
        sha256(archive.read_bytes()).hexdigest() + "  " + archive.name + "\n",
        encoding="ascii",
    )
    (output / "README.txt").write_text(
        """Internal Windows candidate, not a final live-certified release.
Extract the entire ZIP; do not copy totenkahn.exe alone.
Read build-report.json and acceptance/report.json for optional dependency limitations.
CI results are under ci/. No Atomic tests were executed by this pipeline.
First run prepares base modules only; selected test assets require explicit preparation.
""",
        encoding="utf-8",
    )

    return archive


def main():
    parser = argparse.ArgumentParser(
        description="Export a verified Windows candidate and its reports; never publish remotely."
    )
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    print(package(args.build_dir, args.output_dir))

    return 0


if __name__ == "__main__":
    raise SystemExit(run_cli(main))
