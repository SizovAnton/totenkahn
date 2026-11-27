import sys
import json

STATUS_CODES = {
    "passed": 0,
    "completed": 0,
    "passed_with_warnings": 0,
    "blocked": 1,
    "error": 2,
    "failed": 2,
    "needs_verification": 3,
    "needs_action": 3,
    "interrupted": 130,
}


def emit_result(payload, title, *, json_output=False):
    try:
        from displaying.results import emit_result as render_result
    except ModuleNotFoundError as exc:
        if exc.name != "rich" and not (exc.name or "").startswith("rich."):
            raise

        print(json.dumps(payload, ensure_ascii=False, indent=2), flush=True)

        return

    render_result(payload, title, json_output=json_output)


def status_code(status):
    return STATUS_CODES.get(status, 2)


def run_cli(entry):
    try:
        result = entry()

        if type(result) is int:
            return result

        if isinstance(result, dict) and "status" in result:
            return status_code(result["status"])

        return 0
    except KeyboardInterrupt:
        emit_result(
            {
                "status": "interrupted",
                "reason": "Operation interrupted; inspect retained journals and evidence",
            },
            "Operation interrupted",
            json_output="--json" in sys.argv or "--atomic-plan" in sys.argv,
        )

        return 130
    except Exception as exc:
        emit_result(
            {"status": "error", "error_type": type(exc).__name__, "reason": str(exc)},
            "Operation failed",
            json_output="--json" in sys.argv or "--atomic-plan" in sys.argv,
        )

        return 2
