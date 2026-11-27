from displaying.results import emit_result


def execution_prompt(plan):
    actions = ["execute prerequisite checks"] if plan.get("dependencies") else []

    if plan.get("dependencies") and plan.get("prepare_requested"):
        actions.append("prepare missing prerequisites")

    actions.append("run the displayed command on this host")

    if plan.get("cleanup_requested") and plan.get("cleanup_command", "").strip():
        actions.append("run the displayed cleanup after collection")

    return "; ".join(actions).capitalize() + "?"


def execution_summary(plan, verbosity=0):
    summary = {
        key: plan[key]
        for key in (
            "technique",
            "test_number",
            "name",
            "command",
            "executor",
            "elevation_required",
            "timeout_seconds",
        )
        if key in plan
    }
    prerequisites = []

    for item in plan.get("dependencies", []):
        check = {
            key: item[key] for key in ("number", "description", "executor", "check") if key in item
        }

        if plan.get("prepare_requested"):
            check["prepare_if_missing"] = item.get("prepare", "")

        prerequisites.append(check)

    summary["prerequisites"] = prerequisites or "none"

    if prerequisites:
        summary["prerequisite_preparation"] = (
            "allowed if missing; may change this host"
            if plan.get("prepare_requested")
            else "not authorized; missing prerequisites stop execution"
        )

    cleanup = plan.get("cleanup_command", "").strip()
    summary["cleanup"] = (
        cleanup
        if cleanup and plan.get("cleanup_requested")
        else "not requested" if cleanup else "not defined"
    )

    if cleanup and plan.get("cleanup_requested"):
        summary["cleanup_limit"] = "Definition cleanup is not a verified host rollback"

    if verbosity:
        for key in (
            "inputs",
            "definition",
            "definition_sha256",
            "test_guid",
            "module_path",
            "yaml_module_path",
        ):
            if key in plan:
                summary[key] = plan[key]

    return summary


def preflight_summary(payload, title, verbosity=0):
    if not isinstance(payload, dict):
        return payload

    if verbosity >= 2:
        return payload

    if "command" in payload and "technique" in payload:
        return execution_summary(payload, verbosity)

    if payload.get("status") not in ("passed", "planned", "needs_action"):
        return payload

    summary = {"status": payload["status"]}

    for key in ("reason", "warnings", "failures", "blockers", "actions"):
        if payload.get(key):
            summary[key] = payload[key]

    if title == "Base dependencies":
        summary["result"] = "Base dependencies ready; required files verified"

        if verbosity:
            summary["components"] = [
                {key: item.get(key) for key in ("component_key", "version", "origin", "path")}
                for item in payload.get("components", [])
            ]
            summary["saved_verification"] = payload.get("verification", {})
            summary["verification_note"] = "Saved preparation result; not a new module import check"
    elif title == "Selected resources":
        record = payload.get("resources", {})
        files = payload.get("files", record.get("files", {}))
        summary.update(
            technique=payload.get("technique"),
            test_number=payload.get("test_number"),
            resources=payload.get("readiness", "prepared" if record else "planned"),
            file_count=len(files),
            bytes=sum(item["size"] for item in files.values()),
        )

        if payload.get("readiness") != "already verified" or verbosity:
            summary["files"] = list(files) if not verbosity else files
    elif title == "Telemetry readiness":
        requirements = payload.get("requirements", {})
        summary["channels"] = requirements.get("channels", [])
        summary["result"] = (
            "Required telemetry settings are ready; event delivery is checked during the test"
        )
        observation = payload.get("observation", {})
        errors = observation.get("errors", {})
        relevant_errors = (
            {
                key: value
                for key, value in errors.items()
                if key.lower() != "sysmon" or requirements.get("sysmon")
            }
            if isinstance(errors, dict)
            else errors
        )

        if relevant_errors:
            summary["observation_errors"] = relevant_errors

        if verbosity:
            summary["requirements"] = requirements
            observation = payload.get("observation", {})
            summary["observation"] = {
                key: value
                for key, value in observation.items()
                if key not in ("sysmon", "native_sysmon", "errors") or requirements.get("sysmon")
            }
            errors = observation.get("errors", {})

            if errors:
                summary["diagnostic_note"] = (
                    "Additional component observations are available with -vv; required-source blockers remain visible"
                )
    elif title == "Host changes requiring consent":
        summary["requirements"] = payload.get("requirements", {})
        summary["impact"] = payload.get("impact")
    elif title == "Dependency preparation plan":
        summary["actions"] = payload.get("actions", [])
        summary["packages"] = [
            {key: item[key] for key in ("component_id", "version", "size") if key in item}
            for item in payload.get("packages", [])
        ]
        summary["system_changes"] = payload.get("system_changes")

        if verbosity:
            summary["discovery"] = payload.get("discovery", {})
    elif title == "Readiness plan":
        summary["mode"] = payload.get("mode")
        summary["scope"] = payload.get("scope")
        summary["telemetry"] = preflight_summary(
            payload.get("telemetry", {}), "Telemetry readiness", verbosity
        )
        summary["base_dependencies"] = preflight_summary(
            payload.get("base_dependencies", {}), "Base dependencies", verbosity
        )

        return summary
    else:
        for key in ("scope", "reason"):
            if payload.get(key):
                summary[key] = payload[key]

        if verbosity:
            return payload

    return {key: value for key, value in summary.items() if value is not None}


def emit_preflight(payload, title, *, verbosity=0, json_output=False, stream=None):
    emit_result(
        payload,
        title,
        json_output=json_output,
        stream=stream,
        human_payload=preflight_summary(payload, title, verbosity),
        full=True,
        legend=False,
    )
