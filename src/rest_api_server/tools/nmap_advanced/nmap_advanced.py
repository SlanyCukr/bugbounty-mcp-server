"""Advanced Nmap wrapper that keeps output focused on actionable findings."""

import logging
import os
import shlex
from typing import Any

from flask import jsonify, request

from src.rest_api_server.tools.nmap import parse_nmap_output
from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import (
    create_error_response,
    create_stats,
    tool,
)

logger = logging.getLogger(__name__)


def _build_nmap_advanced_command(params: dict[str, Any]) -> str:
    cmd_parts: list[str] = ["nmap"]

    scan_type = params.get("scan_type", "-sS").strip()
    if scan_type:
        cmd_parts.extend(scan_type.split())

    ports = params.get("ports", "").strip()
    if ports:
        cmd_parts.extend(["-p", ports])

    if params.get("stealth", False):
        cmd_parts.extend(["-T2", "-f", "--mtu", "24"])
    else:
        timing = params.get("timing", "T4").lstrip("-")
        if timing:
            cmd_parts.append(f"-{timing}")

    if params.get("os_detection", False):
        cmd_parts.append("-O")

    if params.get("service_detection", True) or params.get("version_detection", False):
        cmd_parts.append("-sV")

    if params.get("aggressive", False):
        cmd_parts.append("-A")

    script_param = params.get("nse_scripts") or params.get("scripts")
    if script_param:
        cmd_parts.extend(["--script", script_param])
    elif not params.get("aggressive", False):
        cmd_parts.extend(["--script", "default,discovery,safe"])

    cmd_parts.extend(["-oX", "-"])

    additional_args = params.get("additional_args", "")
    if additional_args:
        cmd_parts.extend(shlex.split(additional_args))

    cmd_parts.append(params["target"])

    return " ".join(shlex.quote(part) for part in cmd_parts)


def _collect_findings(stdout: str) -> tuple[list[dict[str, Any]], int]:
    findings = parse_nmap_output(stdout)

    duplicates = 0
    unique: list[dict[str, Any]] = []
    seen: set[tuple[str, Any, Any]] = set()

    for finding in findings:
        if finding["type"] == "port":
            key = (
                finding["target"],
                finding["evidence"].get("port"),
                finding["evidence"].get("protocol"),
            )
        else:
            key = (finding["type"], finding["target"], None)

        if key in seen:
            duplicates += 1
            continue

        seen.add(key)

        evidence = finding.get("evidence", {})
        evidence["discovered_by"] = "nmap-advanced"
        finding["evidence"] = evidence

        tags = finding.get("tags", [])
        if "nmap-advanced" not in tags:
            tags.append("nmap-advanced")
            finding["tags"] = tags

        unique.append(finding)

    return unique, duplicates


@tool(name="nmap-advanced", required_fields=["target"])
def execute_nmap_advanced():
    """Execute advanced Nmap scans with clean structured output."""
    data = request.get_json()
    logger.info("Executing advanced Nmap scan on %s", data["target"])

    scan_type = data.get("scan_type", "-sS").strip()
    if scan_type == "-sS" and not os.geteuid() == 0:
        data["scan_type"] = "-sT"
        logger.info("Switched to -sT due to non-root privileges")
    command = _build_nmap_advanced_command(data)
    execution_result = execute_command(command, timeout=1800)

    if not execution_result["success"]:
        error_message = (
            execution_result.get("stderr")
            or execution_result.get("error")
            or "Nmap execution failed"
        )
        error_response, status_code = create_error_response(
            error_message,
            stage="exec",
            details={
                "return_code": execution_result.get("return_code"),
                "command": execution_result.get("command", command),
            },
            status_code=500,
        )
        return jsonify(error_response), status_code

    stdout = execution_result.get("stdout", "")
    with open("/tmp/nmap_advanced_raw_output.log", "w") as f:
        f.write(stdout)
    findings, duplicates = _collect_findings(stdout)

    stats = create_stats(
        len(findings),
        duplicates,
        len(stdout.encode("utf-8")),
    )

    return {
        "findings": findings,
        "stats": stats,
    }
