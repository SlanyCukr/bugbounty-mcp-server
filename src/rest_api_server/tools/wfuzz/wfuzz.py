"""wfuzz tool implementation."""

import logging
from datetime import datetime
from typing import Any

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import tool

logger = logging.getLogger(__name__)


def extract_wfuzz_params(data: dict) -> dict:
    """Extract wfuzz parameters from request data."""
    aggressive = data.get("aggressive", False)

    base_params = {
        "url": data.get("url", data.get("domain", "")),
        "wordlist": data.get(
            "wordlist", "/usr/share/wordlists/wfuzz/Injections/All-attack.txt"
        ),
        "threads": data.get("threads", 40),
        "hide_codes": data.get("hide_codes", "404"),
        "show_codes": data.get("show_codes", "200,301,302,401,403,500"),
        "follow_redirects": data.get("follow_redirects", False),
        "payload": data.get("payload", "FUZZ"),
        "timeout": data.get("timeout", 300),
        "additional_args": data.get("additional_args", ""),
    }

    if aggressive:
        base_params.update(
            {
                "threads": 100,
                "hide_codes": "404",
                "show_codes": "200,301,302,401,403,500",
                "timeout": 30,
            }
        )

    return base_params


def build_wfuzz_command(params: dict) -> str:
    """Build wfuzz command from parameters."""
    command_parts = ["wfuzz", "-w", params["wordlist"], "-t", str(params["threads"])]

    if params["hide_codes"]:
        command_parts.extend(["--hc", params["hide_codes"]])

    if params["show_codes"]:
        command_parts.extend(["--sc", params["show_codes"]])

    if params["follow_redirects"]:
        command_parts.append("-L")

    # Handle FUZZ parameter in URL
    url = params["url"]
    if params["payload"] not in url:
        if url.endswith("/"):
            url += params["payload"]
        else:
            url += f"/{params['payload']}"
    command_parts.append(url)

    if params["additional_args"]:
        command_parts.extend(params["additional_args"].split())

    return " ".join(command_parts)


def parse_wfuzz_output(stdout: str) -> list[dict[str, Any]]:
    """Parse wfuzz output into findings."""
    findings = []

    if not stdout.strip():
        return findings

    lines = stdout.strip().split("\n")

    for line in lines:
        line = line.strip()
        if not line or line.startswith("Warning:") or line.startswith("*"):
            continue

        # Parse wfuzz output format
        if line and not line.startswith("="):
            finding = {
                "type": "endpoint",
                "target": line,
                "evidence": {
                    "raw_output": line,
                    "discovered_by": "wfuzz",
                },
                "severity": "info",
                "confidence": "medium",
                "tags": ["wfuzz", "fuzzing"],
                "raw_ref": line,
            }
            findings.append(finding)

    return findings


def parse_wfuzz_result(
    execution_result: dict,
    params: dict,
    command: str,
    started_at: datetime,
    ended_at: datetime,
) -> dict[str, Any]:
    """Parse wfuzz execution result and format response."""
    duration_ms = int((ended_at - started_at).total_seconds() * 1000)

    if not execution_result["success"]:
        return {
            "success": False,
            "tool": "wfuzz",
            "params": params,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "duration_ms": duration_ms,
            "error": execution_result.get("stderr", "Command execution failed"),
            "findings": [],
            "stats": {"findings": 0, "dupes": 0, "payload_bytes": 0},
        }

    stdout = execution_result.get("stdout", "")
    findings = parse_wfuzz_output(stdout)
    payload_bytes = len(stdout.encode("utf-8"))

    return {
        "success": True,
        "tool": "wfuzz",
        "target": params["url"],
        "command": command,
        "parameters": params,
        "started_at": started_at.isoformat(),
        "ended_at": ended_at.isoformat(),
        "duration_ms": duration_ms,
        "findings": findings,
        "stats": {
            "findings": len(findings),
            "dupes": 0,
            "payload_bytes": payload_bytes,
        },
        "execution": {
            "success": execution_result["success"],
            "return_code": execution_result["return_code"],
            "stdout": execution_result["stdout"],
            "stderr": execution_result["stderr"],
        },
    }


@tool(required_fields=["url"])
def execute_wfuzz():
    """Execute Wfuzz for web application fuzzing."""
    data = request.get_json()
    params = extract_wfuzz_params(data)

    logger.info(f"Executing Wfuzz on {params['url']}")

    started_at = datetime.now()
    command = build_wfuzz_command(params)
    logger.info(f"Wfuzz command: {command}")

    execution_result = execute_command(command, timeout=params["timeout"])
    ended_at = datetime.now()

    return parse_wfuzz_result(execution_result, params, command, started_at, ended_at)
