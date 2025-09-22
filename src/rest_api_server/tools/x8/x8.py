"""x8 tool implementation."""

import re
from datetime import datetime
from typing import Any

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import tool


def extract_x8_params(data: dict) -> dict:
    """Extract and organize x8 parameters from request data."""
    return {
        "url": data["url"],
        "wordlist": data.get("wordlist", "/usr/share/wordlists/x8/params.txt"),
        "method": data.get("method", "GET"),
        "body": data.get("body", ""),
        "headers": data.get("headers", ""),
        "output_file": data.get("output_file", ""),
        "discover": data.get("discover", True),
        "learn": data.get("learn", False),
        "verify": data.get("verify", True),
        "max": data.get("max", 0),
        "workers": data.get("workers", 25),
        "as_body": data.get("as_body", False),
        "encode": data.get("encode", False),
        "force": data.get("force", False),
        "additional_args": data.get("additional_args", ""),
        "profile": data.get("profile", "standard"),
        "timeout": data.get("timeout", 600),
        "recon": data.get("recon", "full"),
    }


def build_x8_command(params: dict) -> list[str]:
    """Build the x8 command from parameters."""
    args = ["x8", "-u", params["url"]]

    # Add HTTP method
    if params.get("method"):
        args.extend(["-X", params["method"]])

    # Add wordlist
    if params.get("wordlist"):
        args.extend(["-w", params["wordlist"]])

    # Add body data
    if params.get("body"):
        args.extend(["-b", params["body"]])

    # Add headers
    headers = params.get("headers")
    if headers:
        if isinstance(headers, str):
            args.extend(["-H", headers])
        elif isinstance(headers, dict):
            for key, value in headers.items():
                args.extend(["-H", f"{key}:{value}"])

    # Add output file
    if params.get("output_file"):
        args.extend(["-o", params["output_file"]])

    # Add workers (concurrency)
    workers = params.get("workers", 25)
    if workers > 1:
        args.extend(["-c", str(workers)])

    # Add max parameters per request
    max_params = params.get("max", 0)
    if max_params > 0:
        args.extend(["-m", str(max_params)])

    # Add boolean flags
    if params.get("verify"):
        args.append("--verify")

    if params.get("encode"):
        args.append("--encode")

    if params.get("force"):
        args.append("--force")

    if params.get("as_body"):
        args.append("--invert")

    if params.get("learn"):
        args.append("--learn")

    if params.get("recon"):
        args.append("--recon")

    # Add additional args if provided
    if params.get("additional_args"):
        args.extend(params["additional_args"].split())

    return args


def parse_x8_output(
    execution_result: dict[str, Any],
    params: dict,
    command: list[str],
    started_at: datetime,
    ended_at: datetime,
) -> dict[str, Any]:
    """Parse x8 execution results into structured findings."""
    duration_ms = int((ended_at - started_at).total_seconds() * 1000)

    if not execution_result["success"]:
        return {
            "success": False,
            "tool": "x8",
            "params": params,
            "command": command,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "duration_ms": duration_ms,
            "error": execution_result.get("error", "Command execution failed"),
            "findings": [],
            "stats": {"findings": 0, "dupes": 0, "payload_bytes": 0},
        }

    # Parse successful output
    stdout = execution_result.get("stdout", "")
    findings = []

    # Extract discovered parameters from output
    for line in stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue

        param_info = _extract_parameter_from_line(line)
        if param_info:
            finding = {
                "type": "parameter",
                "target": param_info.get("name", line),
                "evidence": {
                    "raw_output": line,
                    "method": param_info.get("method", "GET"),
                    "discovery_method": "brute_force",
                },
                "severity": "info",
                "confidence": param_info.get("confidence", "medium"),
                "tags": ["x8", "parameter-discovery"],
                "raw_ref": line,
            }
            findings.append(finding)

    payload_bytes = len(stdout.encode("utf-8"))

    return {
        "success": True,
        "tool": "x8",
        "params": params,
        "command": command,
        "started_at": started_at.isoformat(),
        "ended_at": ended_at.isoformat(),
        "duration_ms": duration_ms,
        "findings": findings,
        "stats": {
            "findings": len(findings),
            "dupes": 0,
            "payload_bytes": payload_bytes,
        },
    }


def _extract_parameter_from_line(line: str) -> dict[str, Any] | None:
    """Extract parameter information from a single output line."""
    param_patterns = [
        r"\[INFO\].*Found parameter:?\s*([a-zA-Z_][a-zA-Z0-9_]*)",
        r"\[FOUND\]\s*(\w+)\s+parameter:?\s*([a-zA-Z_][a-zA-Z0-9_]*)",
        r"([a-zA-Z_][a-zA-Z0-9_]*)\s*->\s*(\w+)",
        r"^([a-zA-Z_][a-zA-Z0-9_]*)\s*$",
    ]

    for pattern in param_patterns:
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            groups = match.groups()

            if len(groups) == 1:
                return {
                    "name": groups[0],
                    "method": "GET",
                    "confidence": "medium",
                    "raw_line": line,
                }
            elif len(groups) == 2:
                if groups[1].upper() in ["GET", "POST", "PUT", "PATCH", "DELETE"]:
                    return {
                        "name": groups[0],
                        "method": groups[1].upper(),
                        "confidence": "high",
                        "raw_line": line,
                    }
                else:
                    return {
                        "name": groups[1],
                        "method": groups[0].upper(),
                        "confidence": "high",
                        "raw_line": line,
                    }

    return None


@tool(required_fields=["url"])
def execute_x8():
    """Execute x8 for hidden parameter discovery."""
    data = request.get_json()
    params = extract_x8_params(data)

    started_at = datetime.now()
    command = build_x8_command(params)
    execution_result = execute_command(command, timeout=params.get("timeout", 600))
    ended_at = datetime.now()

    return parse_x8_output(execution_result, params, command, started_at, ended_at)
