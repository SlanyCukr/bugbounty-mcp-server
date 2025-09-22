"""paramspider tool implementation."""

import re
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import tool


def extract_paramspider_params(data: dict) -> dict:
    """Extract and organize paramspider parameters from request data."""
    # Extract domain from URL if provided
    domain = data.get("domain", data.get("url", ""))
    if domain.startswith("http"):
        parsed = urlparse(domain)
        domain = parsed.netloc

    return {
        "domain": domain,
        "stream": data.get("stream", True),
        "placeholder": data.get("placeholder", "FUZZ"),
        "proxy": data.get("proxy", ""),
        "exclude": data.get("exclude", []),
        "output": data.get("output", ""),
        "level": data.get("level", 1),
        "subs": data.get("subs", False),
        "silent": data.get("silent", False),
        "clean": data.get("clean", False),
        "aggressive": data.get("aggressive", False),
        "additional_args": data.get("additional_args", ""),
        "timeout": data.get("timeout", 600),
    }


def build_paramspider_command(params: dict) -> list[str]:
    """Build the paramspider command from parameters."""
    args = ["paramspider", "-d", params["domain"]]

    # Add stream mode (-s flag) for real-time output
    if params["stream"]:
        args.append("-s")

    # Add placeholder for parameter values
    if params["placeholder"] and params["placeholder"] != "FUZZ":
        args.extend(["-p", params["placeholder"]])

    # Add proxy if specified
    if params["proxy"]:
        args.extend(["--proxy", params["proxy"]])

    # Add level (recursion depth)
    if params["level"] > 1:
        args.extend(["-l", str(params["level"])])

    # Add subdomain inclusion
    if params["subs"]:
        args.append("--subs")

    # Add exclude patterns
    exclude = params.get("exclude", [])
    if exclude:
        if isinstance(exclude, list):
            exclude_str = " ".join(exclude)
        else:
            exclude_str = str(exclude).strip()
        if exclude_str:
            args.extend(["--exclude", exclude_str])

    # Add output file
    if params["output"]:
        args.extend(["-o", params["output"]])

    # Add silent mode
    if params["silent"]:
        args.append("--silent")

    # Add any additional arguments
    if params["additional_args"]:
        args.extend(params["additional_args"].split())

    return args


def parse_paramspider_output(
    execution_result: dict[str, Any],
    params: dict,
    command: list[str],
    started_at: datetime,
    ended_at: datetime,
) -> dict[str, Any]:
    """Parse paramspider execution results into structured findings."""
    duration_ms = int((ended_at - started_at).total_seconds() * 1000)

    if not execution_result["success"]:
        return {
            "success": False,
            "tool": "paramspider",
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

    # Extract parameters from paramspider output
    for line in stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue

        # Parse parameter findings
        param_info = _extract_parameter_from_line(line)
        if param_info:
            finding = {
                "type": "parameter",
                "target": param_info.get("target", params["domain"]),
                "evidence": {
                    "raw_output": line,
                    "parameter_name": param_info.get("parameter_name"),
                    "url": param_info.get("url"),
                },
                "severity": "info",
                "confidence": "medium",
                "tags": ["paramspider", "parameter-discovery"],
                "raw_ref": line,
            }
            findings.append(finding)

    payload_bytes = len(stdout.encode("utf-8"))

    return {
        "success": True,
        "tool": "paramspider",
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
    # ParamSpider outputs URLs with parameters
    # Example: https://example.com/page?param=FUZZ
    if line.startswith("http") and ("?" in line or "&" in line):
        try:
            parsed_url = urlparse(line)
            query = parsed_url.query

            if query:
                # Extract parameter names from query string
                param_pairs = query.split("&")
                for pair in param_pairs:
                    if "=" in pair:
                        param_name, param_value = pair.split("=", 1)
                        param_name = param_name.strip()

                        if param_name:  # Skip empty parameter names
                            return {
                                "parameter_name": param_name,
                                "url": line,
                                "target": parsed_url.netloc,
                                "raw_line": line,
                            }
        except Exception:
            pass

    # Also look for direct parameter listings that some versions output
    elif (
        "=" not in line
        and line
        and not line.startswith("[")
        and not line.startswith("http")
    ):
        # Sometimes paramspider outputs just parameter names
        param_match = re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", line)
        if param_match:
            return {
                "parameter_name": line,
                "target": "unknown",
                "raw_line": line,
            }

    return None


@tool(required_fields=["domain"])
def execute_paramspider():
    """Execute ParamSpider for parameter mining from web archives."""
    data = request.get_json()
    params = extract_paramspider_params(data)

    started_at = datetime.now()
    command = build_paramspider_command(params)
    execution_result = execute_command(
        " ".join(command), timeout=params.get("timeout", 600)
    )
    ended_at = datetime.now()

    return parse_paramspider_output(
        execution_result, params, command, started_at, ended_at
    )
