"""arjun tool implementation."""

import json
import logging
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import create_finding, create_stats, tool

logger = logging.getLogger(__name__)


def extract_arjun_params(data):
    """Extract and validate arjun parameters from request data."""
    base_params = {
        "url": data["url"],
        "threads": data.get("threads", 50),
        "method": data.get("method", "GET"),
        "methods": data.get("methods", "GET,POST"),
        "wordlist": data.get("wordlist", ""),
        "headers": data.get("headers", ""),
        "post_data": data.get("post_data", ""),
        "delay": data.get("delay", 0),
        "timeout": data.get("timeout", 10),
        "stable": data.get("stable", False),
        "include_status": data.get("include_status", ""),
        "exclude_status": data.get("exclude_status", ""),
        "output_file": data.get("output_file", ""),
        "additional_args": data.get("additional_args", ""),
    }

    return base_params


def build_arjun_command(params):
    """Build arjun command from parameters with proper input validation."""
    import shlex

    url = params["url"]

    cmd_parts = ["arjun", "-u", shlex.quote(url)]

    threads = params.get("threads", 10)
    cmd_parts.extend(["-t", str(threads)])

    methods = params.get("methods", "")
    if methods:
        method_list = [m.strip().upper() for m in methods.split(",")]
        cmd_parts.extend(["-m", ",".join(method_list)])

    wordlist = params.get("wordlist", "")
    if wordlist:
        cmd_parts.extend(["-w", shlex.quote(wordlist)])

    headers = params.get("headers", "")
    if headers:
        cmd_parts.extend(["--headers", shlex.quote(headers)])

    post_data = params.get("post_data", "")
    if post_data:
        cmd_parts.extend(["--data", shlex.quote(post_data)])

    delay = params.get("delay", 0)
    if delay > 0:
        cmd_parts.extend(["-d", str(delay)])

    timeout = params.get("timeout", 10)
    cmd_parts.extend(["--timeout", str(timeout)])

    if params.get("stable", False):
        cmd_parts.append("--stable")

    include_status = params.get("include_status", "")
    if include_status:
        cmd_parts.extend(["--include-status", include_status])

    exclude_status = params.get("exclude_status", "")
    if exclude_status:
        cmd_parts.extend(["--exclude-status", exclude_status])

    cmd_parts.append("--json")

    output_file = params.get("output_file", "")
    if output_file:
        cmd_parts.extend(["-o", shlex.quote(output_file)])

    if params["additional_args"]:
        cmd_parts.extend(params["additional_args"].split())

    return cmd_parts


def parse_arjun_json_output(stdout: str) -> list[dict[str, Any]]:
    """Parse arjun JSON output into structured findings."""
    findings = []

    if not stdout.strip():
        return findings

    try:
        data = json.loads(stdout)

        if isinstance(data, dict):
            url = data.get("url", "")
            parameters = data.get("parameters", [])

            if url and parameters:
                parsed_url = urlparse(url)
                host = parsed_url.netloc

                for param_data in parameters:
                    if isinstance(param_data, dict):
                        param_name = param_data.get("name", "")
                        method = param_data.get("method", "GET")

                        if param_name:
                            tags = ["parameter", "discovery", method.lower()]
                            if parsed_url.scheme == "https":
                                tags.append("https")
                            else:
                                tags.append("http")

                            finding = create_finding(
                                finding_type="param",
                                target=host,
                                evidence={
                                    "parameter_name": param_name,
                                    "method": method,
                                    "url": url,
                                    "path": parsed_url.path,
                                    "scheme": parsed_url.scheme,
                                    "port": parsed_url.port,
                                    "discovered_by": "arjun",
                                },
                                severity="info",
                                confidence="medium",
                                tags=tags,
                                raw_ref=json.dumps(param_data),
                            )
                            findings.append(finding)
                    elif isinstance(param_data, str):
                        tags = ["parameter", "discovery"]
                        if parsed_url.scheme == "https":
                            tags.append("https")
                        else:
                            tags.append("http")

                        finding = create_finding(
                            finding_type="param",
                            target=host,
                            evidence={
                                "parameter_name": param_data,
                                "url": url,
                                "path": parsed_url.path,
                                "scheme": parsed_url.scheme,
                                "port": parsed_url.port,
                                "discovered_by": "arjun",
                            },
                            severity="info",
                            confidence="medium",
                            tags=tags,
                            raw_ref=param_data,
                        )
                        findings.append(finding)

        elif isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    finding = create_finding(
                        finding_type="param",
                        target="unknown",
                        evidence={"parameter_name": item, "discovered_by": "arjun"},
                        severity="info",
                        confidence="low",
                        tags=["parameter", "discovery"],
                        raw_ref=item,
                    )
                    findings.append(finding)

    except json.JSONDecodeError:
        logger.warning("Failed to parse arjun JSON output")
        return findings

    if len(findings) > 100:
        findings = findings[:100]

    return findings


def parse_arjun_result(
    execution_result, params, command, started_at: datetime, ended_at: datetime
) -> dict[str, Any]:
    """Parse arjun execution result and format response with findings."""
    if not execution_result["success"]:
        return {"findings": [], "stats": create_stats(0, 0, 0)}

    stdout = execution_result.get("stdout", "")
    findings = parse_arjun_json_output(stdout)

    seen_params = set()
    unique_findings = []
    dupes_count = 0

    for finding in findings:
        param_name = finding["evidence"]["parameter_name"]
        target = finding["target"]
        unique_key = f"{target}:{param_name}"

        if unique_key not in seen_params:
            seen_params.add(unique_key)
            unique_findings.append(finding)
        else:
            dupes_count += 1

    payload_bytes = len(stdout.encode("utf-8"))
    truncated = len(findings) > 100

    stats = create_stats(len(unique_findings), dupes_count, payload_bytes)
    stats["truncated"] = truncated

    return {
        "findings": unique_findings,
        "stats": stats,
    }


@tool(required_fields=["url"])
def execute_arjun():
    """Execute Arjun for HTTP parameter discovery."""
    data = request.get_json()
    params = extract_arjun_params(data)

    logger.info(f"Executing Arjun on {params['url']}")

    started_at = datetime.now()
    command_parts = build_arjun_command(params)
    execution_result = execute_command(command_parts, timeout=600)
    ended_at = datetime.now()

    return parse_arjun_result(
        execution_result, params, command_parts, started_at, ended_at
    )
