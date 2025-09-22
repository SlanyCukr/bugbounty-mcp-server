"""feroxbuster tool implementation."""

import json
import logging
import shlex
from typing import Any
from urllib.parse import urlparse

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import create_finding, create_stats, tool

logger = logging.getLogger(__name__)


def extract_feroxbuster_params(data: dict) -> dict:
    """Extract feroxbuster parameters from request data."""
    base_params = {
        "url": data["url"],
        "wordlist": data.get("wordlist", "/usr/share/wordlists/dirb/common.txt"),
        "extensions": data.get("extensions", ""),
        "threads": data.get("threads", 50),
        "depth": data.get("depth", 1),
        "timeout": data.get("timeout", 7),
        "rate_limit": data.get("rate_limit", ""),
        "status_codes": data.get("status_codes", ""),
        "filter_status": data.get("filter_status", ""),
        "auto_tune": data.get("auto_tune", False),
        "filter_size": data.get("filter_size", ""),
        "additional_args": data.get("additional_args", ""),
    }

    return base_params


def build_feroxbuster_command(params: dict) -> str:
    """Build feroxbuster command from parameters."""
    cmd_parts = [
        "feroxbuster",
        "-u",
        shlex.quote(params["url"]),
        "-w",
        shlex.quote(params["wordlist"]),
    ]

    cmd_parts.extend(["-t", str(params["threads"])])
    cmd_parts.extend(["-d", str(params["depth"])])
    cmd_parts.extend(["-T", str(params["timeout"])])

    if params.get("rate_limit"):
        cmd_parts.extend(["-L", str(params["rate_limit"])])

    if params["extensions"]:
        cmd_parts.extend(["-x", shlex.quote(params["extensions"])])

    if params.get("status_codes"):
        cmd_parts.extend(["-s", shlex.quote(params["status_codes"])])

    if params.get("filter_status"):
        cmd_parts.extend(["-C", shlex.quote(params["filter_status"])])

    if params.get("auto_tune", False):
        cmd_parts.append("--auto-tune")

    if params.get("filter_size"):
        cmd_parts.extend(["-S", str(params["filter_size"])])

    cmd_parts.append("--json")

    if params["additional_args"]:
        additional_parts = shlex.split(params["additional_args"])
        cmd_parts.extend([shlex.quote(part) for part in additional_parts])

    return " ".join(cmd_parts)


def parse_feroxbuster_json_output(stdout: str) -> list[dict[str, Any]]:
    """Parse feroxbuster JSON output into findings."""
    findings = []

    for line in stdout.split("\n"):
        if line.strip():
            try:
                result_data = json.loads(line)
                if result_data.get("type") == "response":
                    url = result_data.get("url", "")
                    status_code = result_data.get("status", 0)
                    content_length = result_data.get("content_length", 0)
                    word_count = result_data.get("word_count", 0)
                    line_count = result_data.get("line_count", 0)

                    if url:
                        parsed_url = urlparse(url)
                        host = parsed_url.netloc
                        path = parsed_url.path or "/"

                        depth = len(url.rstrip("/").split("/")) - 3 if url else 0

                        severity = "info"
                        confidence = "medium"

                        tags = ["endpoint", "directory-enum"]
                        if status_code:
                            tags.append(f"status-{status_code}")
                        if depth > 1:
                            tags.append("deep-path")
                        if parsed_url.scheme == "https":
                            tags.append("https")
                        else:
                            tags.append("http")

                        finding = create_finding(
                            finding_type="endpoint",
                            target=host,
                            evidence={
                                "url": url,
                                "path": path,
                                "status_code": status_code,
                                "content_length": content_length,
                                "word_count": word_count,
                                "line_count": line_count,
                                "depth": depth,
                                "scheme": parsed_url.scheme,
                                "port": parsed_url.port,
                                "discovered_by": "feroxbuster",
                            },
                            severity=severity,
                            confidence=confidence,
                            tags=tags,
                            raw_ref=line,
                        )
                        findings.append(finding)

            except json.JSONDecodeError:
                continue

    if len(findings) > 100:
        findings = findings[:100]

    return findings


def parse_feroxbuster_result(execution_result: dict) -> dict[str, Any]:
    """Parse feroxbuster execution result and format response with findings."""
    if not execution_result["success"]:
        return {"findings": [], "stats": create_stats(0, 0, 0)}

    findings = []
    stdout = execution_result.get("stdout", "")

    json_findings = parse_feroxbuster_json_output(stdout)
    findings.extend(json_findings)

    seen_urls = set()
    unique_findings = []
    dupes_count = 0

    for finding in findings:
        url = finding["evidence"]["url"]
        if url not in seen_urls:
            seen_urls.add(url)
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
def execute_feroxbuster():
    """Execute Feroxbuster for fast directory scanning."""
    data = request.get_json()
    params = extract_feroxbuster_params(data)

    logger.info(f"Executing Feroxbuster on {params['url']}")

    command = build_feroxbuster_command(params)
    execution_result = execute_command(command, timeout=1800)

    return parse_feroxbuster_result(execution_result)
