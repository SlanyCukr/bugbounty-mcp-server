"""httpx tool implementation."""

import json
import logging
import os
import tempfile
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.deduplication import deduplicate_findings
from src.rest_api_server.utils.registry import (
    create_finding,
    tool,
)

logger = logging.getLogger(__name__)


def extract_httpx_params(data):
    """Extract httpx parameters from request data."""
    return {
        "targets": data.get("targets", ""),
        "target_file": data.get("target_file", ""),
        "status_code": data.get("status_code", False) or data.get("sc", False),
        "content_length": data.get("content_length", False) or data.get("cl", False),
        "title": data.get("title", True),
        "tech_detect": data.get("tech_detect", False) or data.get("tech", False),
        "web_server": data.get("web_server", False) or data.get("server", False),
        "location": data.get("location", False),
        "response_time": data.get("response_time", False) or data.get("rt", False),
        "method": data.get("method", ""),
        "methods": data.get("methods", ""),
        "match_code": data.get("match_code", "") or data.get("mc", ""),
        "filter_code": data.get("filter_code", "") or data.get("fc", ""),
        "threads": data.get("threads", 50),
        "timeout": data.get("timeout", 10),
        "follow_redirects": data.get("follow_redirects", False),
        "follow_host_redirects": data.get("follow_host_redirects", False),
        "json": data.get("json", False),
        "ports": data.get("ports", ""),
        "silent": data.get("silent", True),
        "additional_args": data.get("additional_args", ""),
    }


def build_httpx_command(params):
    """Build httpx command from parameters."""
    cmd_parts = ["httpx"]

    # Handle targets - either from direct input or file
    if params["targets"]:
        cmd_parts.extend(["-l", params["targets"]])
    elif params["target_file"]:
        cmd_parts.extend(["-l", params["target_file"]])

    # Add common httpx parameters
    if params["status_code"]:
        cmd_parts.append("-sc")
    if params["content_length"]:
        cmd_parts.append("-cl")
    if params["title"]:
        cmd_parts.append("-title")
    if params["tech_detect"]:
        cmd_parts.append("-tech-detect")
    if params["web_server"]:
        cmd_parts.append("-server")
    if params["location"]:
        cmd_parts.append("-location")
    if params["response_time"]:
        cmd_parts.append("-rt")
    if params["method"] and params["method"] != "GET":
        cmd_parts.extend(["-X", params["method"]])
    if params["methods"] and params["methods"] != "GET":
        cmd_parts.extend(["-X", params["methods"]])

    # Match codes (mc) and filter codes (fc)
    if params["match_code"]:
        cmd_parts.extend(["-mc", str(params["match_code"])])
    if params["filter_code"]:
        cmd_parts.extend(["-fc", str(params["filter_code"])])

    # Threads
    if params["threads"] != 50:
        cmd_parts.extend(["-threads", str(params["threads"])])

    # Timeout
    if params["timeout"] != 10:
        cmd_parts.extend(["-timeout", str(params["timeout"])])

    # Follow redirects
    if params["follow_redirects"]:
        cmd_parts.append("-follow-redirects")
    if params["follow_host_redirects"]:
        cmd_parts.append("-follow-host-redirects")

    # Always use JSON output for structured parsing
    cmd_parts.append("-json")

    # Ports
    if params["ports"]:
        cmd_parts.extend(["-ports", str(params["ports"])])

    # Silent mode
    if params["silent"]:
        cmd_parts.append("-silent")

    # Additional arguments
    if params["additional_args"]:
        cmd_parts.extend(params["additional_args"].split())

    return cmd_parts


def prepare_httpx_targets(params):
    """Prepare target file for httpx execution and return command with temp file."""
    temp_file = None
    command_parts = build_httpx_command(params)

    # Handle targets - create temporary file if needed
    if params["targets"]:
        # For direct targets, create a temporary file
        if isinstance(params["targets"], list):
            targets_content = "\n".join(params["targets"])
        else:
            # Handle multiple targets separated by newlines or commas
            targets_content = params["targets"].replace(",", "\n")

        # Create temporary file
        temp_fd, temp_file = tempfile.mkstemp(suffix=".txt", prefix="httpx_targets_")
        try:
            with os.fdopen(temp_fd, "w") as f:
                f.write(targets_content)

            # Replace the targets placeholder with the temp file
            for i, part in enumerate(command_parts):
                if part == "-l" and i + 1 < len(command_parts):
                    command_parts[i + 1] = temp_file
                    break
        except Exception:
            os.close(temp_fd)
            if os.path.exists(temp_file):
                os.unlink(temp_file)
            raise

    return " ".join(command_parts), temp_file


def parse_httpx_output(stdout: str) -> list[dict[str, Any]]:
    """Parse httpx JSON output into structured findings."""
    findings = []

    if not stdout.strip():
        return findings

    for line in stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue

        try:
            # Each line should be a JSON object
            result = json.loads(line)

            # Extract endpoint information
            url = result.get("url", "")
            status_code = result.get("status_code", 0)
            content_length = result.get("content_length", 0)
            title = result.get("title", "")
            tech_detect = result.get("tech", [])
            web_server = result.get("webserver", "")
            response_time = result.get("response_time", "")
            location = result.get("location", "")

            if url:
                parsed_url = urlparse(url)
                host = parsed_url.netloc

                # Simple technology processing - use directly
                techs = tech_detect if isinstance(tech_detect, list) else []
                if web_server and web_server not in techs:
                    techs.append(web_server)

                # Simple tags
                tags = ["endpoint", "http", "httpx"]
                if status_code:
                    tags.append(f"status-{status_code}")
                if parsed_url.scheme == "https":
                    tags.append("https")
                else:
                    tags.append("http")

                finding = create_finding(
                    finding_type="endpoint",
                    target=host,
                    evidence={
                        "url": url,
                        "status_code": status_code,
                        "content_length": content_length,
                        "title": title,
                        "technologies": techs,
                        "web_server": web_server,
                        "response_time": response_time,
                        "location": location,
                        "scheme": parsed_url.scheme,
                        "port": parsed_url.port,
                        "path": parsed_url.path,
                        "discovered_by": "httpx",
                    },
                    severity="info",
                    confidence="medium",
                    tags=tags,
                    raw_ref=line,
                )
                findings.append(finding)

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse httpx JSON line: {line} - {e}")
            continue

    return findings


def parse_httpx_result(
    execution_result, params, command, started_at: datetime, ended_at: datetime
) -> dict[str, Any]:
    """Parse httpx execution result and format response with findings."""
    duration_ms = int((ended_at - started_at).total_seconds() * 1000)

    if not execution_result["success"]:
        return {
            "success": False,
            "tool": "httpx",
            "params": params,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "duration_ms": duration_ms,
            "error": execution_result.get("error", "Command execution failed"),
            "findings": [],
            "stats": {"findings": 0, "dupes": 0, "payload_bytes": 0},
        }

    # Parse JSON output into structured findings
    stdout = execution_result.get("stdout", "")
    findings = parse_httpx_output(stdout)

    # Use standardized deduplication
    unique_findings = deduplicate_findings(findings)
    dupes_count = len(findings) - len(unique_findings)

    payload_bytes = len(stdout.encode("utf-8"))

    return {
        "success": True,
        "tool": "httpx",
        "params": params,
        "started_at": started_at.isoformat(),
        "ended_at": ended_at.isoformat(),
        "duration_ms": duration_ms,
        "findings": unique_findings,
        "stats": {
            "findings": len(unique_findings),
            "dupes": dupes_count,
            "payload_bytes": payload_bytes,
        },
    }


@tool(required_fields=[])
def execute_httpx():
    """Execute HTTPx for HTTP probing."""
    data = request.get_json()
    params = extract_httpx_params(data)

    logger.info("Executing HTTPx on targets")

    started_at = datetime.now()
    command, temp_file = prepare_httpx_targets(params)

    try:
        execution_result = execute_command(command, timeout=600)
        ended_at = datetime.now()
        return parse_httpx_result(
            execution_result, params, command, started_at, ended_at
        )
    finally:
        # Clean up temporary file if created
        if temp_file and os.path.exists(temp_file):
            try:
                os.unlink(temp_file)
            except Exception:
                pass
