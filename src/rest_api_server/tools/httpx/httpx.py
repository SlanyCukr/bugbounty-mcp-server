"""httpx tool implementation."""

import json
import logging
import os
import tempfile
from datetime import datetime
from typing import Any, cast
from urllib.parse import urlparse

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.confidence_mapping import map_finding_confidence
from src.rest_api_server.utils.deduplication import deduplicate_findings
from src.rest_api_server.utils.registry import (
    ConfidenceLevel,
    SeverityLevel,
    create_finding,
    tool,
)
from src.rest_api_server.utils.severity_mapping import map_finding_severity

logger = logging.getLogger(__name__)

# Aggressive preset for httpx
AGGRESSIVE_PRESET = {
    "ports": (
        "80,443,8080,8443,8000,8001,8002,8003,8004,8005,8006,8007,8008,8009,8010,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,9000,9001,9002,9003,9004,9005,9090,9443,10443"
    ),
    "status_code": True,
    "content_length": True,
    "title": True,
    "tech_detect": True,
    "web_server": True,
    "location": True,
    "response_time": True,
    "follow_redirects": True,
    "follow_host_redirects": True,
    "threads": 100,
    "timeout": 10,
    "additional_args": (
        "-path /.git/HEAD -path /.env -path /backup.zip -path /backup.tar.gz "
        "-path /backup.sql -path /config.php -path /admin -path /wp-admin "
        "-path /phpmyadmin"
    ),
}


def _apply_aggressive_preset(user_params: dict, aggressive: bool = False) -> dict:
    """Apply aggressive preset to user parameters if aggressive=True."""
    if not aggressive:
        return user_params

    # Start with user params and apply aggressive preset
    merged_params = user_params.copy()

    # Apply aggressive preset for parameters not explicitly set by user
    for key, aggressive_value in AGGRESSIVE_PRESET.items():
        if key not in user_params:
            merged_params[key] = aggressive_value
        else:
            # For certain key parameters, use aggressive values if user set defaults
            if key in [
                "threads",
                "ports",
                "status_code",
                "content_length",
                "tech_detect",
                "web_server",
                "location",
                "response_time",
                "follow_redirects",
                "follow_host_redirects",
            ] and user_params.get(key) in [50, "", False, None]:
                merged_params[key] = aggressive_value

    return merged_params


def _extract_httpx_params(data):
    """Extract httpx parameters from request data."""
    # Check for aggressive mode
    aggressive = data.get("aggressive", False)

    targets = data.get("targets", "")
    target_file = data.get("target_file", "")
    threads = data.get("threads", 50)
    timeout = data.get("timeout", 10)
    additional_args = data.get("additional_args", "")

    base_params = {
        "targets": targets,
        "target_file": target_file,
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
        "threads": threads,
        "timeout": timeout,
        "follow_redirects": data.get("follow_redirects", False),
        "follow_host_redirects": data.get("follow_host_redirects", False),
        "json": data.get("json", False),
        "ports": data.get("ports", ""),
        "silent": data.get("silent", True),
        "additional_args": additional_args,
    }

    # Apply aggressive preset if requested
    return _apply_aggressive_preset(base_params, aggressive)


def _build_httpx_command(params):
    """Build httpx command from parameters and handle temp files."""
    cmd_parts = ["httpx"]
    temp_file = None

    # Handle targets - either from direct input or file
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
            cmd_parts.extend(["-l", temp_file])
        except Exception:
            os.close(temp_fd)
            if os.path.exists(temp_file):
                os.unlink(temp_file)
            raise
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

    return " ".join(cmd_parts), temp_file


def _extract_tech_stack(tech_string: str) -> list[str]:
    """Extract technology stack from httpx tech-detect string."""
    if not tech_string:
        return []

    # Split by common separators and clean up
    techs = []
    for tech in tech_string.replace(",", "|").split("|"):
        tech = tech.strip()
        if tech:
            techs.append(tech)

    return techs


def _parse_httpx_json_output(stdout: str) -> list[dict[str, Any]]:
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

                # Process technology detection
                if isinstance(tech_detect, str):
                    techs = _extract_tech_stack(tech_detect)
                elif isinstance(tech_detect, list):
                    techs = tech_detect
                else:
                    techs = []

                # Add web server to tech stack if available
                if web_server and web_server not in techs:
                    techs.append(web_server)

                # Map severity using utility
                severity_info = {
                    "tool": "httpx",
                    "status_code": status_code,
                    "technologies": techs,
                    "title": title,
                }
                severity = map_finding_severity(severity_info)

                # Map confidence using utility
                confidence_info = {
                    "tool": "httpx",
                    "status_code": status_code,
                    "has_response": status_code > 0,
                    "response_time": response_time,
                }
                confidence = map_finding_confidence(confidence_info)

                # Build tags
                tags = ["endpoint", "http"]
                if status_code:
                    tags.append(f"status-{status_code}")
                if techs:
                    tags.extend(techs)
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
                    severity=cast(SeverityLevel, severity),
                    confidence=cast(ConfidenceLevel, confidence),
                    tags=tags,
                    raw_ref=line,
                )
                findings.append(finding)

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse httpx JSON line: {line} - {e}")
            continue

    return findings


def _parse_httpx_result(
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
    findings = _parse_httpx_json_output(stdout)

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
    params = _extract_httpx_params(data)

    logger.info("Executing HTTPx on targets")

    started_at = datetime.now()
    command, temp_file = _build_httpx_command(params)

    try:
        execution_result = execute_command(command, timeout=600)
        ended_at = datetime.now()
        return _parse_httpx_result(
            execution_result, params, command, started_at, ended_at
        )
    finally:
        # Clean up temporary file if created
        if temp_file and os.path.exists(temp_file):
            try:
                os.unlink(temp_file)
            except Exception:
                pass
