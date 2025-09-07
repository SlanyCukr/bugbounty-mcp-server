import logging
import os
import tempfile

from flask import jsonify, request

from utils.commands import execute_command
from utils.registry import tool

logger = logging.getLogger(__name__)


def _extract_httpx_params(data):
    """Extract and validate httpx parameters from request data."""
    targets = data.get("targets", "")
    target_file = data.get("target_file", "")

    if not targets and not target_file:
        return None, "Targets or target_file is required"

    return {
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
        "threads": data.get("threads", 50),
        "timeout": data.get("timeout", 10),
        "follow_redirects": data.get("follow_redirects", False),
        "follow_host_redirects": data.get("follow_host_redirects", False),
        "json": data.get("json", False),
        "ports": data.get("ports", ""),
        "silent": data.get("silent", True),
        "additional_args": data.get("additional_args", ""),
    }, None


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
        cmd_parts.extend(["-mc", params["match_code"]])
    if params["filter_code"]:
        cmd_parts.extend(["-fc", params["filter_code"]])

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

    # Output format
    if params["json"]:
        cmd_parts.append("-json")

    # Ports
    if params["ports"]:
        cmd_parts.extend(["-ports", params["ports"]])

    # Silent mode
    if params["silent"]:
        cmd_parts.append("-silent")

    # Additional arguments
    if params["additional_args"]:
        cmd_parts.extend(params["additional_args"].split())

    return " ".join(cmd_parts), temp_file


def _parse_httpx_result(execution_result, params, command):
    """Parse httpx execution result and format response."""
    return {
        "tool": "httpx",
        "target": params["targets"] or params["target_file"],
        "command": command,
        "success": execution_result["success"],
        "stdout": execution_result.get("stdout", ""),
        "stderr": execution_result.get("stderr", ""),
        "return_code": execution_result.get("return_code", 0),
    }


@tool(required_fields=[])
def execute_httpx():
    """Execute HTTPx for HTTP probing."""
    data = request.get_json()
    params, error = _extract_httpx_params(data)

    if error:
        return jsonify({"error": error}), 400

    logger.info("Executing HTTPx on targets")

    command, temp_file = _build_httpx_command(params)

    try:
        execution_result = execute_command(command, timeout=600)
        return _parse_httpx_result(execution_result, params, command)
    finally:
        # Clean up temporary file if created
        if temp_file and os.path.exists(temp_file):
            try:
                os.unlink(temp_file)
            except Exception:
                pass
