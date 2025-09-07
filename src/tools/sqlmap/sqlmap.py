import logging

from flask import request

from utils.commands import execute_command
from utils.registry import tool

logger = logging.getLogger(__name__)


def _extract_sqlmap_params(data):
    """Extract and validate sqlmap parameters from request data."""
    return {
        "url": data["url"],
        "data": data.get("data"),
        "level": data.get("level", 1),
        "risk": data.get("risk", 1),
        "technique": data.get("technique"),
        "dbms": data.get("dbms"),
        "additional_args": data.get("additional_args"),
    }


def _build_sqlmap_command(params):
    """Build sqlmap command from parameters."""
    cmd_parts = ["sqlmap", "-u", params["url"]]

    if params["data"]:
        cmd_parts.extend(["--data", params["data"]])
    if params["level"] != 1:
        cmd_parts.extend(["--level", str(params["level"])])
    if params["risk"] != 1:
        cmd_parts.extend(["--risk", str(params["risk"])])
    if params["technique"]:
        cmd_parts.extend(["--technique", params["technique"]])
    if params["dbms"]:
        cmd_parts.extend(["--dbms", params["dbms"]])
    if params["additional_args"]:
        cmd_parts.extend(params["additional_args"].split())

    cmd_parts.extend(["--batch"])

    return " ".join(cmd_parts)


def _parse_sqlmap_result(execution_result, params, command):
    """Parse sqlmap execution result and format response."""
    return {
        "tool": "sqlmap",
        "target": params["url"],
        "command": command,
        "success": execution_result["success"],
        "stdout": execution_result.get("stdout", ""),
        "stderr": execution_result.get("stderr", ""),
        "return_code": execution_result.get("return_code", 0),
    }


@tool(required_fields=["url"])
def execute_sqlmap():
    """Execute SQLMap for SQL injection testing."""
    data = request.get_json()
    params = _extract_sqlmap_params(data)

    logger.info(f"Executing SQLMap on {params['url']}")

    command = _build_sqlmap_command(params)
    execution_result = execute_command(command, timeout=900)

    return _parse_sqlmap_result(execution_result, params, command)
