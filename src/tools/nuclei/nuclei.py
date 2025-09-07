import logging

from flask import request

from utils.commands import execute_command
from utils.registry import tool

logger = logging.getLogger(__name__)


def _extract_nuclei_params(data):
    """Extract and validate nuclei parameters from request data."""
    return {
        "target": data["target"],
        "severity": data.get("severity"),
        "tags": data.get("tags"),
        "template": data.get("template"),
        "template_id": data.get("template_id"),
        "exclude_id": data.get("exclude_id"),
        "exclude_tags": data.get("exclude_tags"),
        "concurrency": data.get("concurrency", 25),
        "timeout": data.get("timeout"),
        "additional_args": data.get("additional_args"),
    }


def _build_nuclei_command(params):
    """Build nuclei command from parameters."""
    cmd_parts = ["nuclei", "-u", params["target"]]

    if params["severity"]:
        cmd_parts.extend(["-severity", params["severity"]])
    if params["tags"]:
        cmd_parts.extend(["-tags", params["tags"]])
    if params["template"]:
        cmd_parts.extend(["-t", params["template"]])
    if params["template_id"]:
        cmd_parts.extend(["-template-id", params["template_id"]])
    if params["exclude_id"]:
        cmd_parts.extend(["-exclude-id", params["exclude_id"]])
    if params["exclude_tags"]:
        cmd_parts.extend(["-exclude-tags", params["exclude_tags"]])
    if params["concurrency"] != 25:
        cmd_parts.extend(["-c", str(params["concurrency"])])
    if params["timeout"]:
        cmd_parts.extend(["-timeout", str(params["timeout"])])
    if params["additional_args"]:
        cmd_parts.extend(params["additional_args"].split())

    cmd_parts.extend(["-jsonl"])

    return " ".join(cmd_parts)


def _parse_nuclei_result(execution_result, params, command):
    """Parse nuclei execution result and format response."""
    return {
        "tool": "nuclei",
        "target": params["target"],
        "command": command,
        "success": execution_result["success"],
        "stdout": execution_result.get("stdout", ""),
        "stderr": execution_result.get("stderr", ""),
        "return_code": execution_result.get("return_code", 0),
    }


@tool()
def execute_nuclei():
    """Execute Nuclei vulnerability scanner."""
    data = request.get_json()
    params = _extract_nuclei_params(data)

    logger.info(f"Executing Nuclei scan on {params['target']}")

    command = _build_nuclei_command(params)
    execution_result = execute_command(command, timeout=600)

    return _parse_nuclei_result(execution_result, params, command)
