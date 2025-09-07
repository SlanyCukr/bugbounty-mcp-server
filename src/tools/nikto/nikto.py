import logging

from flask import request

from utils.commands import execute_command
from utils.registry import tool

logger = logging.getLogger(__name__)


def _extract_nikto_params(data):
    """Extract and validate nikto parameters from request data."""
    return {
        "target": data["target"],
        "port": data.get("port", "80"),
        "ssl": data.get("ssl", False),
        "plugins": data.get("plugins", ""),
        "output_format": data.get("output_format", "txt"),
        "evasion": data.get("evasion", ""),
        "timeout": data.get("timeout", 600),
        "additional_args": data.get("additional_args", ""),
    }


def _build_nikto_command(params):
    """Build nikto command from parameters."""
    cmd_parts = ["nikto", "-h", params["target"]]

    if params["port"] and params["port"] != "80":
        cmd_parts.extend(["-p", str(params["port"])])

    if params["ssl"]:
        cmd_parts.append("-ssl")

    if params["plugins"]:
        cmd_parts.extend(["-Plugins", params["plugins"]])

    if params["output_format"] != "txt":
        cmd_parts.extend(["-Format", params["output_format"]])

    if params["evasion"]:
        cmd_parts.extend(["-evasion", params["evasion"]])

    if params["additional_args"]:
        cmd_parts.extend(params["additional_args"].split())

    return " ".join(cmd_parts)


def _parse_nikto_result(execution_result, params, command):
    """Parse nikto execution result and format response."""
    return {
        "tool": "nikto",
        "target": params["target"],
        "parameters": params,
        "command": command,
        "status": "completed" if execution_result["success"] else "failed",
        "raw_output": execution_result.get("stdout", ""),
        "error_output": execution_result.get("stderr", ""),
        "return_code": execution_result.get("return_code", -1),
        "execution_time": None,
    }


@tool()
def execute_nikto():
    """Execute Nikto web server vulnerability scanner."""
    data = request.get_json()
    params = _extract_nikto_params(data)

    logger.info(f"Executing Nikto scan on {params['target']}")

    command = _build_nikto_command(params)
    execution_result = execute_command(command, params["timeout"])

    return _parse_nikto_result(execution_result, params, command)
