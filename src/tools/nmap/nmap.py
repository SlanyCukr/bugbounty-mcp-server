import logging

from flask import request

from utils.commands import execute_command
from utils.registry import tool

logger = logging.getLogger(__name__)


def _extract_nmap_params(data):
    """Extract and validate nmap parameters from request data."""
    target = data["target"]
    scan_type = data.get("scan_type", "-sV")
    ports = data.get("ports", "")
    additional_args = data.get("additional_args", "-T4")

    return {
        "target": target,
        "scan_type": scan_type,
        "ports": ports,
        "additional_args": additional_args,
    }


def _build_nmap_command(params):
    """Build nmap command from parameters."""
    command = f"nmap {params['scan_type']}"

    if params["ports"]:
        command += f" -p {params['ports']}"

    if params["additional_args"]:
        command += f" {params['additional_args']}"

    command += f" {params['target']}"

    return command


def _parse_nmap_result(execution_result, params, command):
    """Parse nmap execution result and format response."""
    return {
        "tool": "nmap",
        "target": params["target"],
        "parameters": params,
        "command": command,
        "success": execution_result["success"],
        "return_code": execution_result["return_code"],
        "stdout": execution_result["stdout"],
        "stderr": execution_result["stderr"],
    }


@tool()
def execute_nmap():
    """Execute Nmap scan against a target."""
    data = request.get_json()
    params = _extract_nmap_params(data)

    logger.info(f"Executing Nmap scan on {params['target']}")

    command = _build_nmap_command(params)
    execution_result = execute_command(command)

    return _parse_nmap_result(execution_result, params, command)
