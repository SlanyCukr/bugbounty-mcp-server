"""wafw00f tool implementation."""

import logging
from datetime import datetime

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import tool

logger = logging.getLogger(__name__)


def _extract_wafw00f_params(data):
    """Extract and validate wafw00f parameters from request data."""
    target = data["target"]
    findall = data.get("findall", False)
    verbose = data.get("verbose", False)
    proxy = data.get("proxy", "")
    headers = data.get("headers", "")
    output_file = data.get("output_file", "")
    additional_args = data.get("additional_args", "")

    return {
        "target": target,
        "findall": findall,
        "verbose": verbose,
        "proxy": proxy,
        "headers": headers,
        "output_file": output_file,
        "additional_args": additional_args,
    }


def _build_wafw00f_command(params):
    """Build wafw00f command from parameters."""
    command = f"wafw00f {params['target']}"

    # Add optional parameters
    if params["findall"]:
        command += " -a"

    if params["verbose"]:
        command += " -v"

    if params["proxy"]:
        command += f" --proxy {params['proxy']}"

    if params["headers"]:
        command += f" --headers '{params['headers']}'"

    if params["output_file"]:
        command += f" -o {params['output_file']}"

    if params["additional_args"]:
        command += f" {params['additional_args']}"

    return command


def _parse_wafw00f_result(execution_result, params, command):
    """Parse wafw00f execution result and format response."""
    result = execution_result.copy()
    result["tool"] = "wafw00f"
    result["target"] = params["target"]
    result["parameters"] = params
    result["command"] = command
    result["timestamp"] = datetime.now().isoformat()

    return result


@tool()
def execute_wafw00f():
    """Execute wafw00f to identify Web Application Firewall (WAF) protection."""
    data = request.get_json()
    params = _extract_wafw00f_params(data)

    logger.info(f"Executing wafw00f on {params['target']}")

    command = _build_wafw00f_command(params)
    execution_result = execute_command(command, timeout=120)

    return _parse_wafw00f_result(execution_result, params, command)
