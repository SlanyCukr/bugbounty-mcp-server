"""jaeles tool implementation."""

import logging

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import tool

logger = logging.getLogger(__name__)


def _extract_jaeles_params(data):
    """Extract and validate jaeles parameters from request data."""
    url = data["url"]
    signatures = data.get("signatures", "")
    config = data.get("config", "")
    threads = data.get("threads", 20)
    timeout = data.get("timeout", 20)
    level = data.get("level", "")
    passive = data.get("passive", False)
    output_file = data.get("output_file", "")
    proxy = data.get("proxy", "")
    headers = data.get("headers", "")
    verbose = data.get("verbose", False)
    debug = data.get("debug", False)
    additional_args = data.get("additional_args", "")

    return {
        "url": url,
        "signatures": signatures,
        "config": config,
        "threads": threads,
        "timeout": timeout,
        "level": level,
        "passive": passive,
        "output_file": output_file,
        "proxy": proxy,
        "headers": headers,
        "verbose": verbose,
        "debug": debug,
        "additional_args": additional_args,
    }


def _build_jaeles_command(params):
    """Build jaeles command from parameters."""
    # Build jaeles command
    command = f"jaeles scan -u {params['url']}"

    # Add concurrency/threads parameter
    command += f" -c {params['threads']}"

    # Add timeout parameter
    command += f" --timeout {params['timeout']}"

    # Add signatures parameter if provided
    if params["signatures"]:
        command += f" -s {params['signatures']}"

    # Add config parameter if provided
    if params["config"]:
        command += f" --config {params['config']}"

    # Add level parameter if provided
    if params["level"]:
        command += f" --level {params['level']}"

    # Add passive scanning option
    if params["passive"]:
        command += " --passive"

    # Add output file if provided
    if params["output_file"]:
        command += f" -o {params['output_file']}"

    # Add proxy if provided
    if params["proxy"]:
        command += f" --proxy {params['proxy']}"

    # Add headers if provided
    if params["headers"]:
        command += f" -H '{params['headers']}'"

    # Add verbose flag
    if params["verbose"]:
        command += " -v"

    # Add debug flag
    if params["debug"]:
        command += " --debug"

    # Add any additional arguments
    if params["additional_args"]:
        command += f" {params['additional_args']}"

    return command


def _parse_jaeles_result(execution_result, params, command):
    """Parse jaeles execution result and format response."""
    # Limit output size to prevent token overflow
    result = execution_result.copy()
    if result.get("stdout") and len(result["stdout"]) > 20000:
        truncated_output = (
            result["stdout"][:20000]
            + "\n\n[OUTPUT TRUNCATED - Results too large for response]"
        )
        result["stdout"] = truncated_output
        result["truncated"] = True
        logger.warning("Jaeles output truncated due to size limits")

    # Add metadata to result
    result["tool"] = "jaeles"
    result["target"] = params["url"]
    result["parameters"] = params
    result["command"] = command

    return result


@tool(required_fields=["url"])
def execute_jaeles():
    """Execute Jaeles for advanced vulnerability scanning with custom signatures."""
    data = request.get_json()
    params = _extract_jaeles_params(data)

    logger.info(f"Executing Jaeles on {params['url']}")

    command = _build_jaeles_command(params)
    execution_result = execute_command(command, timeout=params["timeout"] + 30)

    return _parse_jaeles_result(execution_result, params, command)
