import logging

from flask import request

from utils.commands import execute_command
from utils.registry import tool

logger = logging.getLogger(__name__)


def _extract_dalfox_params(data):
    """Extract and validate dalfox parameters from request data."""
    url = data["url"]
    pipe_mode = data.get("pipe_mode", False)
    blind = data.get("blind", False)
    mining_dom = data.get("mining_dom", True)
    mining_dict = data.get("mining_dict", True)
    custom_payload = data.get("custom_payload", "")
    workers = data.get("workers", 100)
    method = data.get("method", "GET")
    headers = data.get("headers", "")
    cookies = data.get("cookies", "")
    timeout = data.get("timeout", 10)
    additional_args = data.get("additional_args", "")

    return {
        "url": url,
        "pipe_mode": pipe_mode,
        "blind": blind,
        "mining_dom": mining_dom,
        "mining_dict": mining_dict,
        "custom_payload": custom_payload,
        "workers": workers,
        "method": method,
        "headers": headers,
        "cookies": cookies,
        "timeout": timeout,
        "additional_args": additional_args,
    }


def _build_dalfox_command(params):
    """Build dalfox command from parameters."""
    # Build dalfox command
    if params["pipe_mode"]:
        command = "dalfox pipe"
    else:
        command = f"dalfox url {params['url']}"

    # Add dalfox-specific parameters
    if params["blind"]:
        command += " --blind"

    if params["mining_dom"]:
        command += " --mining-dom"

    if params["mining_dict"]:
        command += " --mining-dict"

    if params["custom_payload"]:
        command += f" --custom-payload '{params['custom_payload']}'"

    if params["workers"] != 100:
        command += f" --worker {params['workers']}"

    if params["method"] != "GET":
        command += f" --method {params['method']}"

    if params["headers"]:
        command += f" --header '{params['headers']}'"

    if params["cookies"]:
        command += f" --cookie '{params['cookies']}'"

    if params["timeout"] != 10:
        command += f" --timeout {params['timeout']}"

    if params["additional_args"]:
        command += f" {params['additional_args']}"

    return command


def _parse_dalfox_result(execution_result, params, command):
    """Parse dalfox execution result and format response."""
    return {
        "tool": "dalfox",
        "target": params["url"],
        "command": command,
        "success": execution_result["success"],
        "stdout": execution_result.get("stdout", ""),
        "stderr": execution_result.get("stderr", ""),
        "return_code": execution_result.get("return_code", 0),
        "parameters": {
            "url": params["url"],
            "pipe_mode": params["pipe_mode"],
            "blind": params["blind"],
            "mining_dom": params["mining_dom"],
            "mining_dict": params["mining_dict"],
            "custom_payload": params["custom_payload"],
            "workers": params["workers"],
            "method": params["method"],
            "headers": params["headers"],
            "cookies": params["cookies"],
            "timeout": params["timeout"],
            "additional_args": params["additional_args"],
        },
    }


@tool(required_fields=["url"])
def execute_dalfox():
    """Execute Dalfox for XSS vulnerability scanning."""
    data = request.get_json()
    params = _extract_dalfox_params(data)

    logger.info(f"Executing Dalfox XSS scan on {params['url']}")

    command = _build_dalfox_command(params)
    execution_result = execute_command(
        command, timeout=600
    )  # 10 minutes timeout for XSS scanning

    logger.info(f"Dalfox XSS scan completed for {params['url']}")
    return _parse_dalfox_result(execution_result, params, command)
