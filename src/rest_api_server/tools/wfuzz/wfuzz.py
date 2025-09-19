"""wfuzz tool implementation."""

import logging
from datetime import datetime

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import tool

logger = logging.getLogger(__name__)


def _extract_wfuzz_params(data):
    """Extract and validate wfuzz parameters from request data."""
    # Check for aggressive mode
    aggressive = data.get("aggressive", False)

    # Base parameters (customize as needed for each tool)
    base_params = {
        "url": data.get("url", data.get("domain", "")),
        "additional_args": data.get("additional_args", ""),
    }

    # Apply aggressive preset if requested
    # Apply aggressive preset if requested (local implementation)
    if aggressive:
        # Wfuzz aggressive preset
        base_params.update(
            {
                "threads": 100,
                "hide_codes": "404",
                "show_codes": "200,301,302,401,403,500",
                "timeout": 30,
            }
        )
    return base_params


def _build_wfuzz_command(params):
    """Build wfuzz command from parameters."""
    command = f"wfuzz -w {params['wordlist']}"
    command += f" -t {params['threads']}"

    if params["hide_codes"]:
        command += f" --hc {params['hide_codes']}"

    if params["show_codes"]:
        command += f" --sc {params['show_codes']}"

    if params["follow_redirects"]:
        command += " -L"

    if params["additional_args"]:
        command += f" {params['additional_args']}"

    # Handle FUZZ parameter in URL
    url = params["url"]
    if params["fuzz_parameter"] not in url:
        if url.endswith("/"):
            url += params["fuzz_parameter"]
        else:
            url += f"/{params['fuzz_parameter']}"

    command += f" '{url}'"
    return command


def _parse_wfuzz_result(execution_result, params, command):
    """Parse wfuzz execution result and format response."""
    return {
        "tool": "wfuzz",
        "target": params["url"],
        "command": command,
        "parameters": params,
        "execution": {
            "success": execution_result["success"],
            "return_code": execution_result["return_code"],
            "stdout": execution_result["stdout"],
            "stderr": execution_result["stderr"],
        },
        "timestamp": datetime.now().isoformat(),
    }


@tool(required_fields=["url"])
def execute_wfuzz():
    """Execute Wfuzz for web application fuzzing."""
    data = request.get_json()
    params = _extract_wfuzz_params(data)

    logger.info(f"Executing Wfuzz on {params['url']}")

    command = _build_wfuzz_command(params)
    logger.info(f"Wfuzz command: {command}")

    execution_result = execute_command(command, timeout=params["timeout"])

    return _parse_wfuzz_result(execution_result, params, command)
