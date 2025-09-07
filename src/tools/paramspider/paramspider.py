import logging

from flask import request

from utils.commands import execute_command
from utils.registry import tool

logger = logging.getLogger(__name__)


def _extract_paramspider_params(data):
    """Extract and validate paramspider parameters from request data."""
    domain = data["domain"]
    stream = data.get("stream", False)
    placeholder = data.get("placeholder", "FUZZ")
    proxy = data.get("proxy", "")
    additional_args = data.get("additional_args", "")
    exclude = data.get("exclude", "png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico")
    output = data.get("output", "")
    level = data.get("level", 2)
    subs = data.get("subs", True)
    silent = data.get("silent", False)
    clean = data.get("clean", False)

    return {
        "domain": domain,
        "stream": stream,
        "placeholder": placeholder,
        "proxy": proxy,
        "additional_args": additional_args,
        "exclude": exclude,
        "output": output,
        "level": level,
        "subs": subs,
        "silent": silent,
        "clean": clean,
    }


def _build_paramspider_command(params):
    """Build paramspider command from parameters."""
    # Build paramspider command (paramspider only supports: -d, -l, -s, --proxy, -p)
    cmd_parts = ["paramspider", "-d", params["domain"]]

    # Add stream mode (-s flag)
    if params["stream"]:
        cmd_parts.append("-s")

    # Add placeholder for parameter values
    if params["placeholder"] and params["placeholder"] != "FUZZ":
        cmd_parts.extend(["-p", params["placeholder"]])

    # Add proxy if specified
    if params["proxy"]:
        cmd_parts.extend(["--proxy", params["proxy"]])

    # Add any additional arguments
    if params["additional_args"]:
        cmd_parts.extend(params["additional_args"].split())

    return " ".join(cmd_parts)


def _parse_paramspider_result(execution_result, params, command):
    """Parse paramspider execution result and format response."""
    return {
        "tool": "paramspider",
        "target": params["domain"],
        "command": command,
        "success": execution_result.get("success", False),
        "return_code": execution_result.get("return_code", 1),
        "stdout": execution_result.get("stdout", ""),
        "stderr": execution_result.get("stderr", ""),
        "error": execution_result.get("error", ""),
        "parameters": {
            "domain": params["domain"],
            "stream": params["stream"],
            "placeholder": params["placeholder"],
            "proxy": params["proxy"],
            "additional_args": params["additional_args"],
            # Note: These parameters are ignored by paramspider but kept for compatibility
            "exclude": params["exclude"],
            "output": params["output"],
            "level": params["level"],
            "subs": params["subs"],
            "silent": params["silent"],
            "clean": params["clean"],
        },
    }


@tool(required_fields=["domain"])
def execute_paramspider():
    """Execute ParamSpider for parameter mining from web archives."""
    data = request.get_json()
    params = _extract_paramspider_params(data)

    logger.info(f"Executing ParamSpider on {params['domain']}")

    command = _build_paramspider_command(params)
    logger.info(f"Executing command: {command}")

    execution_result = execute_command(
        command, timeout=600
    )  # 10 minutes timeout for paramspider

    return _parse_paramspider_result(execution_result, params, command)
