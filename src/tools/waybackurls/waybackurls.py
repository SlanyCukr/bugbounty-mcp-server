import logging

from flask import request

from utils.commands import execute_command
from utils.registry import tool

logger = logging.getLogger(__name__)


def _extract_waybackurls_params(data):
    """Extract and validate waybackurls parameters from request data."""
    domain = data["domain"]
    get_versions = data.get("get_versions", False)
    no_subs = data.get("no_subs", False)
    dates = data.get("dates", "")
    output_file = data.get("output_file", "")
    additional_args = data.get("additional_args", "")

    return {
        "domain": domain,
        "get_versions": get_versions,
        "no_subs": no_subs,
        "dates": dates,
        "output_file": output_file,
        "additional_args": additional_args,
    }


def _build_waybackurls_command(params):
    """Build waybackurls command from parameters."""
    command = f"waybackurls {params['domain']}"

    if params["get_versions"]:
        command += " --get-versions"

    if params["no_subs"]:
        command += " --no-subs"

    if params["dates"]:
        command += f" --dates {params['dates']}"

    if params["output_file"]:
        command += f" -o {params['output_file']}"

    if params["additional_args"]:
        command += f" {params['additional_args']}"

    return command


def _parse_waybackurls_result(execution_result, params, command):
    """Parse waybackurls execution result and format response."""
    if execution_result["success"]:
        urls = [
            url.strip() for url in execution_result["stdout"].split("\n") if url.strip()
        ]

        return {
            "tool": "waybackurls",
            "target": params["domain"],
            "parameters": params,
            "status": "completed",
            "urls": urls,
            "unique_urls": len(urls),
            "command": command,
            "success": True,
            "stdout": execution_result["stdout"],
            "stderr": execution_result["stderr"]
            if execution_result["stderr"]
            else None,
        }
    else:
        logger.error(
            f"Waybackurls command failed: {execution_result.get('error', 'Unknown error')}"
        )
        return {
            "tool": "waybackurls",
            "target": params["domain"],
            "parameters": params,
            "command": command,
            "success": False,
            "status": "failed",
            "error": f"Waybackurls execution failed: {execution_result.get('error', execution_result.get('stderr', 'Unknown error'))}",
        }


@tool(required_fields=["domain"])
def execute_waybackurls():
    """Execute Waybackurls for historical URL discovery."""
    data = request.get_json()
    params = _extract_waybackurls_params(data)

    logger.info(f"Executing Waybackurls on {params['domain']}")

    command = _build_waybackurls_command(params)
    execution_result = execute_command(command)

    return _parse_waybackurls_result(execution_result, params, command)
