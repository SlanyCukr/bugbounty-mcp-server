import logging

from flask import request

from utils.commands import execute_command
from utils.registry import tool

logger = logging.getLogger(__name__)


def _extract_gau_params(data):
    """Extract and validate gau parameters from request data."""
    return {
        "domain": data["domain"],
        "providers": data.get("providers", "wayback,commoncrawl,otx,urlscan"),
        "include_subs": data.get("include_subs", True),
        "blacklist": data.get("blacklist", "png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico"),
        "from_date": data.get("from", ""),
        "to_date": data.get("to", ""),
        "output_file": data.get("output_file", ""),
        "threads": data.get("threads", 5),
        "timeout": data.get("timeout", 60),
        "retries": data.get("retries", 5),
        "proxy": data.get("proxy", ""),
        "random_agent": data.get("random_agent", False),
        "verbose": data.get("verbose", False),
        "additional_args": data.get("additional_args", ""),
        "gau_timeout": data.get("timeout", 300),
    }


def _build_gau_command(params):
    """Build gau command from parameters."""
    command = f"gau {params['domain']}"

    if params["providers"] != "wayback,commoncrawl,otx,urlscan":
        command += f" --providers {params['providers']}"

    if params["include_subs"]:
        command += " --subs"

    if params["blacklist"]:
        command += f" --blacklist {params['blacklist']}"

    if params["from_date"]:
        command += f" --from {params['from_date']}"

    if params["to_date"]:
        command += f" --to {params['to_date']}"

    if params["output_file"]:
        command += f" --output {params['output_file']}"

    if params["threads"] != 5:
        command += f" --threads {params['threads']}"

    if params["timeout"] != 60:
        command += f" --timeout {params['timeout']}"

    if params["retries"] != 5:
        command += f" --retries {params['retries']}"

    if params["proxy"]:
        command += f" --proxy {params['proxy']}"

    if params["random_agent"]:
        command += " --random-agent"

    if params["verbose"]:
        command += " --verbose"

    if params["additional_args"]:
        command += f" {params['additional_args']}"

    return command


def _parse_gau_result(execution_result, params, command):
    """Parse gau execution result and format response."""
    if execution_result.get("success"):
        urls = []
        if execution_result.get("stdout"):
            urls = [
                line.strip()
                for line in execution_result["stdout"].split("\n")
                if line.strip()
            ]

        return {
            "tool": "gau",
            "target": params["domain"],
            "command": command,
            "status": "completed",
            "urls": urls,
            "total_urls": len(urls),
            "providers_used": params["providers"].split(",")
            if params["providers"]
            else [],
            "raw_output": execution_result.get("stdout", ""),
            "error_output": execution_result.get("stderr", ""),
            "return_code": execution_result.get("return_code", 0),
            "execution_time": execution_result.get("execution_time", "unknown"),
            "success": True,
        }
    else:
        return {
            "tool": "gau",
            "target": params["domain"],
            "command": command,
            "status": "failed",
            "error": execution_result.get("error", "Command execution failed"),
            "error_output": execution_result.get("stderr", ""),
            "return_code": execution_result.get("return_code", 1),
            "success": False,
        }


@tool(required_fields=["domain"])
def execute_gau():
    """Execute Gau (Get All URLs) for URL discovery from multiple sources."""
    data = request.get_json()
    params = _extract_gau_params(data)

    logger.info(f"Executing Gau on {params['domain']}")

    command = _build_gau_command(params)
    execution_result = execute_command(command, timeout=params["gau_timeout"])

    return _parse_gau_result(execution_result, params, command)
