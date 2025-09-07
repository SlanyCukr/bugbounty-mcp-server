import logging

from flask import request

from utils.commands import execute_command
from utils.registry import tool

logger = logging.getLogger(__name__)


def _extract_hakrawler_params(data):
    """Extract and validate hakrawler parameters from request data."""
    url = data["url"]
    depth = data.get("depth", 2)
    forms = data.get("forms", True)
    robots = data.get("robots", True)
    sitemap = data.get("sitemap", True)
    wayback = data.get("wayback", False)
    insecure = data.get("insecure", False)
    additional_args = data.get("additional_args", "")

    return {
        "url": url,
        "depth": depth,
        "forms": forms,
        "robots": robots,
        "sitemap": sitemap,
        "wayback": wayback,
        "insecure": insecure,
        "additional_args": additional_args,
    }


def _build_hakrawler_command(params):
    """Build hakrawler command from parameters."""
    command = f"hakrawler -url {params['url']} -depth {params['depth']}"

    if params["forms"]:
        command += " -forms"
    if params["robots"]:
        command += " -robots"
    if params["sitemap"]:
        command += " -sitemap"
    if params["wayback"]:
        command += " -wayback"
    if params["insecure"]:
        command += " -insecure"

    # Add any additional arguments
    if params["additional_args"]:
        command += f" {params['additional_args']}"

    return command


def _parse_hakrawler_result(execution_result, params, command):
    """Parse hakrawler execution result and format response."""
    return {
        "tool": "hakrawler",
        "target": params["url"],
        "parameters": params,
        "command": command,
        "success": execution_result["success"],
        "stdout": execution_result["stdout"],
        "stderr": execution_result["stderr"],
        "return_code": execution_result["return_code"],
    }


@tool(required_fields=["url"])
def execute_hakrawler():
    """Execute hakrawler for fast web crawling and endpoint discovery."""
    data = request.get_json()
    params = _extract_hakrawler_params(data)

    logger.info(f"Executing hakrawler on {params['url']}")

    command = _build_hakrawler_command(params)
    execution_result = execute_command(command)

    return _parse_hakrawler_result(execution_result, params, command)
