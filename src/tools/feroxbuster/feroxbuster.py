import json
import logging
import re

from flask import request

from utils.commands import execute_command
from utils.registry import tool

logger = logging.getLogger(__name__)


def _extract_feroxbuster_params(data):
    """Extract and validate feroxbuster parameters from request data."""
    return {
        "url": data["url"],
        "wordlist": data.get("wordlist", "/usr/share/wordlists/dirb/common.txt"),
        "threads": data.get("threads", 10),
        "depth": data.get("depth", 4),
        "extensions": data.get("extensions", ""),
        "filter_codes": data.get("filter_codes", "404"),
        "timeout": data.get("timeout", 7),
        "additional_args": data.get("additional_args", ""),
    }


def _build_feroxbuster_command(params):
    """Build feroxbuster command from parameters."""
    cmd_parts = ["feroxbuster", "-u", params["url"], "-w", params["wordlist"]]

    cmd_parts.extend(["-t", str(params["threads"])])
    cmd_parts.extend(["-d", str(params["depth"])])
    cmd_parts.extend(["-T", str(params["timeout"])])

    if params["extensions"]:
        cmd_parts.extend(["-x", params["extensions"]])

    if params["filter_codes"]:
        cmd_parts.extend(["-C", params["filter_codes"]])

    cmd_parts.append("--json")

    if params["additional_args"]:
        cmd_parts.extend(params["additional_args"].split())

    return " ".join(cmd_parts)


def _parse_feroxbuster_result(execution_result, params, command):
    """Parse feroxbuster execution result and format response."""
    if not execution_result["success"]:
        logger.error(
            f"Feroxbuster command failed: {execution_result.get('stderr', 'Unknown error')}"
        )
        return {
            "error": f"Feroxbuster execution failed: {execution_result.get('error', 'Unknown error')}",
            "command": command,
        }

    discovered_resources = []
    scan_statistics = {
        "total_requests": 0,
        "requests_per_second": 0.0,
        "status_code_distribution": {},
        "recursion_depth_reached": 0,
        "wildcards_filtered": 0,
    }

    # Parse JSON output
    for line in execution_result["stdout"].split("\n"):
        if line.strip():
            try:
                result_data = json.loads(line)
                if result_data.get("type") == "response":
                    resource = {
                        "url": result_data.get("url", ""),
                        "status": result_data.get("status", 0),
                        "size": result_data.get("content_length", 0),
                        "words": result_data.get("word_count", 0),
                        "lines": result_data.get("line_count", 0),
                        "depth": len(result_data.get("url", "").rstrip("/").split("/"))
                        - 3
                        if result_data.get("url")
                        else 0,
                    }
                    discovered_resources.append(resource)

                    scan_statistics["total_requests"] += 1
                    status_code = str(result_data.get("status", 0))
                    scan_statistics["status_code_distribution"][status_code] = (
                        scan_statistics["status_code_distribution"].get(status_code, 0)
                        + 1
                    )

                    resource_depth = resource["depth"]
                    if resource_depth > scan_statistics["recursion_depth_reached"]:
                        scan_statistics["recursion_depth_reached"] = resource_depth

                elif result_data.get("type") == "statistics":
                    stats = result_data.get("data", {})
                    scan_statistics["requests_per_second"] = stats.get(
                        "requests_per_second", 0.0
                    )
                    scan_statistics["wildcards_filtered"] = stats.get(
                        "wildcards_filtered", 0
                    )

            except json.JSONDecodeError:
                continue

    # Fallback to plain text parsing if no JSON results
    if not discovered_resources and execution_result["stdout"]:
        logger.info("JSON parsing yielded no results, attempting plain text parsing")
        for line in execution_result["stdout"].split("\n"):
            if line.strip():
                match = re.search(
                    r"(\d{3})\s+\d+l\s+\d+w\s+(\d+)c\s+(https?://[^\s]+)", line
                )
                if match:
                    status_code, size, url_found = match.groups()
                    resource = {
                        "url": url_found,
                        "status": int(status_code),
                        "size": int(size),
                        "words": 0,
                        "lines": 0,
                        "depth": len(url_found.rstrip("/").split("/")) - 3
                        if url_found
                        else 0,
                    }
                    discovered_resources.append(resource)

                    scan_statistics["total_requests"] += 1
                    status_str = str(status_code)
                    scan_statistics["status_code_distribution"][status_str] = (
                        scan_statistics["status_code_distribution"].get(status_str, 0)
                        + 1
                    )

    # Calculate execution time
    execution_time = "0s"
    if execution_result.get("stderr"):
        time_match = re.search(
            r"(?:finished|completed).*?(\d+\.?\d*)\s*(?:second|sec|s)",
            execution_result["stderr"],
            re.IGNORECASE,
        )
        if time_match:
            execution_time = f"{time_match.group(1)}s"

    return {
        "tool": "feroxbuster",
        "target": params["url"],
        "parameters": params,
        "status": "completed" if execution_result["success"] else "failed",
        "discovered_resources": discovered_resources,
        "scan_statistics": scan_statistics,
        "performance_metrics": {
            "avg_response_time": "N/A",
            "max_response_time": "N/A",
            "min_response_time": "N/A",
            "threads_used": params["threads"],
        },
        "execution_time": execution_time,
        "raw_output": execution_result["stdout"]
        if len(execution_result["stdout"]) < 10000
        else execution_result["stdout"][:10000] + "... (truncated)",
    }


@tool(required_fields=["url"])
def execute_feroxbuster():
    """Execute Feroxbuster for fast recursive directory scanning."""
    data = request.get_json()
    params = _extract_feroxbuster_params(data)

    logger.info(f"Executing Feroxbuster on {params['url']}")

    command = _build_feroxbuster_command(params)
    execution_result = execute_command(command, timeout=1800)  # 30 minute timeout

    return _parse_feroxbuster_result(execution_result, params, command)
