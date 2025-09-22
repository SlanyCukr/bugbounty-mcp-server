"""katana tool implementation."""

import re
from datetime import datetime
from typing import Any

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import tool


def extract_katana_params(data: dict) -> dict:
    """Extract and organize katana parameters from request data."""
    return {
        "url": data["url"],
        "depth": data.get("depth", 3),
        "concurrency": data.get("concurrency", 10),
        "parallelism": data.get("parallelism", 10),
        "max_pages": data.get("max_pages", 100),
        "crawl_duration": data.get("crawl_duration", 0),
        "delay": data.get("delay", 0),
        "timeout": data.get("timeout", 10),
        "retry": data.get("retry", 1),
        "retry_wait": data.get("retry_wait", 1),
        "js_crawl": data.get("js_crawl", True),
        "form_extraction": data.get("form_extraction", True),
        "no_scope": data.get("no_scope", False),
        "display_out_scope": data.get("display_out_scope", False),
        "store_response": data.get("store_response", False),
        "system_chrome": data.get("system_chrome", False),
        "headless": data.get("headless", True),
        "no_incognito": data.get("no_incognito", False),
        "show_source": data.get("show_source", False),
        "show_browser": data.get("show_browser", False),
        "output_format": data.get("output_format", "json"),
        "output_file": data.get("output_file", ""),
        "store_response_dir": data.get("store_response_dir", ""),
        "chrome_data_dir": data.get("chrome_data_dir", ""),
        "scope": data.get("scope", ""),
        "out_of_scope": data.get("out_of_scope", ""),
        "field_scope": data.get("field_scope", ""),
        "crawl_scope": data.get("crawl_scope", ""),
        "filter_regex": data.get("filter_regex", ""),
        "match_regex": data.get("match_regex", ""),
        "extension_filter": data.get("extension_filter", ""),
        "mime_filter": data.get("mime_filter", ""),
        "headers": data.get("headers", ""),
        "cookies": data.get("cookies", ""),
        "user_agent": data.get("user_agent", ""),
        "proxy": data.get("proxy", ""),
        "additional_args": data.get("additional_args", ""),
    }


def build_katana_command(params: dict) -> list[str]:
    """Build the katana command from parameters."""
    args = ["katana", "-u", params["url"]]

    # Core crawling parameters
    if params["depth"] != 3:
        args.extend(["-d", str(params["depth"])])
    if params["concurrency"] != 10:
        args.extend(["-c", str(params["concurrency"])])
    if params["parallelism"] != 10:
        args.extend(["-p", str(params["parallelism"])])

    # Crawling behavior
    if params["max_pages"] > 0:
        args.extend(["-kf", str(params["max_pages"])])
    if params["crawl_duration"] > 0:
        args.extend(["-ct", str(params["crawl_duration"])])
    if params["delay"] > 0:
        args.extend(["-delay", str(params["delay"])])

    # JavaScript crawling
    if params["js_crawl"]:
        args.append("-jc")

    # Form extraction
    if params["form_extraction"]:
        args.append("-fx")

    # Scope control
    if params["scope"]:
        args.extend(["-cs", params["scope"]])
    if params["out_of_scope"]:
        args.extend(["-cos", params["out_of_scope"]])
    if params["field_scope"]:
        args.extend(["-fs", params["field_scope"]])
    if params["no_scope"]:
        args.append("-ns")
    if params["display_out_scope"]:
        args.append("-do")

    # Authentication and headers
    if params["headers"]:
        args.extend(["-H", params["headers"]])
    if params["cookies"]:
        args.extend(["-cookie", params["cookies"]])
    if params["user_agent"]:
        args.extend(["-ua", params["user_agent"]])

    # Proxy settings
    if params["proxy"]:
        args.extend(["-proxy", params["proxy"]])

    # Chrome options
    if params["system_chrome"]:
        args.append("-sc")
    if not params["headless"]:
        args.append("-xhr")
    if params["no_incognito"]:
        args.append("-ni")
    if params["chrome_data_dir"]:
        args.extend(["-cdd", params["chrome_data_dir"]])
    if params["show_source"]:
        args.append("-sr")
    if params["show_browser"]:
        args.append("-sb")

    # Timeout and retry settings
    if params["timeout"] != 10:
        args.extend(["-timeout", str(params["timeout"])])
    if params["retry"] != 1:
        args.extend(["-retry", str(params["retry"])])
    if params["retry_wait"] != 1:
        args.extend(["-rw", str(params["retry_wait"])])

    # Output format
    if params["output_format"] == "json":
        args.append("-jsonl")

    # Filtering
    if params["filter_regex"]:
        args.extend(["-fr", params["filter_regex"]])
    if params["match_regex"]:
        args.extend(["-mr", params["match_regex"]])
    if params["extension_filter"]:
        args.extend(["-ef", params["extension_filter"]])
    if params["mime_filter"]:
        args.extend(["-mf", params["mime_filter"]])

    # Output file
    if params["output_file"]:
        args.extend(["-o", params["output_file"]])

    # Store response
    if params["store_response"]:
        args.append("-sr")
    if params["store_response_dir"]:
        args.extend(["-srd", params["store_response_dir"]])

    # Additional args
    if params["additional_args"]:
        args.extend(params["additional_args"].split())

    return args


def parse_katana_output(
    execution_result: dict[str, Any],
    params: dict,
    command: list[str],
    started_at: datetime,
    ended_at: datetime,
) -> dict[str, Any]:
    """Parse katana execution results into structured findings."""
    duration_ms = int((ended_at - started_at).total_seconds() * 1000)

    if not execution_result["success"]:
        return {
            "success": False,
            "tool": "katana",
            "params": params,
            "command": command,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "duration_ms": duration_ms,
            "error": execution_result.get("error", "Command execution failed"),
            "findings": [],
            "stats": {"findings": 0, "dupes": 0, "payload_bytes": 0},
        }

    # Parse successful output
    stdout = execution_result.get("stdout", "")
    findings = []

    # Extract URLs from katana output
    for line in stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue

        # Parse URL findings
        url_info = _extract_url_from_line(line)
        if url_info:
            finding = {
                "type": "url",
                "target": url_info.get("url", line),
                "evidence": {
                    "raw_output": line,
                    "source": url_info.get("source", "crawl"),
                },
                "severity": "info",
                "confidence": "medium",
                "tags": ["katana", "url-discovery"],
                "raw_ref": line,
            }
            findings.append(finding)

    payload_bytes = len(stdout.encode("utf-8"))

    return {
        "success": True,
        "tool": "katana",
        "params": params,
        "command": command,
        "started_at": started_at.isoformat(),
        "ended_at": ended_at.isoformat(),
        "duration_ms": duration_ms,
        "findings": findings,
        "stats": {
            "findings": len(findings),
            "dupes": 0,
            "payload_bytes": payload_bytes,
        },
    }


def _extract_url_from_line(line: str) -> dict[str, Any] | None:
    """Extract URL information from a single output line."""
    # Simple URL pattern matching
    url_pattern = r"https?://[^\s]+"
    match = re.search(url_pattern, line)
    if match:
        url = match.group(0)
        return {
            "url": url,
            "source": "crawl",
            "raw_line": line,
        }

    # If no URL found but line contains relevant content
    if any(keyword in line.lower() for keyword in ["found", "discovered", "url"]):
        return {"raw_line": line, "source": "unknown"}

    return None


@tool(required_fields=["url"])
def execute_katana():
    """Execute Katana for next-generation crawling and spidering."""
    data = request.get_json()
    params = extract_katana_params(data)

    started_at = datetime.now()
    command = build_katana_command(params)
    execution_result = execute_command(" ".join(command), timeout=300)
    ended_at = datetime.now()

    return parse_katana_output(execution_result, params, command, started_at, ended_at)
