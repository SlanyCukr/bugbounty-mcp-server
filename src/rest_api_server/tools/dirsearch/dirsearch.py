"""dirsearch tool implementation."""

import json
import logging
import os
from typing import Any
from urllib.parse import urlparse

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import create_finding, create_stats, tool

logger = logging.getLogger(__name__)


def extract_dirsearch_params(data: dict) -> dict:
    """Extract dirsearch parameters from request data."""
    base_params = {
        "url": f"https://{data.get('target', '')}",
        "wordlist": data.get("wordlist", "/usr/share/wordlists/dirb/common.txt"),
        "extensions": data.get("extensions", ""),
        "threads": data.get("threads", 10),
        "timeout": data.get("timeout", 10),
        "recursive": data.get("recursive", False),
        "max_recursion_depth": data.get("max_recursion_depth", 1),
        "exclude_status": data.get("exclude_status", "404"),
        "rate_limit": data.get("rate_limit", ""),
        "additional_args": data.get("additional_args", ""),
    }

    return base_params


def build_dirsearch_command(params: dict) -> str:
    """Build dirsearch command from parameters."""
    import shlex

    cmd_parts = ["dirsearch", "-u", params["url"]]

    if params["extensions"]:
        cmd_parts.extend(["-e", params["extensions"]])

    cmd_parts.extend(["-w", params["wordlist"]])
    cmd_parts.extend(["-t", str(params["threads"])])
    cmd_parts.extend(["--timeout", str(params["timeout"])])

    if params["recursive"]:
        cmd_parts.append("-r")
        if params["max_recursion_depth"] > 1:
            cmd_parts.append("--max-recursion-depth")
            cmd_parts.append(str(params["max_recursion_depth"]))

    if params["exclude_status"]:
        cmd_parts.extend(["--exclude-status", params["exclude_status"]])

    if params["rate_limit"]:
        rate_limit_value = params["rate_limit"]
        if isinstance(rate_limit_value, int | float) and rate_limit_value > 0:
            delay_ms = int(1000 / rate_limit_value)
            cmd_parts.extend(["--delay", str(delay_ms)])

    cmd_parts.extend(["--format", "json", "-o", "/tmp/dirsearch_out.json"])

    if params["additional_args"]:
        cmd_parts.extend(params["additional_args"].split())

    return " ".join(shlex.quote(part) for part in cmd_parts)


def parse_dirsearch_json_output(stdout: str) -> list[dict[str, Any]]:
    """Parse dirsearch JSON output into structured findings."""
    findings = []

    if not stdout.strip():
        return findings

    try:
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            try:
                result = json.loads(line)
                url = result.get("url", "")
                status_code = result.get("status", 0)
                content_length = result.get("content-length", 0)
                redirect_url = result.get("redirect", "")

                if url:
                    parsed_url = urlparse(url)
                    host = parsed_url.netloc
                    path = parsed_url.path or "/"

                    confidence = "medium"
                    severity = "info"

                    tags = ["endpoint", "directory-enum"]
                    if status_code:
                        tags.append(f"status-{status_code}")
                    if redirect_url:
                        tags.append("redirect")
                    if parsed_url.scheme == "https":
                        tags.append("https")
                    else:
                        tags.append("http")

                    finding = create_finding(
                        finding_type="endpoint",
                        target=host,
                        evidence={
                            "url": url,
                            "path": path,
                            "status_code": status_code,
                            "content_length": content_length,
                            "redirect_url": redirect_url,
                            "scheme": parsed_url.scheme,
                            "port": parsed_url.port,
                            "discovered_by": "dirsearch",
                        },
                        severity=severity,
                        confidence=confidence,
                        tags=tags,
                        raw_ref=line,
                    )
                    findings.append(finding)

            except json.JSONDecodeError:
                continue

    except Exception as e:
        logger.warning(f"Failed to parse dirsearch JSON output: {e}")
        return findings

    if len(findings) > 100:
        findings = findings[:100]

    return findings


def parse_dirsearch_result(execution_result: dict) -> dict[str, Any]:
    """Parse dirsearch execution result and format response with findings."""
    if not execution_result["success"]:
        return {"findings": [], "stats": create_stats(0, 0, 0), "version": None}

    stdout = execution_result.get("stdout", "")
    with open("/tmp/dirsearch_raw_output.log", "w") as f:
        f.write(stdout)
    json_file_path = "/tmp/dirsearch_out.json"
    findings = []
    if execution_result["success"]:
        try:
            with open(json_file_path) as f:
                file_content = f.read().strip()
            findings = parse_dirsearch_json_output(file_content)
            os.remove(json_file_path)
        except FileNotFoundError:
            logger.warning("Dirsearch JSON output file not found.")
        except json.JSONDecodeError:
            logger.warning("Failed to parse dirsearch JSON file")
        except Exception as e:
            logger.warning(f"Error reading dirsearch JSON file: {e}")

    seen_urls = set()
    unique_findings = []
    dupes_count = 0

    for finding in findings:
        url = finding["evidence"]["url"]
        if url not in seen_urls:
            seen_urls.add(url)
            unique_findings.append(finding)
        else:
            dupes_count += 1

    payload_bytes = len(stdout.encode("utf-8"))
    truncated = len(findings) > 100

    stats = create_stats(len(unique_findings), dupes_count, payload_bytes)
    stats["truncated"] = truncated

    return {
        "findings": unique_findings,
        "stats": stats,
    }


@tool(required_fields=["target"])
def execute_dirsearch():
    """Execute Dirsearch for directory and file discovery."""
    data = request.get_json()
    params = extract_dirsearch_params(data)

    logger.info(f"Executing Dirsearch on {params['url']}")

    command = build_dirsearch_command(params)
    execution_result = execute_command(command, timeout=600)

    return parse_dirsearch_result(execution_result)
