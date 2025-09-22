"""gau tool implementation."""

import logging
from datetime import datetime

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import tool

logger = logging.getLogger(__name__)


def extract_gau_params(data):
    """Extract gau parameters from request data."""
    return {
        "domain": data.get("url", data.get("domain", "")),
        "providers": data.get("providers", "wayback,commoncrawl,otx,urlscan"),
        "include_subs": data.get("include_subs", data.get("include_subdomains", False)),
        "blacklist": data.get("blacklist", ""),
        "from_date": data.get("from_date", ""),
        "to_date": data.get("to_date", ""),
        "output_file": data.get("output_file", ""),
        "threads": data.get("threads", 5),
        "timeout": data.get("timeout", 60),
        "retries": data.get("retries", 5),
        "proxy": data.get("proxy", ""),
        "random_agent": data.get("random_agent", False),
        "verbose": data.get("verbose", False),
        "additional_args": data.get("additional_args", ""),
        "gau_timeout": data.get("gau_timeout", 300),
    }


def build_gau_command(params):
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
        command += f" --threads {int(params['threads'])}"

    if params["timeout"] != 60:
        command += f" --timeout {int(params['timeout'])}"

    if params["retries"] != 5:
        command += f" --retries {int(params['retries'])}"

    if params["proxy"]:
        command += f" --proxy {params['proxy']}"

    if params["random_agent"]:
        command += " --random-agent"

    if params["verbose"]:
        command += " --verbose"

    # Handle additional arguments
    if params["additional_args"]:
        command += " " + params["additional_args"]

    return command


def parse_gau_output(execution_result, params, command, started_at, ended_at):
    """Parse gau execution result and format response."""
    duration_ms = int((ended_at - started_at).total_seconds() * 1000)

    if execution_result.get("success"):
        findings = []
        if execution_result.get("stdout"):
            for url in execution_result["stdout"].split("\n"):
                url = url.strip()
                if url:
                    finding = {
                        "type": "url",
                        "target": url,
                        "evidence": {
                            "raw_output": url,
                            "tool": "gau",
                            "domain": params["domain"],
                        },
                        "severity": "info",
                        "confidence": "medium",
                        "tags": ["gau"],
                        "raw_ref": url,
                    }
                    findings.append(finding)

        payload_bytes = len(execution_result.get("stdout", "").encode("utf-8"))

        return {
            "success": True,
            "tool": "gau",
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
    else:
        return {
            "success": False,
            "tool": "gau",
            "params": params,
            "command": command,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "duration_ms": duration_ms,
            "error": execution_result.get("error", "Command execution failed"),
            "findings": [],
            "stats": {"findings": 0, "dupes": 0, "payload_bytes": 0},
        }


@tool(required_fields=["domain"])
def execute_gau():
    """Execute Gau (Get All URLs) for URL discovery from multiple sources."""
    data = request.get_json()
    params = extract_gau_params(data)

    logger.info(f"Executing Gau on {params['domain']}")

    started_at = datetime.now()
    command = build_gau_command(params)
    execution_result = execute_command(command, timeout=params["gau_timeout"])
    ended_at = datetime.now()

    return parse_gau_output(execution_result, params, command, started_at, ended_at)
