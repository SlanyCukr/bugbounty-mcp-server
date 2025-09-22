"""ffuf tool implementation."""

import json
import logging
import time
from datetime import UTC, datetime
from urllib.parse import urlparse

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.deduplication import deduplicate_findings
from src.rest_api_server.utils.registry import create_finding, tool

logger = logging.getLogger(__name__)


def extract_ffuf_params(data: dict) -> dict:
    """Extract ffuf parameters from request data."""
    base_params = {
        "url": data["url"],
        "wordlist": data.get(
            "wordlist", "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
        ),
        "secondary_wordlist": data.get("secondary_wordlist", ""),
        "extensions": data.get("extensions", ""),
        "force_extensions": data.get("force_extensions", False),
        "exclude_extensions": data.get("exclude_extensions", ""),
        "prefixes": data.get("prefixes", ""),
        "suffixes": data.get("suffixes", ""),
        "include_status": data.get("include_status", "200,204,301,302,307,401,403,500"),
        "exclude_status": data.get("exclude_status", ""),
        "include_size": data.get("include_size", ""),
        "exclude_size": data.get("exclude_size", ""),
        "include_words": data.get("include_words", ""),
        "exclude_words": data.get("exclude_words", ""),
        "include_lines": data.get("include_lines", ""),
        "exclude_lines": data.get("exclude_lines", ""),
        "include_regex": data.get("include_regex", ""),
        "exclude_regex": data.get("exclude_regex", ""),
        "threads": data.get("threads", 40),
        "delay": data.get("delay", ""),
        "timeout": data.get("timeout", 10),
        "method": data.get("method", "GET"),
        "headers": data.get("headers", ""),
        "cookies": data.get("cookies", ""),
        "proxy": data.get("proxy", ""),
        "rate_limit": data.get("rate_limit", ""),
        "recursion": data.get("recursion", False),
        "recursion_depth": data.get("recursion_depth", 1),
        "additional_args": data.get("additional_args", ""),
    }

    return base_params


def build_ffuf_command(params: dict) -> str:
    """Build ffuf command from parameters."""
    command_parts = ["ffuf"]

    url = params["url"]
    if "FUZZ" not in url:
        if url.endswith("/"):
            target_url = f"{url}FUZZ"
        else:
            target_url = f"{url}/FUZZ"
    else:
        target_url = url

    command_parts.extend(["-u", target_url])
    command_parts.extend(["-w", params["wordlist"]])

    if params.get("secondary_wordlist"):
        command_parts.extend(["-w", params["secondary_wordlist"]])

    if params.get("include_status"):
        command_parts.extend(["-mc", params["include_status"]])

    if params.get("exclude_status"):
        command_parts.extend(["-fc", params["exclude_status"]])

    if params.get("include_size"):
        command_parts.extend(["-ms", params["include_size"]])

    if params.get("exclude_size"):
        command_parts.extend(["-fs", params["exclude_size"]])

    if params.get("include_words"):
        command_parts.extend(["-mw", params["include_words"]])

    if params.get("exclude_words"):
        command_parts.extend(["-fw", params["exclude_words"]])

    if params.get("include_lines"):
        command_parts.extend(["-ml", params["include_lines"]])

    if params.get("exclude_lines"):
        command_parts.extend(["-fl", params["exclude_lines"]])

    if params.get("include_regex"):
        command_parts.extend(["-mr", params["include_regex"]])

    if params.get("exclude_regex"):
        command_parts.extend(["-fr", params["exclude_regex"]])

    if params.get("extensions"):
        extensions = params["extensions"].split(",")
        for ext in extensions:
            ext = ext.strip()
            if not ext.startswith("."):
                ext = f".{ext}"
            command_parts.extend(["-e", ext])

    threads = params.get("threads", 40)
    command_parts.extend(["-t", str(threads)])

    if params.get("delay"):
        command_parts.extend(["-p", params["delay"]])

    if params.get("rate_limit"):
        command_parts.extend(["-rate", str(params["rate_limit"])])

    if params.get("method", "GET") != "GET":
        command_parts.extend(["-X", params["method"]])

    if params.get("headers"):
        headers = params["headers"]
        if isinstance(headers, str):
            for header in headers.split(";"):
                if header.strip():
                    command_parts.extend(["-H", header.strip()])
        elif isinstance(headers, list):
            for header in headers:
                command_parts.extend(["-H", header])

    if params.get("cookies"):
        command_parts.extend(["-b", params["cookies"]])

    if params.get("proxy"):
        command_parts.extend(["-x", params["proxy"]])

    if params.get("timeout"):
        command_parts.extend(["-timeout", str(params["timeout"])])

    if params.get("recursion"):
        command_parts.append("-recursion")
        if params.get("recursion_depth"):
            command_parts.extend(["-recursion-depth", str(params["recursion_depth"])])

    command_parts.extend(["-of", "json"])
    command_parts.append("-s")

    if params.get("additional_args"):
        command_parts.extend(params["additional_args"].split())

    return " ".join(command_parts)


def parse_ffuf_output(stdout: str) -> list[dict]:
    """Parse ffuf JSON output into findings."""
    findings = []

    if not stdout.strip():
        return findings

    try:
        data = json.loads(stdout)
        results = data.get("results", [])

        for result in results:
            if not isinstance(result, dict):
                continue

            url = result.get("url", "")
            status = result.get("status", 0)
            length = result.get("length", 0)
            words = result.get("words", 0)
            lines = result.get("lines", 0)
            input_data = result.get("input", {})

            if not url:
                continue

            evidence = {
                "url": url,
                "status_code": status,
                "response_size": length,
                "word_count": words,
                "line_count": lines,
                "discovered_by": "ffuf",
            }

            if input_data:
                evidence["fuzzed_input"] = input_data

            if "redirectlocation" in result:
                evidence["redirect_location"] = result["redirectlocation"]

            parsed_url = urlparse(url)
            target = parsed_url.netloc

            severity = "info"
            confidence = "medium"

            tags = ["directory-enum", f"status-{status}"]
            if status == 200:
                tags.append("found")
            elif status in [301, 302, 307]:
                tags.append("redirect")
            elif status in [401, 403]:
                tags.append("restricted")
            elif status >= 500:
                tags.append("server-error")

            if length > 10000:
                tags.append("large-response")
            elif length == 0:
                tags.append("empty-response")

            finding = create_finding(
                finding_type="endpoint",
                target=target,
                evidence=evidence,
                severity=severity,
                confidence=confidence,
                tags=tags,
                raw_ref=f"ffuf_{len(findings)}",
            )
            findings.append(finding)

    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse ffuf JSON output: {e}")
    except Exception as e:
        logger.error(f"Error processing ffuf results: {e}")

    if len(findings) > 100:
        findings = findings[:100]

    return findings


def parse_ffuf_result(
    execution_result: dict,
    params: dict,
    command: str,
    start_time: float,
    end_time: float,
) -> dict:
    """Parse ffuf execution result and format response."""
    duration_ms = int((end_time - start_time) * 1000)

    if not execution_result["success"]:
        return {
            "success": False,
            "tool": "ffuf",
            "params": params,
            "started_at": datetime.fromtimestamp(start_time, UTC).isoformat(),
            "ended_at": datetime.fromtimestamp(end_time, UTC).isoformat(),
            "duration_ms": duration_ms,
            "error": execution_result.get("stderr", "Command execution failed"),
            "findings": [],
            "stats": {"findings": 0, "dupes": 0, "payload_bytes": 0},
        }

    stdout = execution_result.get("stdout", "")
    findings = parse_ffuf_output(stdout)
    unique_findings = deduplicate_findings(findings)
    dupes_count = len(findings) - len(unique_findings)
    payload_bytes = len(stdout.encode("utf-8"))
    truncated = len(findings) > 100

    stats = {
        "findings": len(unique_findings),
        "dupes": dupes_count,
        "payload_bytes": payload_bytes,
        "truncated": truncated,
    }

    return {
        "success": True,
        "tool": "ffuf",
        "params": params,
        "started_at": datetime.fromtimestamp(start_time, UTC).isoformat(),
        "ended_at": datetime.fromtimestamp(end_time, UTC).isoformat(),
        "duration_ms": duration_ms,
        "findings": unique_findings,
        "stats": stats,
    }


@tool(required_fields=["url"])
def execute_ffuf():
    """Execute FFuf web fuzzer."""
    data = request.get_json()
    params = extract_ffuf_params(data)

    logger.info(f"Executing FFuf on {params['url']}")

    start_time = time.time()
    command = build_ffuf_command(params)
    execution_result = execute_command(command, timeout=params["timeout"] * 60)
    end_time = time.time()

    return parse_ffuf_result(execution_result, params, command, start_time, end_time)
