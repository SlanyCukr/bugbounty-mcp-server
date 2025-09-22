"""gobuster tool implementation."""

import logging
import re
from typing import Any
from urllib.parse import urlparse

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import create_finding, tool

logger = logging.getLogger(__name__)


def extract_gobuster_params(data: dict) -> dict:
    """Extract gobuster parameters from request data."""
    base_params = {
        "url": data.get("url", ""),
        "mode": data.get("mode", "dir"),
        "wordlist": data.get(
            "wordlist", "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
        ),
        "extensions": data.get("extensions", "php,html,js,txt"),
        "threads": data.get("threads", 10),
        "timeout": data.get("timeout", "10s"),
        "user_agent": data.get("user_agent", ""),
        "cookies": data.get("cookies", ""),
        "status_codes": data.get("status_codes", "200,204,301,302,307,401,403,500"),
        "exclude_status": data.get("exclude_status", ""),
        "additional_args": data.get("additional_args", ""),
    }

    if base_params["mode"] == "s3":
        base_params["region"] = data.get("region", "")
        base_params["max_files"] = data.get("max-files", 1000)
        if base_params["wordlist"] == "/usr/share/wordlists/dirb/common.txt":
            base_params["wordlist"] = (
                "/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"
            )

    return base_params


def build_gobuster_command(params: dict) -> str:
    """Build gobuster command from parameters."""
    cmd_parts = ["gobuster", params["mode"]]

    if params["mode"] == "dns":
        cmd_parts.extend(["-d", params["url"]])
    elif params["mode"] == "s3":
        pass
    else:
        cmd_parts.extend(["-u", params["url"]])

    cmd_parts.extend(["-w", params["wordlist"]])

    if params["mode"] == "dir" and params["extensions"]:
        cmd_parts.extend(["-x", params["extensions"]])

    cmd_parts.extend(["-t", str(params["threads"])])
    cmd_parts.extend(["--timeout", params["timeout"]])

    if params["user_agent"]:
        cmd_parts.extend(["-a", params["user_agent"]])

    if params["cookies"]:
        cmd_parts.extend(["-c", params["cookies"]])

    if params["status_codes"]:
        cmd_parts.extend(["-s", params["status_codes"]])

    if params["exclude_status"]:
        cmd_parts.extend(["-b", params["exclude_status"]])

    if params["mode"] == "s3":
        if params.get("region"):
            cmd_parts.extend(["--region", params["region"]])
        if params.get("max_files"):
            cmd_parts.extend(["--maxfiles", str(params["max_files"])])

    if params["additional_args"]:
        cmd_parts.extend(params["additional_args"].split())

    return " ".join(cmd_parts)


def parse_gobuster_dir_mode(line: str, target: str) -> dict[str, Any]:
    """Parse directory mode output."""
    dir_match = re.search(
        r"(/[^\s]*)\s+\(Status:\s+(\d{3})\)\s+\[Size:\s+(\d+)\]"
        r"(?:\s+\[--> ([^\]]+)\])?",
        line,
    )
    if not dir_match:
        return {}

    path, status_code, size, redirect = dir_match.groups()
    base_url = target.rstrip("/")
    full_url = f"{base_url}{path}"
    parsed_url = urlparse(full_url)
    host = parsed_url.netloc
    status = int(status_code)
    content_size = int(size)

    severity = "info"
    confidence = "medium"

    tags = ["endpoint", "directory-enum", f"status-{status_code}"]
    if redirect:
        tags.append("redirect")
    if parsed_url.scheme == "https":
        tags.append("https")
    else:
        tags.append("http")

    evidence = {
        "url": full_url,
        "path": path,
        "status_code": status,
        "content_length": content_size,
        "scheme": parsed_url.scheme,
        "port": parsed_url.port,
        "discovered_by": "gobuster",
        "mode": "dir",
    }

    if redirect:
        evidence["redirect_url"] = redirect

    return create_finding(
        finding_type="endpoint",
        target=host,
        evidence=evidence,
        severity=severity,
        confidence=confidence,
        tags=tags,
        raw_ref=line,
    )


def parse_gobuster_dns_mode(line: str, target: str) -> dict[str, Any]:
    """Parse DNS mode output."""
    dns_match = re.search(r"Found:\s+([^\s]+)(?:\s+\(([^)]+)\))?", line)
    if not dns_match:
        return {}

    subdomain, record_type = dns_match.groups()
    severity = "info"
    confidence = "medium"

    tags = [
        "subdomain",
        "dns",
        f"record-{record_type.lower()}" if record_type else "record-a",
    ]

    return create_finding(
        finding_type="subdomain",
        target=subdomain,
        evidence={
            "subdomain": subdomain,
            "record_type": record_type if record_type else "A",
            "parent_domain": target,
            "discovered_by": "gobuster",
            "mode": "dns",
        },
        severity=severity,
        confidence=confidence,
        tags=tags,
        raw_ref=line,
    )


def parse_gobuster_vhost_mode(line: str, target: str) -> dict[str, Any]:
    """Parse vhost mode output."""
    vhost_match = re.search(
        r"Found:\s+([^\s]+)\s+\(Status:\s+(\d{3})\)\s+\[Size:\s+(\d+)\]", line
    )
    if not vhost_match:
        return {}

    vhost, status_code, size = vhost_match.groups()
    status = int(status_code)
    content_size = int(size)

    severity = "info"
    confidence = "medium"

    tags = ["subdomain", "vhost", f"status-{status_code}"]

    return create_finding(
        finding_type="subdomain",
        target=vhost,
        evidence={
            "vhost": vhost,
            "status_code": status,
            "content_length": content_size,
            "parent_target": target,
            "discovered_by": "gobuster",
            "mode": "vhost",
        },
        severity=severity,
        confidence=confidence,
        tags=tags,
        raw_ref=line,
    )


def parse_gobuster_fuzz_mode(line: str, target: str) -> dict[str, Any]:
    """Parse fuzzing mode output."""
    fuzz_match = re.search(
        r"(/[^\s]*)\s+\(Status:\s+(\d{3})\)\s+\[Size:\s+(\d+)\]", line
    )
    if not fuzz_match:
        return {}

    fuzzed_path, status_code, size = fuzz_match.groups()
    base_url = target.rstrip("/")
    full_url = f"{base_url}{fuzzed_path}"
    parsed_url = urlparse(full_url)
    host = parsed_url.netloc
    status = int(status_code)
    content_size = int(size)

    severity = "info"
    confidence = "medium"

    tags = [
        "endpoint",
        "parameter-enum",
        "fuzzing",
        f"status-{status_code}",
    ]
    if parsed_url.scheme == "https":
        tags.append("https")
    else:
        tags.append("http")

    return create_finding(
        finding_type="param",
        target=host,
        evidence={
            "url": full_url,
            "fuzzed_path": fuzzed_path,
            "status_code": status,
            "content_length": content_size,
            "scheme": parsed_url.scheme,
            "port": parsed_url.port,
            "discovered_by": "gobuster",
            "mode": "fuzz",
        },
        severity=severity,
        confidence=confidence,
        tags=tags,
        raw_ref=line,
    )


def parse_gobuster_s3_mode(line: str) -> dict[str, Any] | None:
    """Parse S3 mode output."""
    s3_match = re.search(
        r"(https?://([^/\s]+)\.s3[^/\s]*\.amazonaws\.com/)\s*-\s*([^\s]+)(?:\s+\(([^)]+)\))?",
        line,
    )
    if not s3_match:
        return {}

    bucket_url, bucket_domain, bucket_name, error_info = s3_match.groups()

    if error_info and "NoSuchBucket" in error_info:
        return None

    if error_info and "ListBucket Error" in error_info:
        access_level = "no_list"
        confidence = "medium"
        severity = "info"
    elif error_info and "Access Denied" in error_info:
        access_level = "access_denied"
        confidence = "medium"
        severity = "info"
    else:
        access_level = "accessible"
        confidence = "medium"
        severity = "info"

    tags = [
        "s3-bucket",
        "cloud-storage",
        "s3-enum",
        f"access-{access_level}",
    ]
    if "https" in bucket_url:
        tags.append("https")
    else:
        tags.append("http")

    region = "us-east-1"
    if "s3-" in bucket_domain:
        region_match = re.search(r"s3-([^.]+)", bucket_domain)
        if region_match:
            region = region_match.group(1)

    return create_finding(
        finding_type="cloud_storage",
        target=bucket_name,
        evidence={
            "bucket_url": bucket_url,
            "bucket_name": bucket_name,
            "bucket_domain": bucket_domain,
            "access_level": access_level,
            "region": region,
            "error_info": error_info or "",
            "discovered_by": "gobuster",
            "mode": "s3",
        },
        severity=severity,
        confidence=confidence,
        tags=tags,
        raw_ref=line,
    )


def parse_gobuster_output_to_findings(
    raw_output: str, mode: str, target: str
) -> list[dict[str, Any]]:
    """Parse gobuster output and convert to structured findings."""
    findings = []

    if not raw_output:
        return findings

    lines = raw_output.split("\n")

    for line in lines:
        line = line.strip()
        if (
            not line
            or line.startswith("=")
            or line.startswith("Gobuster")
            or line.startswith("[+]")
        ):
            continue

        try:
            if mode == "dir":
                finding = parse_gobuster_dir_mode(line, target)
            elif mode == "dns":
                finding = parse_gobuster_dns_mode(line, target)
            elif mode == "vhost":
                finding = parse_gobuster_vhost_mode(line, target)
            elif mode == "fuzz":
                finding = parse_gobuster_fuzz_mode(line, target)
            elif mode == "s3":
                finding = parse_gobuster_s3_mode(line)
            else:
                continue

            if finding:
                findings.append(finding)

        except Exception as e:
            logger.warning(f"Failed to parse gobuster line: {line} - {e}")
            continue

    if len(findings) > 100:
        findings = findings[:100]

    return findings


def parse_gobuster_result(execution_result: dict, params: dict) -> dict[str, Any]:
    """Parse gobuster execution result and format response with findings."""
    if not execution_result["success"]:
        return {
            "findings": [],
            "stats": {
                "findings": 0,
                "dupes": 0,
                "payload_bytes": 0,
                "truncated": False,
            },
        }

    stdout = execution_result.get("stdout", "")
    findings = parse_gobuster_output_to_findings(stdout, params["mode"], params["url"])

    seen_items = set()
    unique_findings = []
    dupes_count = 0

    for finding in findings:
        if finding["type"] == "subdomain":
            unique_key = finding["evidence"].get(
                "subdomain", finding["evidence"].get("vhost", finding["target"])
            )
        elif finding["type"] == "endpoint":
            unique_key = finding["evidence"]["url"]
        elif finding["type"] == "param":
            unique_key = finding["evidence"]["fuzzed_path"]
        else:
            unique_key = finding["target"]

        if unique_key not in seen_items:
            seen_items.add(unique_key)
            unique_findings.append(finding)
        else:
            dupes_count += 1

    payload_bytes = len(stdout.encode("utf-8"))
    truncated = len(findings) > 100

    stats = {
        "findings": len(unique_findings),
        "dupes": dupes_count,
        "payload_bytes": payload_bytes,
        "truncated": truncated,
    }

    return {
        "findings": unique_findings,
        "stats": stats,
    }


@tool(required_fields=["url"])
def execute_gobuster():
    """Execute Gobuster for directory, DNS, or vhost discovery."""
    data = request.get_json()
    params = extract_gobuster_params(data)

    logger.info(f"Executing Gobuster {params['mode']} scan on {params['url']}")

    command = build_gobuster_command(params)
    execution_result = execute_command(command, timeout=600)

    return parse_gobuster_result(execution_result, params)
