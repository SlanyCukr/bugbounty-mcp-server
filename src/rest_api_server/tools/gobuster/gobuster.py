"""gobuster tool implementation."""

import logging
import re
from datetime import datetime
from typing import Any, cast
from urllib.parse import urlparse

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import (
    ConfidenceLevel,
    SeverityLevel,
    create_finding,
    create_stats,
    tool,
)

logger = logging.getLogger(__name__)

# Aggressive preset for gobuster
AGGRESSIVE_PRESET = {
    "wordlist": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "extensions": (
        "php,asp,aspx,jsp,jspx,html,htm,txt,bak,old,zip,tar,tar.gz,"
        "sql,xml,json,config,conf,ini,log"
    ),
    "threads": 100,
    "timeout": "10s",
    "status_codes": "200,204,301,302,307,401,403,500,503",
    "exclude_status": "404",
}


def _determine_gobuster_severity(
    mode: str, status_code: int, path_or_host: str, size: int
) -> str:
    """Determine severity based on mode, status code and path/host characteristics."""
    if mode == "dns":
        # DNS findings are generally informational
        if any(
            keyword in path_or_host.lower()
            for keyword in ["admin", "mail", "ftp", "vpn"]
        ):
            return "low"  # Potentially interesting subdomains
        return "info"

    elif mode in ["dir", "vhost", "fuzz"]:
        if status_code in [403, 401]:
            return "low"  # Authentication/authorization endpoints
        elif status_code >= 500:
            return "low"  # Server errors
        elif any(
            keyword in path_or_host.lower()
            for keyword in ["admin", "debug", "test", "config", "backup", "login"]
        ):
            return "medium"  # Potentially sensitive paths
        elif status_code == 200 and size > 0:
            return "info"  # Successfully accessible content

    elif mode == "s3":
        # S3 bucket findings severity based on access level and bucket name
        if any(
            keyword in path_or_host.lower()
            for keyword in ["backup", "private", "secret", "admin", "internal"]
        ):
            return "medium"  # Potentially sensitive bucket names
        elif any(
            keyword in path_or_host.lower()
            for keyword in ["public", "static", "assets", "images"]
        ):
            return "info"  # Less sensitive bucket names
        else:
            return "low"  # Default for discovered buckets

    return "info"


def _parse_gobuster_output_to_findings(
    raw_output: str, mode: str, target: str
) -> list[dict[str, Any]]:
    """Parse gobuster output and convert to standardized findings.

    Args:
        raw_output: Raw stdout from gobuster command
        mode: Gobuster mode (dir, dns, vhost, fuzz, s3)
        target: Original target URL/domain

    Returns:
        List of standardized finding dictionaries
    """
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

        if mode == "dir":
            # Directory/file enumeration output format:
            # /admin                (Status: 301) [Size: 178] [--> http://example.com/admin/]
            # /login.php            (Status: 200) [Size: 2456]
            dir_match = re.search(
                r"(/[^\s]*)\s+\(Status:\s+(\d{3})\)\s+\[Size:\s+(\d+)\]"
                r"(?:\s+\[--> ([^\]]+)\])?",
                line,
            )
            if dir_match:
                path, status_code, size, redirect = dir_match.groups()

                # Build full URL
                base_url = target.rstrip("/")
                full_url = f"{base_url}{path}"

                parsed_url = urlparse(full_url)
                host = parsed_url.netloc

                status = int(status_code)
                content_size = int(size)

                confidence = cast(ConfidenceLevel, "high" if status < 400 else "medium")
                severity = cast(
                    SeverityLevel,
                    _determine_gobuster_severity(mode, status, path, content_size),
                )

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
                    "mode": mode,
                }

                if redirect:
                    evidence["redirect_url"] = redirect

                finding = create_finding(
                    finding_type="endpoint",
                    target=host,
                    evidence=evidence,
                    severity=severity,
                    confidence=confidence,
                    tags=tags,
                    raw_ref=line,
                )
                findings.append(finding)

        elif mode == "dns":
            # DNS subdomain enumeration output format:
            # Found: mail.example.com
            # Found: www.example.com (CNAME)
            dns_match = re.search(r"Found:\s+([^\s]+)(?:\s+\(([^)]+)\))?", line)
            if dns_match:
                subdomain, record_type = dns_match.groups()

                confidence = cast(ConfidenceLevel, "high")
                severity = cast(
                    SeverityLevel, _determine_gobuster_severity(mode, 0, subdomain, 0)
                )

                tags = [
                    "subdomain",
                    "dns",
                    f"record-{record_type.lower()}" if record_type else "record-a",
                ]

                finding = create_finding(
                    finding_type="subdomain",
                    target=subdomain,
                    evidence={
                        "subdomain": subdomain,
                        "record_type": record_type if record_type else "A",
                        "parent_domain": target,
                        "discovered_by": "gobuster",
                        "mode": mode,
                    },
                    severity=severity,
                    confidence=confidence,
                    tags=tags,
                    raw_ref=line,
                )
                findings.append(finding)

        elif mode == "vhost":
            # Virtual host enumeration output format:
            # Found: admin.example.com (Status: 200) [Size: 1234]
            vhost_match = re.search(
                r"Found:\s+([^\s]+)\s+\(Status:\s+(\d{3})\)\s+\[Size:\s+(\d+)\]", line
            )
            if vhost_match:
                vhost, status_code, size = vhost_match.groups()

                status = int(status_code)
                content_size = int(size)

                confidence = cast(ConfidenceLevel, "high" if status < 400 else "medium")
                severity = cast(
                    SeverityLevel,
                    _determine_gobuster_severity(mode, status, vhost, content_size),
                )

                tags = ["subdomain", "vhost", f"status-{status_code}"]

                finding = create_finding(
                    finding_type="subdomain",
                    target=vhost,
                    evidence={
                        "vhost": vhost,
                        "status_code": status,
                        "content_length": content_size,
                        "parent_target": target,
                        "discovered_by": "gobuster",
                        "mode": mode,
                    },
                    severity=severity,
                    confidence=confidence,
                    tags=tags,
                    raw_ref=line,
                )
                findings.append(finding)

        elif mode == "fuzz":
            # Fuzzing mode output format (similar to dir mode):
            # /test=admin           (Status: 200) [Size: 1234]
            fuzz_match = re.search(
                r"(/[^\s]*)\s+\(Status:\s+(\d{3})\)\s+\[Size:\s+(\d+)\]", line
            )
            if fuzz_match:
                fuzzed_path, status_code, size = fuzz_match.groups()

                # Build full URL
                base_url = target.rstrip("/")
                full_url = f"{base_url}{fuzzed_path}"

                parsed_url = urlparse(full_url)
                host = parsed_url.netloc

                status = int(status_code)
                content_size = int(size)

                confidence = cast(ConfidenceLevel, "high" if status < 400 else "medium")
                severity = cast(
                    SeverityLevel,
                    _determine_gobuster_severity(
                        mode, status, fuzzed_path, content_size
                    ),
                )

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

                finding = create_finding(
                    finding_type="param",  # Fuzzing is typically parameter discovery
                    target=host,
                    evidence={
                        "url": full_url,
                        "fuzzed_path": fuzzed_path,
                        "status_code": status,
                        "content_length": content_size,
                        "scheme": parsed_url.scheme,
                        "port": parsed_url.port,
                        "discovered_by": "gobuster",
                        "mode": mode,
                    },
                    severity=severity,
                    confidence=confidence,
                    tags=tags,
                    raw_ref=line,
                )
                findings.append(finding)

        elif mode == "s3":
            # S3 bucket enumeration output format:
            # http://bucket-name.s3.amazonaws.com/ - bucket-name
            # https://bucket-name.s3-eu-west-1.amazonaws.com/ - bucket-name
            # (ListBucket Error)
            s3_match = re.search(
                r"(https?://([^/\s]+)\.s3[^/\s]*\.amazonaws\.com/)\s*-\s*([^\s]+)"
                r"(?:\s+\(([^)]+)\))?",
                line,
            )
            if s3_match:
                bucket_url, bucket_domain, bucket_name, error_info = s3_match.groups()

                # Determine access level and confidence based on error info
                if error_info and "ListBucket Error" in error_info:
                    access_level = "no_list"
                    confidence = cast(ConfidenceLevel, "medium")
                    severity = cast(SeverityLevel, "info")
                elif error_info and "Access Denied" in error_info:
                    access_level = "access_denied"
                    confidence = cast(ConfidenceLevel, "high")
                    severity = cast(SeverityLevel, "low")
                elif error_info and "NoSuchBucket" in error_info:
                    # Skip non-existent buckets
                    continue
                else:
                    # No error info means likely accessible
                    access_level = "accessible"
                    confidence = cast(ConfidenceLevel, "high")
                    severity = cast(SeverityLevel, "medium")

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

                # Extract region from domain if possible
                region = "us-east-1"  # default
                if "s3-" in bucket_domain:
                    region_match = re.search(r"s3-([^.]+)", bucket_domain)
                    if region_match:
                        region = region_match.group(1)

                finding = create_finding(
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
                        "mode": mode,
                    },
                    severity=severity,
                    confidence=confidence,
                    tags=tags,
                    raw_ref=line,
                )
                findings.append(finding)

    return findings


def _apply_aggressive_preset(user_params: dict, aggressive: bool = False) -> dict:
    """Apply aggressive preset to user parameters if aggressive=True."""
    if not aggressive:
        return user_params

    # Start with user params and apply aggressive preset
    merged_params = user_params.copy()

    # Apply aggressive preset for parameters not explicitly set by user
    for key, aggressive_value in AGGRESSIVE_PRESET.items():
        if key not in user_params:
            merged_params[key] = aggressive_value
        else:
            # For certain key parameters, use aggressive values if user set defaults
            if key in ["threads", "status_codes", "exclude_status"] and user_params.get(
                key
            ) in [10, "200,204,301,302,307,401,403,500", ""]:
                merged_params[key] = aggressive_value

    return merged_params


def _extract_gobuster_params(data):
    """Extract and validate gobuster parameters from request data."""
    # Check for aggressive mode
    aggressive = data.get("aggressive", False)

    # Base parameters
    base_params = {
        "url": data.get("url", ""),  # Made optional for S3 mode
        "mode": data.get("mode", "dir"),
        "wordlist": data.get("wordlist", "/usr/share/wordlists/dirb/common.txt"),
        "extensions": data.get("extensions", ""),
        "threads": data.get("threads", 10),
        "timeout": data.get("timeout", "10s"),
        "user_agent": data.get("user_agent", ""),
        "cookies": data.get("cookies", ""),
        "status_codes": data.get("status_codes", "200,204,301,302,307,401,403,500"),
        "exclude_status": data.get("exclude_status", ""),
        "additional_args": data.get("additional_args", ""),
    }

    # S3 mode specific parameters
    if base_params["mode"] == "s3":
        base_params["region"] = data.get("region", "")
        base_params["max-files"] = data.get("max_files", data.get("max-files", 1000))
        # Use S3-specific wordlist if not specified
        if base_params["wordlist"] == "/usr/share/wordlists/dirb/common.txt":
            base_params["wordlist"] = (
                "/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"
            )

    # Validate required parameters per mode
    if base_params["mode"] in ["dir", "vhost", "fuzz"] and not base_params["url"]:
        raise ValueError("URL is required for dir, vhost, and fuzz modes")
    elif base_params["mode"] == "dns" and not base_params["url"]:
        raise ValueError("Domain is required for DNS mode")

    # Apply aggressive preset if requested
    return _apply_aggressive_preset(base_params, aggressive)


def _build_gobuster_command(params):
    """Build gobuster command from parameters."""
    # Build gobuster command
    cmd_parts = ["gobuster", params["mode"]]

    # Add target URL/domain - different modes require different parameters
    if params["mode"] == "dns":
        cmd_parts.extend(["-d", params["url"]])
    elif params["mode"] == "s3":
        # S3 mode uses -w for wordlist and no URL parameter
        pass  # URL not needed for S3 mode
    else:
        cmd_parts.extend(["-u", params["url"]])

    # Add wordlist
    cmd_parts.extend(["-w", params["wordlist"]])

    # Add extensions for dir mode
    if params["mode"] == "dir" and params["extensions"]:
        cmd_parts.extend(["-x", params["extensions"]])

    # Add threads
    cmd_parts.extend(["-t", str(params["threads"])])

    # Add timeout
    cmd_parts.extend(["--timeout", params["timeout"]])

    # Add user agent
    if params["user_agent"]:
        cmd_parts.extend(["-a", params["user_agent"]])

    # Add cookies
    if params["cookies"]:
        cmd_parts.extend(["-c", params["cookies"]])

    # Add status codes (include/positive matching)
    if params["status_codes"]:
        cmd_parts.extend(["-s", params["status_codes"]])

    # Add status codes to exclude (negative matching)
    if params["exclude_status"]:
        cmd_parts.extend(["-b", params["exclude_status"]])

    # S3 specific parameters
    if params["mode"] == "s3":
        # S3 mode specific options
        if params.get("region"):
            cmd_parts.extend(["--region", params["region"]])
        if params.get("max-files"):
            cmd_parts.extend(["--maxfiles", str(params["max-files"])])

    # Add additional arguments
    if params["additional_args"]:
        cmd_parts.extend(params["additional_args"].split())

    return " ".join(cmd_parts)


def _parse_gobuster_result(
    execution_result, params, command, started_at: datetime, ended_at: datetime
) -> dict[str, Any]:
    """Parse gobuster execution result and format response with findings."""
    if not execution_result["success"]:
        return {"findings": [], "stats": create_stats(0, 0, 0)}

    # Parse output into structured findings
    stdout = execution_result.get("stdout", "")
    findings = _parse_gobuster_output_to_findings(stdout, params["mode"], params["url"])

    # Remove duplicates based on target and evidence key
    seen_items = set()
    unique_findings = []
    dupes_count = 0

    for finding in findings:
        # Create unique key based on finding type and key evidence
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

    return {
        "findings": unique_findings,
        "stats": create_stats(len(unique_findings), dupes_count, payload_bytes),
    }


@tool(required_fields=["url"])
def execute_gobuster():
    """Execute Gobuster for directory, DNS, or vhost discovery."""
    data = request.get_json()
    params = _extract_gobuster_params(data)

    # Handle validation error
    if isinstance(params, tuple):
        return params

    logger.info(f"Executing Gobuster {params['mode']} scan on {params['url']}")

    started_at = datetime.now()
    command = _build_gobuster_command(params)
    execution_result = execute_command(command, timeout=600)
    ended_at = datetime.now()

    return _parse_gobuster_result(
        execution_result, params, command, started_at, ended_at
    )
