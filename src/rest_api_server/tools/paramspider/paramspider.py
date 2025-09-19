"""paramspider tool implementation."""

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

# Aggressive preset for paramspider
AGGRESSIVE_PRESET = {
    "level": "high",
    "quiet": False,
    "subs": True,
    "exclude": "css,js,png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot",
}


def _extract_paramspider_params(data):
    """Extract and validate paramspider parameters from request data."""
    # Check for aggressive mode
    aggressive = data.get("aggressive", False)

    # Base parameters - paramspider uses -d for domain
    domain = data.get("domain", data.get("url", ""))
    if domain.startswith("http"):
        parsed = urlparse(domain)
        domain = parsed.netloc

    base_params = {
        "domain": domain,
        "stream": data.get("stream", True),  # Stream mode for real-time output
        "placeholder": data.get("placeholder", "FUZZ"),
        "proxy": data.get("proxy", ""),
        "exclude": data.get("exclude", ""),
        "output": data.get("output", ""),
        "level": data.get("level", 1),
        "subs": data.get("subs", False),
        "silent": data.get("silent", False),
        "clean": data.get("clean", False),
        "additional_args": data.get("additional_args", ""),
    }

    # Apply aggressive preset if requested
    return _apply_aggressive_preset(base_params, aggressive)


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
            if key in ["level", "quiet", "subs"] and user_params.get(key) in [
                "medium",
                True,
                False,
                None,
            ]:
                merged_params[key] = aggressive_value

    return merged_params


def _build_paramspider_command(params):
    """Build paramspider command from parameters."""
    cmd_parts = ["paramspider", "-d", params["domain"]]

    # Add stream mode (-s flag) for real-time output
    if params["stream"]:
        cmd_parts.append("-s")

    # Add placeholder for parameter values
    if params["placeholder"] and params["placeholder"] != "FUZZ":
        cmd_parts.extend(["-p", params["placeholder"]])

    # Add proxy if specified
    if params["proxy"]:
        cmd_parts.extend(["--proxy", params["proxy"]])

    # Add level (recursion depth)
    if params["level"] > 1:
        cmd_parts.extend(["-l", str(params["level"])])

    # Add subdomain inclusion
    if params["subs"]:
        cmd_parts.append("--subs")

    # Add exclude patterns
    if params["exclude"]:
        cmd_parts.extend(["--exclude", params["exclude"]])

    # Add output file
    if params["output"]:
        cmd_parts.extend(["-o", params["output"]])

    # Add silent mode
    if params["silent"]:
        cmd_parts.append("--silent")

    # Add any additional arguments
    if params["additional_args"]:
        cmd_parts.extend(params["additional_args"].split())

    return " ".join(cmd_parts)


def _classify_parameter_security(param_name: str) -> dict[str, Any]:
    """Classify parameter by security risk and potential attack vectors.

    Args:
        param_name: Parameter name to classify

    Returns:
        Dictionary with classification details
    """
    param_lower = param_name.lower()

    # Security-critical parameter patterns from task requirements
    authentication_params = [
        "user",
        "username",
        "password",
        "passwd",
        "pwd",
        "token",
        "session",
        "auth",
        "login",
        "key",
        "secret",
    ]
    file_handling_params = [
        "file",
        "upload",
        "filename",
        "path",
        "dir",
        "directory",
        "filepath",
        "doc",
        "document",
    ]
    database_params = [
        "db",
        "database",
        "query",
        "table",
        "id",
        "uid",
        "sql",
        "select",
        "insert",
        "delete",
        "update",
    ]
    admin_params = [
        "admin",
        "administrator",
        "priv",
        "privilege",
        "level",
        "access",
        "role",
        "permission",
    ]
    api_params = [
        "api",
        "apikey",
        "endpoint",
        "version",
        "v",
        "method",
        "action",
        "service",
    ]
    config_params = [
        "config",
        "configuration",
        "setting",
        "env",
        "environment",
        "debug",
        "test",
        "dev",
    ]
    injection_params = [
        "cmd",
        "command",
        "exec",
        "system",
        "shell",
        "script",
        "eval",
        "include",
        "require",
    ]
    redirect_params = [
        "url",
        "redirect",
        "return",
        "callback",
        "next",
        "goto",
        "forward",
        "target",
    ]

    classification = {
        "category": "unknown",
        "risk_level": "low",
        "attack_vectors": [],
        "follow_up_tools": [],
    }

    # Classify by category and determine risk level
    if any(keyword in param_lower for keyword in authentication_params):
        classification["category"] = "authentication"
        classification["risk_level"] = "critical"
        classification["attack_vectors"] = [
            "credential_stuffing",
            "brute_force",
            "session_hijacking",
        ]
        classification["follow_up_tools"] = ["hydra", "burp_intruder", "ffuf"]

    elif any(keyword in param_lower for keyword in file_handling_params):
        classification["category"] = "file_handling"
        classification["risk_level"] = "high"
        classification["attack_vectors"] = [
            "path_traversal",
            "file_upload",
            "lfi",
            "rfi",
        ]
        classification["follow_up_tools"] = ["ffuf", "burp_intruder", "dirb"]

    elif any(keyword in param_lower for keyword in database_params):
        classification["category"] = "database"
        classification["risk_level"] = "high"
        classification["attack_vectors"] = [
            "sql_injection",
            "nosql_injection",
            "blind_sqli",
        ]
        classification["follow_up_tools"] = ["sqlmap", "burp_intruder", "ffuf"]

    elif any(keyword in param_lower for keyword in injection_params):
        classification["category"] = "injection"
        classification["risk_level"] = "critical"
        classification["attack_vectors"] = [
            "command_injection",
            "code_injection",
            "rce",
        ]
        classification["follow_up_tools"] = ["ffuf", "burp_intruder", "wfuzz"]

    elif any(keyword in param_lower for keyword in admin_params):
        classification["category"] = "admin_privilege"
        classification["risk_level"] = "high"
        classification["attack_vectors"] = [
            "privilege_escalation",
            "authorization_bypass",
        ]
        classification["follow_up_tools"] = ["ffuf", "burp_intruder", "arjun"]

    elif any(keyword in param_lower for keyword in redirect_params):
        classification["category"] = "redirect"
        classification["risk_level"] = "medium"
        classification["attack_vectors"] = ["open_redirect", "ssrf", "phishing"]
        classification["follow_up_tools"] = ["ffuf", "burp_intruder"]

    elif any(keyword in param_lower for keyword in api_params):
        classification["category"] = "api"
        classification["risk_level"] = "medium"
        classification["attack_vectors"] = [
            "api_abuse",
            "rate_limiting_bypass",
            "information_disclosure",
        ]
        classification["follow_up_tools"] = ["ffuf", "arjun", "x8"]

    elif any(keyword in param_lower for keyword in config_params):
        classification["category"] = "configuration"
        classification["risk_level"] = "medium"
        classification["attack_vectors"] = [
            "information_disclosure",
            "debug_mode_exposure",
        ]
        classification["follow_up_tools"] = ["ffuf", "arjun"]

    else:
        # Generic parameter
        classification["category"] = "generic"
        classification["risk_level"] = "low"
        classification["attack_vectors"] = [
            "parameter_pollution",
            "information_disclosure",
        ]
        classification["follow_up_tools"] = ["ffuf", "arjun"]

    return classification


def _map_risk_to_severity(risk_level: str) -> str:
    """Map risk level to severity for findings.

    Args:
        risk_level: Risk level (critical, high, medium, low)

    Returns:
        Severity string for findings
    """
    risk_mapping = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "info",
    }
    return risk_mapping.get(risk_level, "info")


def _parse_paramspider_output(stdout: str) -> list[dict[str, Any]]:
    """Parse paramspider output into structured findings."""
    findings = []

    if not stdout.strip():
        return findings

    lines = stdout.strip().split("\n")

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # ParamSpider outputs URLs with parameters
        # Example: https://example.com/page?param=FUZZ
        # Example: https://example.com/api/v1?id=FUZZ&type=FUZZ
        if line.startswith("http") and ("?" in line or "&" in line):
            try:
                parsed_url = urlparse(line)
                host = parsed_url.netloc
                path = parsed_url.path
                query = parsed_url.query

                if query:
                    # Extract parameter names from query string
                    param_pairs = query.split("&")
                    for pair in param_pairs:
                        if "=" in pair:
                            param_name, param_value = pair.split("=", 1)
                            param_name = param_name.strip()

                            if param_name:  # Skip empty parameter names
                                # Classify parameter by security risk
                                param_classification = _classify_parameter_security(
                                    param_name
                                )

                                tags = ["parameter", "discovery", "archive"]
                                if parsed_url.scheme == "https":
                                    tags.append("https")
                                else:
                                    tags.append("http")

                                # Add security classification tags
                                if param_classification["category"]:
                                    tags.append(param_classification["category"])
                                if param_classification["risk_level"]:
                                    tags.append(
                                        f"risk_{param_classification['risk_level']}"
                                    )

                                # Determine confidence based on source
                                # and parameter type
                                confidence = (
                                    "medium"  # Archive data is usually reliable
                                )
                                # but may be outdated
                                if "FUZZ" in param_value:
                                    # Fuzzing placeholder indicates active parameter
                                    confidence = "high"
                                if param_classification["risk_level"] == "high":
                                    # High-risk parameters are more significant
                                    confidence = "high"

                                finding = create_finding(
                                    finding_type="param",
                                    target=host,
                                    evidence={
                                        "parameter_name": param_name,
                                        "parameter_value": param_value,
                                        "url": line,
                                        "path": path,
                                        "query_string": query,
                                        "scheme": parsed_url.scheme,
                                        "port": parsed_url.port,
                                        "discovered_by": "paramspider",
                                        "source": "web_archive",
                                        "security_classification": param_classification,
                                        "parameter_type": param_classification[
                                            "category"
                                        ],
                                        "risk_level": param_classification[
                                            "risk_level"
                                        ],
                                        "attack_vectors": param_classification[
                                            "attack_vectors"
                                        ],
                                        "follow_up_tools": param_classification[
                                            "follow_up_tools"
                                        ],
                                    },
                                    severity=cast(
                                        SeverityLevel,
                                        _map_risk_to_severity(
                                            param_classification["risk_level"]
                                        ),
                                    ),
                                    confidence=cast(ConfidenceLevel, confidence),
                                    tags=tags,
                                    raw_ref=line,
                                )
                                findings.append(finding)

            except Exception as e:
                logger.warning(f"Failed to parse paramspider URL line: {line} - {e}")
                continue

        # Also look for direct parameter listings that some versions output
        elif (
            "=" not in line
            and line
            and not line.startswith("[")
            and not line.startswith("http")
        ):
            # Sometimes paramspider outputs just parameter names
            param_match = re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", line)
            if param_match:
                param_classification = _classify_parameter_security(line)

                tags = ["parameter", "discovery", "archive"]
                if param_classification["category"]:
                    tags.append(param_classification["category"])
                if param_classification["risk_level"]:
                    tags.append(f"risk_{param_classification['risk_level']}")

                finding = create_finding(
                    finding_type="param",
                    target="unknown",
                    evidence={
                        "parameter_name": line,
                        "discovered_by": "paramspider",
                        "source": "web_archive",
                        "security_classification": param_classification,
                        "parameter_type": param_classification["category"],
                        "risk_level": param_classification["risk_level"],
                        "attack_vectors": param_classification["attack_vectors"],
                        "follow_up_tools": param_classification["follow_up_tools"],
                    },
                    severity=cast(
                        SeverityLevel,
                        _map_risk_to_severity(param_classification["risk_level"]),
                    ),
                    confidence=cast(ConfidenceLevel, "low"),
                    tags=tags,
                    raw_ref=line,
                )
                findings.append(finding)

    return findings


def _parse_paramspider_result(
    execution_result, params, command, started_at: datetime, ended_at: datetime
) -> dict[str, Any]:
    """Parse paramspider execution result and format response with findings."""
    duration_ms = int((ended_at - started_at).total_seconds() * 1000)

    if not execution_result["success"]:
        return {
            "findings": [],
            "stats": create_stats(0, 0, 0),
            "security_summary": {
                "parameters_by_risk": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "parameters_by_category": {},
                "total_security_relevant": 0,
            },
        }

    # Parse output into structured findings
    stdout = execution_result.get("stdout", "")
    findings = _parse_paramspider_output(stdout)

    # Remove duplicates based on parameter name and target
    seen_params = set()
    unique_findings = []
    dupes_count = 0

    # Track security metrics
    risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    category_counts = {}

    for finding in findings:
        param_name = finding["evidence"]["parameter_name"]
        target = finding["target"]
        unique_key = f"{target}:{param_name}"

        if unique_key not in seen_params:
            seen_params.add(unique_key)
            unique_findings.append(finding)

            # Count security classifications
            risk_level = finding["evidence"].get("risk_level", "low")
            if risk_level in risk_counts:
                risk_counts[risk_level] += 1

            category = finding["evidence"].get("parameter_type", "generic")
            category_counts[category] = category_counts.get(category, 0) + 1
        else:
            dupes_count += 1

    payload_bytes = len(stdout.encode("utf-8"))

    # Calculate security-relevant parameters
    total_security_relevant = (
        risk_counts["critical"] + risk_counts["high"] + risk_counts["medium"]
    )

    return {
        "findings": unique_findings,
        "stats": create_stats(len(unique_findings), dupes_count, payload_bytes),
        "security_summary": {
            "parameters_by_risk": risk_counts,
            "parameters_by_category": category_counts,
            "total_security_relevant": total_security_relevant,
            "security_coverage_percentage": (
                total_security_relevant / len(unique_findings) * 100
            )
            if unique_findings
            else 0,
        },
        "parameters_used": params,
        "execution_result": execution_result,
        "duration_ms": duration_ms,
    }


@tool(required_fields=["domain"])
def execute_paramspider():
    """Execute ParamSpider for parameter mining from web archives."""
    data = request.get_json()
    params = _extract_paramspider_params(data)

    logger.info(f"Executing ParamSpider on {params['domain']}")

    started_at = datetime.now()
    command = _build_paramspider_command(params)
    execution_result = execute_command(
        command, timeout=600
    )  # 10 minutes timeout for paramspider
    ended_at = datetime.now()

    return _parse_paramspider_result(
        execution_result, params, command, started_at, ended_at
    )
