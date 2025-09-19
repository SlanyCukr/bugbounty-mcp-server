"""waybackurls tool implementation."""

import logging
import re
import shlex
import subprocess
from typing import Any

from flask import request

from src.rest_api_server.utils.registry import tool

logger = logging.getLogger(__name__)

# Aggressive preset for waybackurls
AGGRESSIVE_PRESET = {
    "no_subs": False,  # Include subdomains
    "get_versions": True,
    "timeout": 120,
}


def _validate_domain(domain: str) -> str:
    """Validate and sanitize domain parameter."""
    if not domain:
        raise ValueError("Domain is required")

    # Remove any potential shell metacharacters and validate domain format
    domain = domain.strip()

    # Basic domain validation - allow alphanumeric, dots, hyphens, and underscores
    if not re.match(r"^[a-zA-Z0-9.-]+$", domain):
        raise ValueError(f"Invalid domain format: {domain}")

    # Prevent command injection attempts
    dangerous_chars = ["&", "|", ";", "`", "$", "(", ")", "<", ">", '"', "'", "\\"]
    for char in dangerous_chars:
        if char in domain:
            raise ValueError(f"Invalid character in domain: {char}")

    return domain


def _validate_boolean(value) -> bool:
    """Validate boolean parameter."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ("true", "1", "yes", "on")
    return bool(value)


def _validate_dates(dates: str) -> str:
    """Validate and sanitize dates parameter."""
    if not dates:
        return ""

    dates = dates.strip()

    # Basic date range validation (format: YYYYMMDD:YYYYMMDD)
    if dates and not re.match(r"^\d{8}:\d{8}$", dates):
        raise ValueError(
            f"Invalid date format: {dates}. Expected format: YYYYMMDD:YYYYMMDD"
        )

    return dates


def _validate_output_file(output_file: str) -> str:
    """Validate and sanitize output file parameter."""
    if not output_file:
        return ""

    output_file = output_file.strip()

    # Basic file path validation - prevent path traversal
    if ".." in output_file or output_file.startswith("/"):
        raise ValueError(f"Invalid output file path: {output_file}")

    # Only allow safe characters in filename
    if not re.match(r"^[a-zA-Z0-9._-]+$", output_file):
        raise ValueError(f"Invalid output file name: {output_file}")

    return output_file


def _validate_timeout(timeout) -> int:
    """Validate timeout parameter."""
    try:
        timeout_val = int(timeout)
        if timeout_val < 1 or timeout_val > 3600:  # 1 second to 1 hour
            raise ValueError(
                f"Timeout must be between 1 and 3600 seconds: {timeout_val}"
            )
        return timeout_val
    except (ValueError, TypeError) as err:
        raise ValueError(f"Invalid timeout value: {timeout}") from err


def _validate_additional_args(additional_args: str) -> str:
    """Validate and sanitize additional arguments."""
    if not additional_args:
        return ""

    additional_args = additional_args.strip()

    # Check for dangerous patterns that could lead to command injection
    dangerous_patterns = [
        r"[;&|`$()]",  # Shell metacharacters
        r"rm\s",  # File deletion
        r"wget\s",  # Network downloads
        r"curl\s",  # Network requests
        r"nc\s",  # Netcat
        r">/dev/",  # Device writes
    ]

    for pattern in dangerous_patterns:
        if re.search(pattern, additional_args, re.IGNORECASE):
            raise ValueError(
                f"Potentially dangerous argument pattern detected: {additional_args}"
            )

    return additional_args


def _extract_waybackurls_params(data) -> dict[str, Any]:
    """Extract and validate waybackurls parameters from request data."""
    # Check for aggressive mode
    aggressive = data.get("aggressive", False)

    # Extract and validate domain/URL
    domain = _validate_domain(data.get("url", data.get("domain", "")))

    # Base parameters with proper validation
    base_params = {
        "domain": domain,
        "no_subs": _validate_boolean(data.get("no_subs", False)),
        "get_versions": _validate_boolean(data.get("get_versions", False)),
        "dates": _validate_dates(data.get("dates", "")),
        "output_file": _validate_output_file(data.get("output_file", "")),
        "timeout": _validate_timeout(data.get("timeout", 30)),
        "additional_args": _validate_additional_args(data.get("additional_args", "")),
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
            if key in ["no_subs", "get_versions", "timeout"] and user_params.get(
                key
            ) in [True, False, 30, None]:
                merged_params[key] = aggressive_value

    return merged_params


def _build_waybackurls_command(params) -> list[str]:
    """Build waybackurls command from parameters to prevent injection."""
    command_args = ["waybackurls", params["domain"]]

    if params["get_versions"]:
        command_args.append("--get-versions")

    if params["no_subs"]:
        command_args.append("--no-subs")

    if params["dates"]:
        command_args.extend(["--dates", params["dates"]])

    if params["output_file"]:
        command_args.extend(["-o", params["output_file"]])

    # Parse additional args safely
    if params["additional_args"]:
        try:
            additional_parsed = shlex.split(params["additional_args"])
            command_args.extend(additional_parsed)
        except ValueError as e:
            logger.warning(
                f"Invalid additional args: {params['additional_args']}, error: {e}"
            )
            # Skip invalid additional args rather than failing

    return command_args


def _parse_waybackurls_result(execution_result, params, command_args) -> dict[str, Any]:
    """Parse waybackurls execution result and format response."""
    command_str = " ".join(command_args)  # For logging only

    if execution_result["success"]:
        urls = [
            url.strip() for url in execution_result["stdout"].split("\n") if url.strip()
        ]

        return {
            "tool": "waybackurls",
            "target": params["domain"],
            "parameters": params,
            "status": "completed",
            "urls": urls,
            "unique_urls": len(urls),
            "command": command_str,
            "success": True,
            "stdout": execution_result["stdout"],
            "stderr": execution_result["stderr"]
            if execution_result["stderr"]
            else None,
        }
    else:
        default_error = "Unknown error"
        error_msg = execution_result.get(
            "error", execution_result.get("stderr", default_error)
        )
        logger.error(
            "Waybackurls command failed: "
            f"{execution_result.get('error', 'Unknown error')}"
        )
        return {
            "tool": "waybackurls",
            "target": params["domain"],
            "parameters": params,
            "command": command_str,
            "success": False,
            "status": "failed",
            "error": f"Waybackurls execution failed: {error_msg}",
        }


def _execute_secure_command(
    command_args: list[str], timeout: int = 300
) -> dict[str, Any]:
    """Execute command securely using subprocess.run with argument list."""
    try:
        command_str = " ".join(command_args)  # For logging only
        logger.info(f"Executing command: {command_str}")

        result = subprocess.run(
            command_args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        return {
            "success": result.returncode == 0,
            "return_code": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "command": command_str,
        }

    except subprocess.TimeoutExpired:
        command_str = " ".join(command_args)
        logger.error(f"Command timed out: {command_str}")
        return {
            "success": False,
            "error": "Command timed out",
            "command": command_str,
            "timeout": timeout,
        }
    except Exception as e:
        command_str = " ".join(command_args)
        logger.error(f"Error executing command: {str(e)}")
        return {"success": False, "error": str(e), "command": command_str}


@tool(required_fields=["domain"])
def execute_waybackurls():
    """Execute Waybackurls for historical URL discovery."""
    data = request.get_json()
    params = _extract_waybackurls_params(data)

    logger.info(f"Executing Waybackurls on {params['domain']}")

    command_args = _build_waybackurls_command(params)
    execution_result = _execute_secure_command(command_args, params["timeout"])

    return _parse_waybackurls_result(execution_result, params, command_args)
