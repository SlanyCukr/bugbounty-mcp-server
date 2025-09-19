"""x8 tool implementation."""

import logging
import re
import subprocess
import time
from typing import Any
from urllib.parse import urlparse

from flask import request

from src.rest_api_server.utils.registry import tool

logger = logging.getLogger(__name__)


def _validate_x8_inputs(data: dict[str, Any]) -> list[str]:
    """Validate X8 input parameters to prevent injection attacks.

    Args:
        data: Input parameters dictionary

    Returns:
        List of validation error messages
    """
    errors = []

    # Validate URL
    url = data.get("url", "")
    if not url:
        errors.append("URL is required")
    else:
        try:
            parsed = urlparse(url)
            if not all([parsed.scheme, parsed.netloc]):
                errors.append("URL must include scheme and domain")
            if parsed.scheme not in ["http", "https"]:
                errors.append("URL scheme must be http or https")
        except Exception:
            errors.append("Invalid URL format")

    # Validate method
    method = data.get("method", "GET")
    if method not in ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]:
        errors.append(f"Invalid HTTP method: {method}")

    # Validate wordlist path if provided
    wordlist = data.get("wordlist")
    if wordlist:
        # Only allow specific paths to prevent path traversal
        allowed_wordlist_dirs = [
            "/usr/share/wordlists/",
            "/opt/wordlists/",
            "/tmp/wordlists/",
            "./wordlists/",
        ]
        if not any(
            wordlist.startswith(allowed_dir) for allowed_dir in allowed_wordlist_dirs
        ):
            errors.append("Wordlist path not in allowed directories")
        if ".." in wordlist or wordlist.startswith("/"):
            if not wordlist.startswith(tuple(allowed_wordlist_dirs)):
                errors.append("Wordlist path contains invalid characters")

    # Validate headers
    headers = data.get("headers")
    if headers:
        if isinstance(headers, str):
            # Check for command injection patterns in header string
            dangerous_patterns = [";", "|", "&", "`", "$", "(", ")", "\\"]
            if any(pattern in headers for pattern in dangerous_patterns):
                errors.append("Headers contain potentially dangerous characters")
        elif isinstance(headers, dict):
            for key, value in headers.items():
                if not isinstance(key, str) or not isinstance(value, str):
                    errors.append("Header keys and values must be strings")
                # Check for injection patterns
                for item in [key, value]:
                    if any(
                        pattern in item
                        for pattern in [";", "|", "&", "`", "$", "(", ")"]
                    ):
                        errors.append(f"Header contains dangerous characters: {item}")

    # Validate numeric parameters
    workers = data.get("workers", 25)
    if not isinstance(workers, int) or workers < 1 or workers > 100:
        errors.append("Workers must be an integer between 1 and 100")

    max_params = data.get("max", 0)
    if not isinstance(max_params, int) or max_params < 0:
        errors.append("Max must be a non-negative integer")

    # Validate body content
    body = data.get("body")
    if body and not isinstance(body, str):
        errors.append("Body must be a string")

    # Validate output file path
    output_file = data.get("output_file")
    if output_file:
        # Prevent path traversal and restrict to safe directories
        if ".." in output_file or not output_file.startswith(("/tmp/", "./output/")):
            errors.append("Output file path not in allowed directories")

    return errors


def _apply_discovery_profile(data: dict[str, Any], profile: str) -> dict[str, Any]:
    """Apply discovery profile configuration to parameters.

    Args:
        data: Base parameters
        profile: Discovery profile name

    Returns:
        Updated parameters dictionary

    Raises:
        ValueError: If profile is invalid
    """
    # Base configuration
    params = {
        "url": data["url"],
        "wordlist": data.get("wordlist", "/usr/share/wordlists/x8/params.txt"),
        "method": data.get("method", "GET"),
        "body": data.get("body", ""),
        "headers": data.get("headers", ""),
        "output_file": data.get("output_file", ""),
        "discover": data.get("discover", True),
        "learn": data.get("learn", False),
        "verify": data.get("verify", True),
        "max": data.get("max", 0),
        "workers": data.get("workers", 25),
        "as_body": data.get("as_body", False),
        "encode": data.get("encode", False),
        "force": data.get("force", False),
        "additional_args": data.get("additional_args", ""),
    }

    # Apply profile-specific configurations
    if profile == "standard":
        # Default configuration - already set above
        pass
    elif profile == "aggressive":
        params.update(
            {
                "workers": 50,
                "max": 1000,
                "force": True,
                "learn": True,
            }
        )
    elif profile == "body-inverted":
        params.update(
            {
                "as_body": True,
                "method": "POST",
                "workers": 30,
            }
        )
    elif profile == "learning-enabled":
        params.update(
            {
                "learn": True,
                "workers": 40,
                "max": 500,
            }
        )
    elif profile == "fast":
        params.update(
            {
                "workers": 20,
                "max": 100,
                "learn": False,
                "verify": False,
            }
        )
    elif profile == "force":
        params.update(
            {
                "force": True,
                "workers": 35,
                "max": 800,
            }
        )
    elif profile == "multi-method":
        params.update(
            {
                "method": "GET",  # Will be handled in command building
                # for multiple methods
                "workers": 25,
                "multi_method": True,
            }
        )
    else:
        raise ValueError(f"Unknown discovery profile: {profile}")

    return params


def _build_x8_command_args(url: str, params: dict[str, Any]) -> list[str]:
    """Build secure X8 command arguments list.

    Args:
        url: Target URL (already validated)
        params: X8 parameters (already validated)

    Returns:
        List of command arguments

    Raises:
        ValueError: If parameters are invalid for command construction
    """
    args = ["x8", "-u", url]

    # Add HTTP method
    if params.get("method"):
        args.extend(["-X", params["method"]])

    # Add wordlist
    if params.get("wordlist"):
        args.extend(["-w", params["wordlist"]])

    # Add body data
    if params.get("body"):
        args.extend(["-b", params["body"]])

    # Add headers
    headers = params.get("headers")
    if headers:
        if isinstance(headers, str):
            args.extend(["-H", headers])
        elif isinstance(headers, dict):
            for key, value in headers.items():
                args.extend(["-H", f"{key}:{value}"])

    # Add output file
    if params.get("output_file"):
        args.extend(["-o", params["output_file"]])

    # Add workers (concurrency)
    workers = params.get("workers", 25)
    if workers > 1:
        args.extend(["-c", str(workers)])

    # Add max parameters per request
    max_params = params.get("max", 0)
    if max_params > 0:
        args.extend(["-m", str(max_params)])

    # Add boolean flags
    if params.get("verify"):
        args.append("--verify")

    if params.get("encode"):
        args.append("--encode")

    if params.get("force"):
        args.append("--force")

    if params.get("as_body"):
        args.append("--invert")

    if params.get("learn"):
        args.append("--learn")

    # Handle multi-method profile
    if params.get("multi_method"):
        # For multi-method, we'll run multiple commands
        # For now, just use the primary method
        pass

    return args


def _execute_secure_command(
    command_args: list[str], timeout: int = 600
) -> dict[str, Any]:
    """Execute command securely using subprocess with argument list.

    Args:
        command_args: List of command arguments
        timeout: Command timeout in seconds

    Returns:
        Dictionary with execution results
    """
    try:
        logger.info(f"Executing secure command: {' '.join(command_args)}")

        start_time = time.time()
        result = subprocess.run(
            command_args,
            capture_output=True,
            text=True,
            timeout=timeout,
            # Security: shell=False prevents command injection
            shell=False,
        )
        execution_time = time.time() - start_time

        return {
            "success": result.returncode == 0,
            "return_code": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "execution_time": execution_time,
        }

    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out: {' '.join(command_args)}")
        return {
            "success": False,
            "error": "Command timed out",
            "timeout": timeout,
        }
    except FileNotFoundError:
        logger.error("x8 command not found - ensure x8 is installed")
        return {
            "success": False,
            "error": "x8 command not found",
        }
    except Exception as e:
        logger.error(f"Error executing command: {str(e)}")
        return {
            "success": False,
            "error": str(e),
        }


def _parse_x8_output(output: str) -> list[dict[str, Any]]:
    """Parse X8 output to extract discovered parameters.

    Args:
        output: Raw X8 stdout output

    Returns:
        List of discovered parameter dictionaries
    """
    discovered_parameters = []

    if not output:
        return discovered_parameters

    lines = output.split("\n")
    for line in lines:
        line = line.strip()
        if not line:
            continue

        # X8 output patterns (updated based on actual tool behavior)
        param_info = _extract_parameter_from_line(line)
        if param_info:
            discovered_parameters.append(param_info)

    return discovered_parameters


def _extract_parameter_from_line(line: str) -> dict[str, Any] | None:
    """Extract parameter information from a single output line.

    Args:
        line: Single line from X8 output

    Returns:
        Parameter info dictionary or None
    """
    # X8 typically outputs in formats like:
    # [INFO] Found parameter: param_name
    # [FOUND] GET parameter: test=value
    # param_name -> GET

    param_patterns = [
        # Pattern 1: [INFO] Found parameter: param_name
        r"\[INFO\].*Found parameter:?\s*([a-zA-Z_][a-zA-Z0-9_]*)",
        # Pattern 2: [FOUND] METHOD parameter: param=value
        r"\[FOUND\]\s*(\w+)\s+parameter:?\s*([a-zA-Z_][a-zA-Z0-9_]*)",
        # Pattern 3: param_name -> METHOD
        r"([a-zA-Z_][a-zA-Z0-9_]*)\s*->\s*(\w+)",
        # Pattern 4: Simple param discovery
        r"^([a-zA-Z_][a-zA-Z0-9_]*)\s*$",
    ]

    for pattern in param_patterns:
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            groups = match.groups()

            if len(groups) == 1:
                # Simple parameter name
                param_name = groups[0]
                return {
                    "name": param_name,
                    "method": "GET",  # Default
                    "confidence": "medium",
                    "raw_line": line,
                    "discovery_method": "brute_force",
                }
            elif len(groups) == 2:
                # Parameter with method or method with parameter
                if groups[1].upper() in ["GET", "POST", "PUT", "PATCH", "DELETE"]:
                    # Format: param -> METHOD
                    return {
                        "name": groups[0],
                        "method": groups[1].upper(),
                        "confidence": "high",
                        "raw_line": line,
                        "discovery_method": "brute_force",
                    }
                else:
                    # Format: METHOD parameter: param
                    return {
                        "name": groups[1],
                        "method": groups[0].upper(),
                        "confidence": "high",
                        "raw_line": line,
                        "discovery_method": "brute_force",
                    }

    # If no patterns match but line contains parameter-like content
    if any(
        keyword in line.lower()
        for keyword in ["parameter", "param", "found", "discovered"]
    ):
        return {"raw_line": line, "parse_status": "unparsed", "confidence": "low"}

    return None


def _classify_parameters(parameters: list[dict[str, Any]]) -> dict[str, Any]:
    """Classify discovered parameters by type and category.

    Args:
        parameters: List of discovered parameters

    Returns:
        Classification summary dictionary
    """
    classification = {
        "by_method": {
            "GET": 0,
            "POST": 0,
            "PUT": 0,
            "PATCH": 0,
            "DELETE": 0,
            "UNKNOWN": 0,
        },
        "by_category": {
            "authentication": 0,
            "data_handling": 0,
            "navigation": 0,
            "configuration": 0,
            "security": 0,
            "technical": 0,
            "other": 0,
        },
        "by_confidence": {"high": 0, "medium": 0, "low": 0, "unknown": 0},
        "by_discovery_method": {
            "brute_force": 0,
            "pattern": 0,
            "inference": 0,
            "learning": 0,
            "unknown": 0,
        },
    }

    # Parameter category keywords
    category_keywords = {
        "authentication": [
            "auth",
            "login",
            "password",
            "token",
            "session",
            "csrf",
            "user",
            "uid",
        ],
        "data_handling": [
            "data",
            "content",
            "file",
            "upload",
            "download",
            "export",
            "import",
        ],
        "navigation": [
            "page",
            "offset",
            "limit",
            "sort",
            "order",
            "filter",
            "search",
            "query",
        ],
        "configuration": [
            "config",
            "setting",
            "option",
            "mode",
            "view",
            "layout",
            "theme",
        ],
        "security": [
            "key",
            "secret",
            "nonce",
            "signature",
            "captcha",
            "verify",
            "hash",
        ],
        "technical": [
            "debug",
            "test",
            "dev",
            "env",
            "version",
            "format",
            "callback",
            "api",
        ],
    }

    for param in parameters:
        # Skip unparsed parameters
        if not param.get("name"):
            continue

        param_name = param["name"].lower()

        # Classify by method
        method = param.get("method", "UNKNOWN").upper()
        if method in classification["by_method"]:
            classification["by_method"][method] += 1
        else:
            classification["by_method"]["UNKNOWN"] += 1

        # Classify by category
        categorized = False
        for category, keywords in category_keywords.items():
            if any(keyword in param_name for keyword in keywords):
                classification["by_category"][category] += 1
                categorized = True
                break

        if not categorized:
            classification["by_category"]["other"] += 1

        # Classify by confidence
        confidence = param.get("confidence", "unknown")
        if confidence in classification["by_confidence"]:
            classification["by_confidence"][confidence] += 1
        else:
            classification["by_confidence"]["unknown"] += 1

        # Classify by discovery method
        discovery_method = param.get("discovery_method", "unknown")
        if discovery_method in classification["by_discovery_method"]:
            classification["by_discovery_method"][discovery_method] += 1
        else:
            classification["by_discovery_method"]["unknown"] += 1

    return classification


def _calculate_performance_metrics(
    parameters: list[dict[str, Any]], execution_time: float, params: dict[str, Any]
) -> dict[str, Any]:
    """Calculate performance metrics for X8 execution.

    Args:
        parameters: Discovered parameters
        execution_time: Total execution time
        params: X8 parameters used

    Returns:
        Performance metrics dictionary
    """
    metrics = {
        "parameters_found": len(parameters),
        "execution_time_seconds": execution_time,
        "parameters_per_second": 0.0,
        "workers_used": params.get("workers", 25),
        "discovery_efficiency": 0.0,
        "learning_mode_used": params.get("learn", False),
        "verification_used": params.get("verify", True),
        "force_mode_used": params.get("force", False),
    }

    if execution_time > 0:
        metrics["parameters_per_second"] = len(parameters) / execution_time

        # Discovery efficiency: parameters found per second per worker
        if params.get("workers", 25) > 0:
            metrics["discovery_efficiency"] = (
                metrics["parameters_per_second"] / params["workers"]
            )

    return metrics


def _extract_discovery_methods(params: dict[str, Any]) -> set[str]:
    """Extract discovery methods used based on parameters.

    Args:
        params: X8 parameters

    Returns:
        Set of discovery method names
    """
    methods = set()

    if params.get("discover", True):
        methods.add("discover")
    if params.get("learn", False):
        methods.add("learn")
    if params.get("verify", True):
        methods.add("verify")
    if params.get("force", False):
        methods.add("force")
    if params.get("encode", False):
        methods.add("encode")
    if params.get("as_body", False):
        methods.add("body-invert")

    return methods


@tool(required_fields=["url"])
def execute_x8():
    """Execute x8 for hidden parameter discovery."""
    data = request.get_json()
    url = data["url"]

    logger.info(f"Executing x8 on {url}")

    # Validate input parameters before use
    validation_errors = _validate_x8_inputs(data)
    if validation_errors:
        return {
            "tool": "x8",
            "status": "failed",
            "error": "Input validation failed",
            "validation_errors": validation_errors,
            "target": url,
        }

    # Determine discovery profile
    profile = data.get("profile", "standard")

    # Apply discovery profile configuration
    try:
        x8_params = _apply_discovery_profile(data, profile)
    except ValueError as e:
        return {
            "tool": "x8",
            "status": "failed",
            "error": f"Profile configuration error: {str(e)}",
            "target": url,
        }

    # Build secure x8 command using argument list
    try:
        command_args = _build_x8_command_args(url, x8_params)
    except ValueError as e:
        return {
            "tool": "x8",
            "status": "failed",
            "error": f"Command construction error: {str(e)}",
            "target": url,
        }

    # Execute the command securely
    logger.info(f"Executing x8 with profile '{profile}' on {url}")
    start_time = time.time()
    cmd_result = _execute_secure_command(command_args, timeout=600)
    execution_time = time.time() - start_time

    # Parse x8 output to extract discovered parameters
    discovered_parameters = _parse_x8_output(cmd_result.get("stdout", ""))

    # Classify parameters by type
    parameter_classification = _classify_parameters(discovered_parameters)

    # Track performance metrics
    performance_metrics = _calculate_performance_metrics(
        discovered_parameters, execution_time, x8_params
    )

    # Create comprehensive result structure
    result = {
        "tool": "x8",
        "target": url,
        "profile": profile,
        "parameters": x8_params,
        "command_args": [str(arg) for arg in command_args],  # Safe to log
        "status": "completed" if cmd_result["success"] else "failed",
        "raw_output": cmd_result["stdout"],
        "stderr": cmd_result["stderr"],
        "return_code": cmd_result["return_code"],
        "execution_time": execution_time,
        "discovered_parameters": discovered_parameters,
        "parameter_count": len(discovered_parameters),
        "parameter_classification": parameter_classification,
        "performance_metrics": performance_metrics,
        "discovery_methods": _extract_discovery_methods(x8_params),
        "success": cmd_result["success"] and len(discovered_parameters) >= 0,
    }

    return result
