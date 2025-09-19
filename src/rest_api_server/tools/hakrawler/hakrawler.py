"""hakrawler tool implementation."""

import logging
import re
import shlex
from urllib.parse import urlparse

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import tool

logger = logging.getLogger(__name__)


def _validate_url(url):
    """Validate URL format to prevent command injection.

    Args:
        url: URL to validate

    Returns:
        bool: True if URL is valid and safe
    """
    if not url or not isinstance(url, str):
        return False

    # Check for dangerous characters that could enable command injection
    dangerous_chars = [";", "|", "&", "`", "$", "(", ")", "<", ">", "\n", "\r"]
    if any(char in url for char in dangerous_chars):
        return False

    try:
        parsed = urlparse(url)
        # Must have scheme and netloc
        if not parsed.scheme or not parsed.netloc:
            return False
        # Only allow http/https schemes
        if parsed.scheme not in ["http", "https"]:
            return False
        return True
    except Exception:
        return False


def _validate_additional_args(args):
    """Validate additional arguments to prevent command injection.

    Args:
        args: Additional arguments string

    Returns:
        bool: True if arguments are safe
    """
    if not args or not isinstance(args, str):
        return True

    # Check for dangerous characters and patterns
    dangerous_patterns = [
        ";",
        "|",
        "&",
        "`",
        "$",
        "$(",
        "${",
        "&&",
        "||",
        "\n",
        "\r",
        ">",
        "<",
        "*",
        "?",
        "[",
        "]",
        "rm ",
        "del ",
        "format ",
        "kill ",
        "sudo ",
        "su ",
        "/etc/",
        "/bin/",
        "/usr/",
        "/var/",
        "/tmp/",
    ]

    args_lower = args.lower()
    for pattern in dangerous_patterns:
        if pattern in args_lower:
            return False

    # Only allow safe hakrawler arguments
    safe_patterns = [
        r"^-[a-zA-Z][\w\-]*$",  # Single flags like -v, -silent
        r"^-[a-zA-Z][\w\-]*\s+\d+$",  # Flags with numbers like -rate-limit 100
        r"^-[a-zA-Z][\w\-]*\s+[\w\-\.]+$",  # Flags with safe values
    ]

    # Split args and validate each part
    try:
        arg_parts = shlex.split(args)
        for arg in arg_parts:
            if not any(re.match(pattern, arg) for pattern in safe_patterns):
                # Allow some specific safe arguments
                if arg not in ["-silent", "-v", "-json", "-plain"]:
                    return False
        return True
    except Exception:
        return False


def _extract_hakrawler_params(data):
    """Extract and validate hakrawler parameters from request data."""
    url = data["url"]
    depth = data.get("depth", 2)
    forms = data.get("forms", True)
    robots = data.get("robots", True)
    sitemap = data.get("sitemap", True)
    wayback = data.get("wayback", False)
    insecure = data.get("insecure", False)
    additional_args = data.get("additional_args", "")

    # CRITICAL SECURITY FIX: Validate URL format to prevent injection
    if not _validate_url(url):
        raise ValueError(f"Invalid URL format: {url}")

    # CRITICAL SECURITY FIX: Validate depth parameter
    if not isinstance(depth, int) or depth < 1 or depth > 10:
        raise ValueError(f"Invalid depth parameter: {depth}. Must be integer 1-10")

    # CRITICAL SECURITY FIX: Validate boolean parameters
    for param_name, param_value in [
        ("forms", forms),
        ("robots", robots),
        ("sitemap", sitemap),
        ("wayback", wayback),
        ("insecure", insecure),
    ]:
        if not isinstance(param_value, bool):
            raise ValueError(
                f"Invalid {param_name} parameter: {param_value}. Must be boolean"
            )

    # CRITICAL SECURITY FIX: Sanitize additional_args to prevent injection
    if additional_args and not _validate_additional_args(additional_args):
        raise ValueError(
            "Invalid additional_args: contains potentially unsafe characters"
        )

    return {
        "url": url,
        "depth": depth,
        "forms": forms,
        "robots": robots,
        "sitemap": sitemap,
        "wayback": wayback,
        "insecure": insecure,
        "additional_args": additional_args,
    }


def _build_hakrawler_command(params):
    """Build secure hakrawler command from parameters using proper escaping.

    Args:
        params: Validated parameters dictionary

    Returns:
        str: Safe command string
    """
    # CRITICAL SECURITY FIX: Use array-based command construction and proper escaping
    command_parts = ["hakrawler"]

    # Add URL with proper escaping - this is the critical fix
    command_parts.extend(["-url", shlex.quote(params["url"])])

    # Add depth parameter with validation
    command_parts.extend(["-depth", str(int(params["depth"]))])

    # Add boolean flags only if enabled
    if params["forms"]:
        command_parts.append("-forms")
    if params["robots"]:
        command_parts.append("-robots")
    if params["sitemap"]:
        command_parts.append("-sitemap")
    if params["wayback"]:
        command_parts.append("-wayback")
    if params["insecure"]:
        command_parts.append("-insecure")

    # CRITICAL SECURITY FIX: Handle additional arguments securely
    if params["additional_args"]:
        # Split and validate each argument individually
        try:
            additional_parts = shlex.split(params["additional_args"])
            # Each part is already validated by _validate_additional_args
            command_parts.extend(additional_parts)
        except ValueError:
            # If shlex.split fails, the args are malformed - skip them for security
            logger.warning(
                "Malformed additional_args detected and ignored for security"
            )

    # Join with spaces to create final command
    return " ".join(command_parts)


def _parse_hakrawler_result(execution_result, params, command):
    """Parse hakrawler execution result and format response."""
    return {
        "tool": "hakrawler",
        "target": params["url"],
        "parameters": params,
        "command": command,
        "success": execution_result["success"],
        "stdout": execution_result["stdout"],
        "stderr": execution_result["stderr"],
        "return_code": execution_result["return_code"],
    }


def _calculate_execution_timeout(params):
    """Calculate appropriate timeout based on crawling parameters.

    Args:
        params: Validated hakrawler parameters

    Returns:
        int: Timeout in seconds
    """
    base_timeout = 60  # Base timeout of 1 minute

    # Add timeout based on depth (more depth = more time needed)
    depth = params.get("depth", 2)
    depth_timeout = depth * 30  # 30 seconds per depth level

    # Add timeout for enabled features
    feature_timeout = 0
    if params.get("forms", False):
        feature_timeout += 30  # Forms discovery adds time
    if params.get("robots", False):
        feature_timeout += 15  # Robots.txt processing
    if params.get("sitemap", False):
        feature_timeout += 15  # Sitemap processing
    if params.get("wayback", False):
        feature_timeout += 60  # Wayback integration adds significant time

    # Calculate total timeout with reasonable maximum
    total_timeout = base_timeout + depth_timeout + feature_timeout

    # Cap at reasonable maximum (10 minutes) to prevent runaway processes
    max_timeout = 600
    final_timeout = min(total_timeout, max_timeout)

    logger.debug(
        f"Timeout calculation: base={base_timeout}, depth={depth_timeout}, "
        f"features={feature_timeout}, total={final_timeout}"
    )

    return final_timeout


def _parse_hakrawler_result_with_error_handling(
    execution_result, params, command, execution_time_ms
):
    """Parse hakrawler execution result with comprehensive error handling.

    Args:
        execution_result: Result from execute_command
        params: Hakrawler parameters used
        command: Command that was executed
        execution_time_ms: Actual execution time in milliseconds

    Returns:
        dict: Parsed result with error handling
    """
    try:
        # Base result structure
        result = {
            "tool": "hakrawler",
            "target": params["url"],
            "parameters": params,
            "command": command,
            "execution_time_ms": execution_time_ms,
            "success": execution_result.get("success", False),
            "stdout": execution_result.get("stdout", ""),
            "stderr": execution_result.get("stderr", ""),
            "return_code": execution_result.get("return_code", -1),
        }

        # Handle timeout specifically
        if execution_result.get("error") == "Command timed out":
            result.update(
                {
                    "success": False,
                    "error": f"Command timed out after {execution_time_ms}ms",
                    "error_type": "timeout_error",
                    "timeout_occurred": True,
                }
            )
            return result

        # Handle general command execution failures
        if not execution_result.get("success", False):
            error_msg = execution_result.get("error", "Unknown execution error")
            result.update(
                {
                    "error": error_msg,
                    "error_type": "command_execution_error",
                }
            )

            # Add specific error categorization based on stderr content
            stderr = execution_result.get("stderr", "").lower()
            if "permission denied" in stderr:
                result["error_type"] = "permission_error"
            elif "no such file" in stderr or "command not found" in stderr:
                result["error_type"] = "binary_not_found"
            elif "connection" in stderr or "network" in stderr or "timeout" in stderr:
                result["error_type"] = "network_error"
            elif "invalid" in stderr or "malformed" in stderr:
                result["error_type"] = "invalid_target"

            return result

        # For successful executions, add additional metadata
        stdout = execution_result.get("stdout", "")
        if stdout:
            # Count discovered URLs
            urls = [line.strip() for line in stdout.strip().split("\n") if line.strip()]
            result["urls_discovered"] = len(urls)
            result["unique_urls"] = len(set(urls))

            # Calculate crawl speed
            if execution_time_ms > 0:
                urls_per_second = (len(urls) * 1000) / execution_time_ms
                result["crawl_speed"] = round(urls_per_second, 2)
        else:
            result["urls_discovered"] = 0
            result["unique_urls"] = 0
            result["crawl_speed"] = 0.0

            # If no output but success=True, it might be a warning scenario
            if result["success"]:
                result["warning"] = "Execution completed but no URLs discovered"

        return result

    except Exception as e:
        logger.error(f"Error parsing hakrawler result: {e}")
        # Return a minimal error result if parsing fails
        return {
            "tool": "hakrawler",
            "target": params.get("url", "unknown"),
            "parameters": params,
            "command": command,
            "execution_time_ms": execution_time_ms,
            "success": False,
            "error": f"Result parsing failed: {str(e)}",
            "error_type": "parsing_error",
            "return_code": -1,
        }


@tool(required_fields=["url"])
def execute_hakrawler():
    """Execute hakrawler for fast web crawling and endpoint discovery."""
    data = request.get_json()

    # COMPREHENSIVE ERROR HANDLING: Wrap entire execution in try-catch
    try:
        # CRITICAL SECURITY FIX: Extract and validate parameters with error handling
        params = _extract_hakrawler_params(data)
    except ValueError as e:
        logger.error(f"Parameter validation failed: {e}")
        return {
            "tool": "hakrawler",
            "target": data.get("url", "unknown"),
            "success": False,
            "error": f"Parameter validation failed: {str(e)}",
            "error_type": "validation_error",
            "return_code": -1,
            "execution_time_ms": 0,
        }
    except Exception as e:
        logger.error(f"Unexpected error during parameter extraction: {e}")
        return {
            "tool": "hakrawler",
            "target": data.get("url", "unknown"),
            "success": False,
            "error": f"Unexpected parameter error: {str(e)}",
            "error_type": "system_error",
            "return_code": -1,
            "execution_time_ms": 0,
        }

    logger.info(f"Executing hakrawler on {params['url']}")

    # Record start time for timeout management
    import time

    start_time = time.time()

    try:
        # CRITICAL SECURITY FIX: Build secure command
        command = _build_hakrawler_command(params)

        # TIMEOUT MANAGEMENT: Determine appropriate timeout based on depth and features
        timeout = _calculate_execution_timeout(params)
        logger.info(f"Using timeout of {timeout} seconds for hakrawler execution")

        # Add comprehensive error handling for command execution
        execution_result = execute_command(command, timeout=timeout)

        # Calculate actual execution time
        end_time = time.time()
        execution_time_ms = int((end_time - start_time) * 1000)

        # Enhanced result parsing with error handling
        result = _parse_hakrawler_result_with_error_handling(
            execution_result, params, command, execution_time_ms
        )

        return result

    except TimeoutError as e:
        execution_time_ms = int((time.time() - start_time) * 1000)
        logger.error(f"Hakrawler execution timed out after {execution_time_ms}ms: {e}")
        return {
            "tool": "hakrawler",
            "target": params["url"],
            "parameters": params,
            "success": False,
            "error": f"Execution timed out after {execution_time_ms}ms",
            "error_type": "timeout_error",
            "return_code": -1,
            "execution_time_ms": execution_time_ms,
            "timeout_occurred": True,
        }
    except PermissionError as e:
        execution_time_ms = int((time.time() - start_time) * 1000)
        logger.error(f"Permission denied executing hakrawler: {e}")
        return {
            "tool": "hakrawler",
            "target": params["url"],
            "parameters": params,
            "success": False,
            "error": f"Permission denied: {str(e)}",
            "error_type": "permission_error",
            "return_code": -1,
            "execution_time_ms": execution_time_ms,
        }
    except FileNotFoundError as e:
        execution_time_ms = int((time.time() - start_time) * 1000)
        logger.error(f"Hakrawler binary not found: {e}")
        return {
            "tool": "hakrawler",
            "target": params["url"],
            "parameters": params,
            "success": False,
            "error": f"Hakrawler binary not found: {str(e)}",
            "error_type": "binary_not_found",
            "return_code": -1,
            "execution_time_ms": execution_time_ms,
        }
    except Exception as e:
        execution_time_ms = int((time.time() - start_time) * 1000)
        logger.error(f"Hakrawler execution failed: {e}")
        return {
            "tool": "hakrawler",
            "target": params["url"],
            "parameters": params,
            "success": False,
            "error": f"Execution failed: {str(e)}",
            "error_type": "execution_error",
            "return_code": -1,
            "execution_time_ms": execution_time_ms,
        }
