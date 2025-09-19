"""katana tool implementation."""

import logging
import re

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import tool

logger = logging.getLogger(__name__)


@tool(required_fields=["url"])
def execute_katana():
    """Execute Katana for next-generation crawling and spidering."""
    data = request.get_json()
    url = data["url"]
    logger.info(f"Executing Katana on {url}")

    # CRITICAL SECURITY FIX: Input validation to prevent command injection
    if not _validate_url(url):
        return {
            "tool": "katana",
            "target": url,
            "status": "failed",
            "error": "Invalid URL format",
            "execution_success": False,
        }

    # Validate and sanitize all parameters to prevent injection attacks
    try:
        katana_params = _validate_and_sanitize_params(data)
    except ValueError as e:
        return {
            "tool": "katana",
            "target": url,
            "status": "failed",
            "error": f"Parameter validation failed: {str(e)}",
            "execution_success": False,
        }

    # Build katana command with proper escaping and validation
    try:
        command_args = _build_secure_command(url, katana_params)
        logger.info("Executing Katana with secure parameters")
    except ValueError as e:
        return {
            "tool": "katana",
            "target": url,
            "status": "failed",
            "error": f"Command construction failed: {str(e)}",
            "execution_success": False,
        }

    # Execute the katana command with timeout
    result = execute_command(" ".join(command_args), timeout=300)

    # Prepare the response based on execution result
    if result["success"]:
        response_result = {
            "tool": "katana",
            "target": url,
            "parameters": katana_params,
            "command": " ".join(command_args),  # Safe to show sanitized command
            "status": "completed" if result["success"] else "failed",
            "stdout": result["stdout"],
            "stderr": result["stderr"],
            "return_code": result["return_code"],
            "execution_success": True,
            "raw_output": result["stdout"],
        }
    else:
        response_result = {
            "tool": "katana",
            "target": url,
            "parameters": katana_params,
            "command": " ".join(command_args),
            "status": "failed",
            "stdout": result["stdout"],
            "stderr": result["stderr"],
            "return_code": result["return_code"],
            "execution_success": False,
            "error": result.get("error", "Command execution failed"),
        }
    return response_result


def _validate_url(url: str) -> bool:
    """Validate URL format and prevent malicious inputs.

    Args:
        url: URL to validate

    Returns:
        True if URL is valid and safe
    """
    import re
    from urllib.parse import urlparse

    if not url or not isinstance(url, str):
        return False

    # Remove whitespace
    url = url.strip()

    # Check for basic URL format
    url_pattern = re.compile(
        r"^https?://"  # http:// or https://
        r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|"  # domain...
        r"localhost|"  # localhost...
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"  # ...or ip
        r"(?::\d+)?"  # optional port
        r"(?:/?|[/?]\S+)$",
        re.IGNORECASE,
    )

    if not url_pattern.match(url):
        return False

    # Additional security checks
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return False

    # Block dangerous protocols and characters
    dangerous_chars = ["`", "$", "|", "&", ";", "(", ")", "<", ">", '"', "'", "\\"]
    for char in dangerous_chars:
        if char in url:
            return False

    return True


def _validate_and_sanitize_params(data: dict) -> dict:
    """Validate and sanitize all input parameters to prevent injection attacks.

    Args:
        data: Raw parameter data from request

    Returns:
        Validated and sanitized parameters

    Raises:
        ValueError: If parameters are invalid or potentially malicious
    """
    katana_params = {}

    # URL already validated in main function
    katana_params["url"] = data["url"]

    # Integer parameters with bounds checking
    katana_params["depth"] = _validate_int_param(data.get("depth", 3), "depth", 1, 10)
    katana_params["concurrency"] = _validate_int_param(
        data.get("concurrency", 10), "concurrency", 1, 50
    )
    katana_params["parallelism"] = _validate_int_param(
        data.get("parallelism", 10), "parallelism", 1, 50
    )
    katana_params["max_pages"] = _validate_int_param(
        data.get("max_pages", 100), "max_pages", 0, 10000
    )
    katana_params["crawl_duration"] = _validate_int_param(
        data.get("crawl_duration", 0), "crawl_duration", 0, 3600
    )
    katana_params["delay"] = _validate_int_param(data.get("delay", 0), "delay", 0, 60)
    katana_params["timeout"] = _validate_int_param(
        data.get("timeout", 10), "timeout", 1, 300
    )
    katana_params["retry"] = _validate_int_param(data.get("retry", 1), "retry", 0, 10)
    katana_params["retry_wait"] = _validate_int_param(
        data.get("retry_wait", 1), "retry_wait", 0, 60
    )

    # Boolean parameters
    katana_params["js_crawl"] = bool(data.get("js_crawl", True))
    katana_params["form_extraction"] = bool(data.get("form_extraction", True))
    katana_params["no_scope"] = bool(data.get("no_scope", False))
    katana_params["display_out_scope"] = bool(data.get("display_out_scope", False))
    katana_params["store_response"] = bool(data.get("store_response", False))
    katana_params["system_chrome"] = bool(data.get("system_chrome", False))
    katana_params["headless"] = bool(data.get("headless", True))
    katana_params["no_incognito"] = bool(data.get("no_incognito", False))
    katana_params["show_source"] = bool(data.get("show_source", False))
    katana_params["show_browser"] = bool(data.get("show_browser", False))

    # String parameters requiring validation and sanitization
    katana_params["output_format"] = _validate_output_format(
        data.get("output_format", "json")
    )

    # File path parameters - CRITICAL: Validate to prevent path traversal
    katana_params["output_file"] = _validate_file_path(
        data.get("output_file", ""), "output_file"
    )
    katana_params["store_response_dir"] = _validate_file_path(
        data.get("store_response_dir", ""), "store_response_dir"
    )
    katana_params["chrome_data_dir"] = _validate_file_path(
        data.get("chrome_data_dir", ""), "chrome_data_dir"
    )

    # Pattern parameters - validate regex patterns
    katana_params["scope"] = _validate_regex_param(data.get("scope", ""), "scope")
    katana_params["out_of_scope"] = _validate_regex_param(
        data.get("out_of_scope", ""), "out_of_scope"
    )
    katana_params["field_scope"] = _validate_regex_param(
        data.get("field_scope", ""), "field_scope"
    )
    katana_params["crawl_scope"] = _validate_regex_param(
        data.get("crawl_scope", ""), "crawl_scope"
    )
    katana_params["filter_regex"] = _validate_regex_param(
        data.get("filter_regex", ""), "filter_regex"
    )
    katana_params["match_regex"] = _validate_regex_param(
        data.get("match_regex", ""), "match_regex"
    )
    katana_params["extension_filter"] = _validate_extension_filter(
        data.get("extension_filter", "")
    )
    katana_params["mime_filter"] = _validate_mime_filter(data.get("mime_filter", ""))

    # Header and auth parameters - sanitize to prevent injection
    katana_params["headers"] = _validate_headers(data.get("headers", ""))
    katana_params["cookies"] = _validate_cookies(data.get("cookies", ""))
    katana_params["user_agent"] = _validate_user_agent(data.get("user_agent", ""))
    katana_params["proxy"] = _validate_proxy(data.get("proxy", ""))

    # Additional args - CRITICAL: Must be completely blocked to prevent injection
    additional_args = data.get("additional_args", "")
    if additional_args:
        raise ValueError("Additional arguments are not permitted for security reasons")
    katana_params["additional_args"] = ""

    return katana_params


def _validate_int_param(value, name: str, min_val: int, max_val: int) -> int:
    """Validate integer parameter within bounds."""
    try:
        int_val = int(value)
        if int_val < min_val or int_val > max_val:
            raise ValueError(f"{name} must be between {min_val} and {max_val}")
        return int_val
    except (ValueError, TypeError) as e:
        raise ValueError(f"Invalid {name}: must be an integer") from e


def _validate_output_format(format_str: str) -> str:
    """Validate output format parameter."""
    allowed_formats = ["json", "jsonl", "txt"]
    if format_str not in allowed_formats:
        raise ValueError(f"Output format must be one of: {allowed_formats}")
    return format_str


def _validate_file_path(path: str, param_name: str) -> str:
    """Validate file path to prevent path traversal attacks.

    Args:
        path: File path to validate
        param_name: Parameter name for error messages

    Returns:
        Validated path

    Raises:
        ValueError: If path is potentially malicious
    """
    import os

    if not path:
        return ""

    # Block dangerous path elements
    dangerous_elements = [
        "..",
        "~",
        "$",
        "|",
        "&",
        ";",
        "`",
        "<",
        ">",
        '"',
        "'",
        "\\",
        "*",
        "?",
    ]
    for element in dangerous_elements:
        if element in path:
            raise ValueError(f"Invalid {param_name}: contains dangerous characters")

    # Ensure path is relative and within allowed directories
    if os.path.isabs(path):
        raise ValueError(f"Invalid {param_name}: absolute paths not allowed")

    # Normalize and check path
    normalized = os.path.normpath(path)
    if normalized.startswith("..") or "/.." in normalized:
        raise ValueError(f"Invalid {param_name}: path traversal not allowed")

    return normalized


def _validate_regex_param(pattern: str, param_name: str) -> str:
    """Validate regex parameter to prevent ReDoS attacks."""
    import re

    if not pattern:
        return ""

    # Block potentially dangerous regex patterns
    dangerous_patterns = [
        ".*.*.*.*",  # Catastrophic backtracking
        "(.+)+",  # Exponential backtracking
        "(x+x+)+y",  # Complex nested quantifiers
        "`",
        "$",
        "|",
        "&",
        ";",
        "<",
        ">",
        '"',
        "'",  # Command injection chars
    ]

    for dangerous in dangerous_patterns:
        if dangerous in pattern:
            raise ValueError(f"Invalid {param_name}: potentially dangerous pattern")

    # Test compile the regex to ensure it's valid
    try:
        re.compile(pattern)
    except re.error as e:
        raise ValueError(f"Invalid {param_name}: invalid regex - {str(e)}") from e

    return pattern


def _validate_extension_filter(extensions: str) -> str:
    """Validate extension filter parameter."""
    if not extensions:
        return ""

    # Split and validate each extension
    ext_list = [ext.strip() for ext in extensions.split(",") if ext.strip()]
    for ext in ext_list:
        if not re.match(r"^[a-zA-Z0-9]+$", ext):
            raise ValueError(f"Invalid extension filter: {ext}")

    return ",".join(ext_list)


def _validate_mime_filter(mimes: str) -> str:
    """Validate MIME type filter parameter."""
    if not mimes:
        return ""

    # Split and validate each MIME type
    mime_list = [mime.strip() for mime in mimes.split(",") if mime.strip()]
    for mime in mime_list:
        if not re.match(r"^[a-zA-Z0-9\-]+/[a-zA-Z0-9\-\+\.]+$", mime):
            raise ValueError(f"Invalid MIME type: {mime}")

    return ",".join(mime_list)


def _validate_headers(headers: str) -> str:
    """Validate HTTP headers parameter."""
    if not headers:
        return ""

    # Basic header format validation
    if any(char in headers for char in ["`", "$", "|", "&", ";", "<", ">", '"']):
        raise ValueError("Invalid headers: contains dangerous characters")

    return headers


def _validate_cookies(cookies: str) -> str:
    """Validate cookies parameter."""
    if not cookies:
        return ""

    # Basic cookie format validation
    if any(char in cookies for char in ["`", "$", "|", "&", ";", "<", ">", '"']):
        raise ValueError("Invalid cookies: contains dangerous characters")

    return cookies


def _validate_user_agent(user_agent: str) -> str:
    """Validate user agent parameter."""
    if not user_agent:
        return ""

    # Basic user agent validation
    if any(char in user_agent for char in ["`", "$", "|", "&", ";", "<", ">", '"']):
        raise ValueError("Invalid user agent: contains dangerous characters")

    return user_agent


def _validate_proxy(proxy: str) -> str:
    """Validate proxy parameter."""
    if not proxy:
        return ""

    # Basic proxy URL validation
    if not _validate_url(proxy):
        raise ValueError("Invalid proxy URL format")

    return proxy


def _build_secure_command(url: str, params: dict) -> list:
    """Build secure katana command using list arguments to prevent injection.

    Args:
        url: Target URL (already validated)
        params: Validated parameters

    Returns:
        List of command arguments for secure execution

    Raises:
        ValueError: If command cannot be built securely
    """
    # Use list format to prevent shell injection
    command_args = ["katana", "-u", url]

    # Core crawling parameters
    if params["depth"] != 3:
        command_args.extend(["-d", str(params["depth"])])
    if params["concurrency"] != 10:
        command_args.extend(["-c", str(params["concurrency"])])
    if params["parallelism"] != 10:
        command_args.extend(["-p", str(params["parallelism"])])

    # Crawling behavior
    if params["max_pages"] > 0:
        command_args.extend(["-kf", str(params["max_pages"])])
    if params["crawl_duration"] > 0:
        command_args.extend(["-ct", str(params["crawl_duration"])])
    if params["delay"] > 0:
        command_args.extend(["-delay", str(params["delay"])])

    # JavaScript crawling
    if params["js_crawl"]:
        command_args.append("-jc")

    # Form extraction
    if params["form_extraction"]:
        command_args.append("-fx")

    # Scope control
    if params["scope"]:
        command_args.extend(["-cs", params["scope"]])
    if params["out_of_scope"]:
        command_args.extend(["-cos", params["out_of_scope"]])
    if params["field_scope"]:
        command_args.extend(["-fs", params["field_scope"]])
    if params["no_scope"]:
        command_args.append("-ns")
    if params["display_out_scope"]:
        command_args.append("-do")

    # Authentication and headers
    if params["headers"]:
        command_args.extend(["-H", params["headers"]])
    if params["cookies"]:
        command_args.extend(["-cookie", params["cookies"]])
    if params["user_agent"]:
        command_args.extend(["-ua", params["user_agent"]])

    # Proxy settings
    if params["proxy"]:
        command_args.extend(["-proxy", params["proxy"]])

    # Chrome options
    if params["system_chrome"]:
        command_args.append("-sc")
    if not params["headless"]:
        command_args.append("-xhr")
    if params["no_incognito"]:
        command_args.append("-ni")
    if params["chrome_data_dir"]:
        command_args.extend(["-cdd", params["chrome_data_dir"]])
    if params["show_source"]:
        command_args.append("-sr")
    if params["show_browser"]:
        command_args.append("-sb")

    # Timeout and retry settings
    if params["timeout"] != 10:
        command_args.extend(["-timeout", str(params["timeout"])])
    if params["retry"] != 1:
        command_args.extend(["-retry", str(params["retry"])])
    if params["retry_wait"] != 1:
        command_args.extend(["-rw", str(params["retry_wait"])])

    # Output format
    if params["output_format"] == "json":
        command_args.append("-jsonl")

    # Filtering
    if params["filter_regex"]:
        command_args.extend(["-fr", params["filter_regex"]])
    if params["match_regex"]:
        command_args.extend(["-mr", params["match_regex"]])
    if params["extension_filter"]:
        command_args.extend(["-ef", params["extension_filter"]])
    if params["mime_filter"]:
        command_args.extend(["-mf", params["mime_filter"]])

    # Output file
    if params["output_file"]:
        command_args.extend(["-o", params["output_file"]])

    # Store response
    if params["store_response"]:
        command_args.append("-sr")
    if params["store_response_dir"]:
        command_args.extend(["-srd", params["store_response_dir"]])

    return command_args
