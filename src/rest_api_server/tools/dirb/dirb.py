"""dirb tool implementation."""

import logging

from flask import request

from src.rest_api_server.utils.registry import tool

logger = logging.getLogger(__name__)


def _extract_dirb_params(data):
    """Extract dirb parameters from request data with input validation."""
    import re
    from urllib.parse import urlparse

    # Extract and validate URL parameter
    url = data.get("url")
    if not url:
        raise ValueError("URL parameter is required")

    # Validate URL format
    parsed_url = urlparse(url)
    if not parsed_url.scheme or not parsed_url.netloc:
        raise ValueError("Invalid URL format")

    # Only allow HTTP/HTTPS protocols for security
    if parsed_url.scheme not in ["http", "https"]:
        raise ValueError("Only HTTP and HTTPS protocols are allowed")

    # Validate and sanitize wordlist parameter
    wordlist = data.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
    if not isinstance(wordlist, str):
        raise ValueError("Wordlist must be a string")

    # Validate wordlist path to prevent path traversal
    if (
        ".." in wordlist
        or wordlist.startswith("/tmp/")
        or wordlist.startswith("/var/tmp/")
    ):
        raise ValueError("Invalid wordlist path - path traversal detected")

    # Only allow wordlists from safe directories
    allowed_wordlist_dirs = [
        "/usr/share/wordlists/",
        "/usr/share/dirb/wordlists/",
        "/opt/wordlists/",
    ]
    if not any(
        wordlist.startswith(allowed_dir) for allowed_dir in allowed_wordlist_dirs
    ):
        raise ValueError("Wordlist must be from an allowed directory")

    # Validate and sanitize extensions parameter
    extensions = data.get("extensions", "")
    if extensions:
        if not isinstance(extensions, str):
            raise ValueError("Extensions must be a string")
        # Validate extension format (only alphanumeric and dots)
        if not re.match(r"^[a-zA-Z0-9.,]*$", extensions):
            raise ValueError("Invalid characters in extensions parameter")

    # Validate boolean parameters
    recursive = bool(data.get("recursive", False))
    ignore_case = bool(data.get("ignore_case", False))

    # Validate and sanitize user agent
    user_agent = data.get("user_agent", "")
    if user_agent:
        if not isinstance(user_agent, str):
            raise ValueError("User agent must be a string")
        # Remove potentially dangerous characters
        user_agent = re.sub(r"[^\w\s\-\.\/\(\)]", "", user_agent)
        # Limit length
        user_agent = user_agent[:200]

    # Validate and sanitize headers parameter
    headers = data.get("headers", "")
    if headers:
        if not isinstance(headers, str):
            raise ValueError("Headers must be a string")
        # Basic header format validation (Key: Value)
        if not re.match(r"^[a-zA-Z0-9\-_: ]*$", headers):
            raise ValueError("Invalid characters in headers parameter")
        headers = headers[:500]  # Limit length

    # Validate and sanitize cookies parameter
    cookies = data.get("cookies", "")
    if cookies:
        if not isinstance(cookies, str):
            raise ValueError("Cookies must be a string")
        # Basic cookie format validation
        if not re.match(r"^[a-zA-Z0-9=;_\-. ]*$", cookies):
            raise ValueError("Invalid characters in cookies parameter")
        cookies = cookies[:500]  # Limit length

    # Validate proxy parameter
    proxy = data.get("proxy", "")
    if proxy:
        if not isinstance(proxy, str):
            raise ValueError("Proxy must be a string")
        # Validate proxy format (host:port)
        if not re.match(r"^[a-zA-Z0-9\.\-]+:\d+$", proxy):
            raise ValueError("Invalid proxy format - must be host:port")

    # Validate authentication parameter
    auth = data.get("auth", "")
    if auth:
        if not isinstance(auth, str):
            raise ValueError("Auth must be a string")
        # Basic auth format validation (username:password)
        if ":" not in auth or len(auth) > 100:
            raise ValueError("Invalid auth format")
        # Remove dangerous characters
        auth = re.sub(r"[^\w:@\-.]", "", auth)

    # Validate delay parameter
    delay = data.get("delay", "")
    if delay:
        if isinstance(delay, str):
            if not delay.isdigit():
                raise ValueError("Delay must be a number")
            delay = int(delay)
        elif isinstance(delay, int):
            pass
        else:
            raise ValueError("Delay must be a number")

        if delay < 0 or delay > 10:
            raise ValueError("Delay must be between 0 and 10 seconds")

    # SECURITY FIX: Remove dangerous additional_args parameter entirely
    # This parameter was the source of command injection vulnerability
    # additional_args = data.get("additional_args", "")

    return {
        "url": url,
        "wordlist": wordlist,
        "extensions": extensions,
        "recursive": recursive,
        "ignore_case": ignore_case,
        "user_agent": user_agent,
        "headers": headers,
        "cookies": cookies,
        "proxy": proxy,
        "auth": auth,
        "delay": delay,
        # "additional_args": additional_args,  # REMOVED for security
    }


def _build_dirb_command(params):
    """Build dirb command from parameters as an argument list (secure)."""
    cmd_parts = ["dirb", params["url"]]

    # Add wordlist parameter
    cmd_parts.append(params["wordlist"])

    # Add extensions if specified
    if params["extensions"]:
        cmd_parts.extend(["-X", params["extensions"]])

    # Add recursive scanning option
    if params["recursive"]:
        cmd_parts.append("-r")

    # Add case insensitive option
    if params["ignore_case"]:
        cmd_parts.append("-z")

    # Add non-interactive mode (always use this for automated execution)
    cmd_parts.append("-N")

    # Add user agent if specified
    if params["user_agent"]:
        cmd_parts.extend(["-a", params["user_agent"]])

    # Add custom headers if specified
    if params["headers"]:
        cmd_parts.extend(["-H", params["headers"]])

    # Add cookies if specified
    if params["cookies"]:
        cmd_parts.extend(["-c", params["cookies"]])

    # Add proxy if specified
    if params["proxy"]:
        cmd_parts.extend(["-p", params["proxy"]])

    # Add authentication if specified
    if params["auth"]:
        cmd_parts.extend(["-u", params["auth"]])

    # Add delay between requests if specified
    if params["delay"]:
        cmd_parts.extend(["-l", str(params["delay"])])

    # SECURITY: No longer accepting additional_args to prevent command injection
    # The additional_args parameter has been completely removed

    return cmd_parts


def _execute_dirb_command_secure(cmd_parts, timeout=600):
    """Execute dirb command securely using subprocess.run with argument list.

    Args:
        cmd_parts: List of command arguments
        timeout: Command timeout in seconds

    Returns:
        Dictionary with execution results
    """
    import subprocess

    try:
        logger.info(f"Executing secure DIRB command: {' '.join(cmd_parts)}")

        # Use subprocess.run with argument list (no shell=True for security)
        result = subprocess.run(
            cmd_parts,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,  # SECURITY: Never use shell=True
        )

        return {
            "success": result.returncode == 0,
            "return_code": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "command": cmd_parts,
            "duration_ms": 0,  # Could add timing if needed
        }

    except subprocess.TimeoutExpired:
        logger.error(f"DIRB command timed out: {' '.join(cmd_parts)}")
        return {
            "success": False,
            "error": "Command timed out",
            "command": cmd_parts,
            "timeout": timeout,
            "timeout_occurred": True,
        }
    except FileNotFoundError:
        logger.error("DIRB command not found - ensure dirb is installed")
        return {
            "success": False,
            "error": "DIRB not found - please install dirb",
            "command": cmd_parts,
        }
    except Exception as e:
        logger.error(f"Error executing DIRB command: {str(e)}")
        return {"success": False, "error": str(e), "command": cmd_parts}


def _parse_dirb_result(execution_result, params, command):
    """Parse dirb execution result and format response."""
    return {
        "tool": "dirb",
        "target": params["url"],
        "command": " ".join(command) if isinstance(command, list) else command,
        "success": execution_result["success"],
        "stdout": execution_result["stdout"],
        "stderr": execution_result["stderr"],
        "return_code": execution_result["return_code"],
        "parameters": {
            "url": params["url"],
            "wordlist": params["wordlist"],
            "extensions": params["extensions"],
            "recursive": params["recursive"],
            "ignore_case": params["ignore_case"],
            "user_agent": params["user_agent"],
            "headers": params["headers"],
            "cookies": params["cookies"],
            "proxy": params["proxy"],
            "auth": params["auth"],
            "delay": params["delay"],
            # "additional_args": params["additional_args"],  # REMOVED for security
        },
    }


@tool(required_fields=["url"])
def execute_dirb():
    """Execute DIRB directory scanner with enhanced security and scanning profiles."""
    try:
        data = request.get_json()

        # Extract and validate parameters (now includes comprehensive input validation)
        params = _extract_dirb_params(data)

        # Apply scanning profile if specified
        profile = data.get("profile", "default")
        params = _apply_scanning_profile(params, profile)

        logger.info(f"Executing DIRB scan on {params['url']} with profile: {profile}")

        # Build secure command as argument list
        command_parts = _build_dirb_command(params)

        # Execute command securely (no shell injection possible)
        execution_result = _execute_dirb_command_secure(command_parts, timeout=600)

        return _parse_dirb_result(execution_result, params, command_parts)

    except ValueError as e:
        # Input validation errors
        logger.error(f"DIRB input validation error: {str(e)}")
        return {
            "tool": "dirb",
            "success": False,
            "error": f"Input validation failed: {str(e)}",
            "error_stage": "validation",
        }
    except Exception as e:
        # Other unexpected errors
        logger.error(f"DIRB execution error: {str(e)}")
        return {
            "tool": "dirb",
            "success": False,
            "error": f"Execution failed: {str(e)}",
            "error_stage": "execution",
        }


def _apply_scanning_profile(params, profile):
    """Apply predefined scanning profiles to optimize for different scenarios.

    Args:
        params: Base parameters
        profile: Profile name (default, stealth, speed-optimized, comprehensive)

    Returns:
        Updated parameters with profile-specific settings
    """
    if profile == "stealth":
        # Stealth profile: Slower, less detectable
        params["delay"] = params.get("delay", 2)  # 2 second delay between requests
        params["user_agent"] = params.get(
            "user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        )
        # Use smaller wordlist for stealth
        if params["wordlist"] == "/usr/share/wordlists/dirb/common.txt":
            params["wordlist"] = "/usr/share/wordlists/dirb/small.txt"

    elif profile == "speed-optimized":
        # Speed profile: Faster scanning with minimal delays
        params["delay"] = 0  # No delay between requests
        params["recursive"] = False  # Disable recursive for speed
        # Use smaller wordlist for speed
        if params["wordlist"] == "/usr/share/wordlists/dirb/common.txt":
            params["wordlist"] = "/usr/share/wordlists/dirb/small.txt"

    elif profile == "comprehensive":
        # Comprehensive profile: Thorough scanning
        params["recursive"] = True
        params["extensions"] = params.get(
            "extensions", "php,html,txt,bak,conf,xml,json"
        )
        # Use larger wordlist for comprehensive scanning
        if params["wordlist"] == "/usr/share/wordlists/dirb/common.txt":
            params["wordlist"] = "/usr/share/wordlists/dirb/big.txt"

    # Default profile requires no changes

    return params
