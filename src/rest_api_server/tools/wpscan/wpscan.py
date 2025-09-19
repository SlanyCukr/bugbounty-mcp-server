"""wpscan tool implementation."""

import logging

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import tool

logger = logging.getLogger(__name__)


@tool(required_fields=["url"])
def execute_wpscan():
    """Execute WPScan for comprehensive WordPress vulnerability analysis."""
    data = request.get_json()
    url = data["url"]
    logger.info(f"Executing WPScan on {url}")

    # Build wpscan command
    cmd_parts = ["wpscan", "--url", url]

    # Enhanced enumeration options for comprehensive WordPress security assessment
    enumerate = data.get("enumerate", "ap,at,cb,dbe,u,m")
    if enumerate:
        cmd_parts.extend(["--enumerate", enumerate])

    # Add detection evasion and stealth options
    if data.get("stealthy", False):
        cmd_parts.extend(["--stealthy"])

    # Add user agent randomization for better detection evasion
    if data.get("random_user_agent", True):
        cmd_parts.append("--random-user-agent")

    # Add custom user agent if specified
    custom_user_agent = data.get("user_agent", "")
    if custom_user_agent:
        cmd_parts.extend(["--ua", custom_user_agent])

    # Enhanced WordPress detection options
    if data.get("detection_mode", "mixed") == "aggressive":
        cmd_parts.extend(["--detection-mode", "aggressive"])
    elif data.get("detection_mode", "mixed") == "passive":
        cmd_parts.extend(["--detection-mode", "passive"])
    else:
        cmd_parts.extend(["--detection-mode", "mixed"])

    # Add comprehensive plugin and theme detection
    plugin_detection = data.get("plugin_detection", "mixed")
    if plugin_detection != "mixed":
        cmd_parts.extend(["--plugins-detection", plugin_detection])

    # Add update option for vulnerability database
    if data.get("update", True):
        cmd_parts.append("--update")

    # Add API token for enhanced vulnerability data
    api_token = data.get("api_token", "")
    if api_token:
        cmd_parts.extend(["--api-token", api_token])

    # Enhanced threading for better performance
    threads = data.get("threads", 5)
    cmd_parts.extend(["--max-threads", str(threads)])

    # Add request timeout for better reliability
    timeout = data.get("request_timeout", 60)
    cmd_parts.extend(["--request-timeout", str(timeout)])

    # Add connection timeout
    connect_timeout = data.get("connect_timeout", 30)
    cmd_parts.extend(["--connect-timeout", str(connect_timeout)])

    # Add follow redirects option
    if data.get("follow_redirects", True):
        cmd_parts.append("--follow-redirects")

    # Add WordPress content directory detection
    wp_content_dir = data.get("wp_content_dir", "")
    if wp_content_dir:
        cmd_parts.extend(["--wp-content-dir", wp_content_dir])

    # Add WordPress plugin directory detection
    wp_plugins_dir = data.get("wp_plugins_dir", "")
    if wp_plugins_dir:
        cmd_parts.extend(["--wp-plugins-dir", wp_plugins_dir])

    # Add force SSL verification control
    if data.get("disable_ssl_check", False):
        cmd_parts.append("--disable-tls-checks")

    # Add proxy support for testing through security tools
    proxy = data.get("proxy", "")
    if proxy:
        cmd_parts.extend(["--proxy", proxy])

    # Add HTTP authentication if required
    http_auth = data.get("http_auth", "")
    if http_auth:
        cmd_parts.extend(["--http-auth", http_auth])

    # Add custom headers for advanced testing
    headers = data.get("headers", {})
    for header_name, header_value in headers.items():
        cmd_parts.extend(["--headers", f"{header_name}: {header_value}"])

    # Add comprehensive vulnerability checking
    if data.get("ignore_main_redirect", False):
        cmd_parts.append("--ignore-main-redirect")

    # Enhanced output format for better parsing
    output_format = data.get("format", "json")
    if output_format in ["json", "cli"]:
        cmd_parts.extend(["--format", output_format])

    # Add verbose output for detailed analysis
    if data.get("verbose", False):
        cmd_parts.append("--verbose")

    # Add no banner option for cleaner output
    if data.get("no_banner", True):
        cmd_parts.append("--no-banner")

    # Add WordPress security specific scans
    if data.get("check_core_version", True):
        # This is enabled by default in WPScan, but we ensure it's documented
        pass

    # Add additional security checks
    passwords_file = data.get("passwords_file", "")
    if passwords_file:
        cmd_parts.extend(["--passwords", passwords_file])

    usernames_file = data.get("usernames_file", "")
    if usernames_file:
        cmd_parts.extend(["--usernames", usernames_file])

    # Add password attack options
    if data.get("password_attack", False):
        multicall = data.get("multicall", 20)
        cmd_parts.extend(["--multicall-max-passwords", str(multicall)])

    # Add output file for detailed logging
    output_file = data.get("output_file", "")
    if output_file:
        cmd_parts.extend(["--output", output_file])

    # Add custom cookie if needed for authenticated scans
    cookie = data.get("cookie", "")
    if cookie:
        cmd_parts.extend(["--cookie-string", cookie])

    # Add scope limitation for focused testing
    scope = data.get("scope", "")
    if scope:
        cmd_parts.extend(["--scope", scope])

    # Add additional arguments
    additional_args = data.get("additional_args", "")
    if additional_args:
        cmd_parts.extend(additional_args.split())

    command = " ".join(cmd_parts)

    # Execute wpscan command with extended timeout for comprehensive scans
    execution_result = execute_command(
        command, timeout=1800
    )  # 30 minutes for thorough scans

    # Enhanced parameter collection
    wpscan_params = {
        "url": url,
        "enumerate": enumerate,
        "detection_mode": data.get("detection_mode", "mixed"),
        "plugin_detection": data.get("plugin_detection", "mixed"),
        "stealthy": data.get("stealthy", False),
        "update": data.get("update", True),
        "random_user_agent": data.get("random_user_agent", True),
        "user_agent": data.get("user_agent", ""),
        "api_token": api_token,
        "threads": threads,
        "request_timeout": timeout,
        "connect_timeout": connect_timeout,
        "follow_redirects": data.get("follow_redirects", True),
        "wp_content_dir": wp_content_dir,
        "wp_plugins_dir": wp_plugins_dir,
        "disable_ssl_check": data.get("disable_ssl_check", False),
        "proxy": proxy,
        "http_auth": http_auth,
        "headers": headers,
        "format": output_format,
        "verbose": data.get("verbose", False),
        "no_banner": data.get("no_banner", True),
        "passwords_file": passwords_file,
        "usernames_file": usernames_file,
        "password_attack": data.get("password_attack", False),
        "output_file": output_file,
        "cookie": cookie,
        "scope": scope,
        "additional_args": additional_args,
    }

    result = {
        "tool": "wpscan",
        "target": url,
        "parameters": wpscan_params,
        "command": command,
        "success": execution_result["success"],
        "stdout": execution_result.get("stdout", ""),
        "stderr": execution_result.get("stderr", ""),
        "return_code": execution_result.get("return_code", 0),
    }

    return result
