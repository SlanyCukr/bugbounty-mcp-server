"""Common parameter extraction utilities for cybersecurity tools."""

import ipaddress
import logging
import re
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class ParameterExtractor:
    """Common parameter extraction and validation utilities."""

    # Common aggressive presets for tools
    COMMON_AGGRESSIVE_PRESETS = {
        "threads": 50,
        "timeout": 600,
        "rate_limit": 100,
    }

    @staticmethod
    def extract_base_params(
        data: dict, required_fields: list[str] | None = None
    ) -> dict:
        """Extract base parameters common to all tools."""
        if not data:
            raise ValueError("Request data is required")

        # Validate required fields
        if required_fields:
            for field in required_fields:
                if field not in data or not data[field]:
                    raise ValueError(f"{field} parameter is required")

        # Extract common parameters
        params = {
            "target": data.get("target", data.get("url", data.get("domain", ""))) or "",
            "timeout": int(data.get("timeout", 300)),
            "aggressive": bool(data.get("aggressive", False)),
            "silent": bool(data.get("silent", True)),
            "threads": int(data.get("threads", 10)),
            "additional_args": data.get("additional_args", ""),
            "proxy": data.get("proxy", ""),
            "headers": data.get("headers", {}),
            "cookies": data.get("cookies", {}),
            "user_agent": data.get("user_agent", ""),
        }

        return params

    @staticmethod
    def validate_string_param(
        value: Any, param_name: str, max_length: int = 1000
    ) -> str:
        """Validate and clean string parameters."""
        if not value:
            return ""

        value = str(value).strip()

        if len(value) > max_length:
            raise ValueError(f"{param_name} exceeds maximum length of {max_length}")

        # Remove potentially dangerous characters
        dangerous_chars = [";", "&", "|", "`", "$", "(", ")", "{", "}", "<", ">"]
        for char in dangerous_chars:
            if char in value:
                value = value.replace(char, "")

        return value

    @staticmethod
    def validate_int_param(
        value: Any,
        param_name: str,
        min_val: int | None = None,
        max_val: int | None = None,
    ) -> int:
        """Validate integer parameters."""
        try:
            int_value = int(value)
        except (ValueError, TypeError):
            raise ValueError(f"{param_name} must be an integer") from None

        if min_val is not None and int_value < min_val:
            raise ValueError(f"{param_name} must be >= {min_val}")

        if max_val is not None and int_value > max_val:
            raise ValueError(f"{param_name} must be <= {max_val}")

        return int_value

    @staticmethod
    def validate_url(url: str) -> str:
        """Validate and clean URL parameters."""
        if not url:
            raise ValueError("URL cannot be empty")

        url = str(url).strip()

        parsed = urlparse(url)
        if not parsed.scheme:
            raise ValueError("URL must include a scheme (http/https)")

        if parsed.scheme not in ["http", "https"]:
            raise ValueError("URL scheme must be http or https")

        if not parsed.netloc:
            raise ValueError("URL must include a valid hostname")

        return url

    @staticmethod
    def validate_domain(domain: str) -> str:
        """Validate domain parameters."""
        if not domain:
            raise ValueError("Domain cannot be empty")

        domain = str(domain).strip().lower()

        # Remove http:// or https:// if present
        if domain.startswith("http://"):
            domain = domain[7:]
        elif domain.startswith("https://"):
            domain = domain[8:]

        # Remove trailing slashes
        domain = domain.rstrip("/")

        # Basic domain validation
        domain_pattern = (
            r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
            r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
        )
        if not re.match(domain_pattern, domain):
            raise ValueError("Invalid domain format")

        return domain

    @staticmethod
    def validate_ip_address(target: str) -> str:
        """Validate IP address parameters."""
        if not target:
            raise ValueError("IP address cannot be empty")

        target = str(target).strip()

        try:
            # Try to parse as IP address
            ipaddress.ip_address(target)
            return target
        except ValueError:
            # Not an IP address, could be a hostname
            return target

    @staticmethod
    def validate_port_range(ports: str) -> str:
        """Validate port range parameters."""
        if not ports:
            return ""

        ports = str(ports).strip()

        # Check for common port range formats
        port_patterns = [
            r"^\d+$",  # Single port
            r"^\d+-\d+$",  # Port range
            r"^\d+(,\d+)*$",  # Comma-separated ports
        ]

        for pattern in port_patterns:
            if re.match(pattern, ports):
                return ports

        raise ValueError("Invalid port range format")

    @staticmethod
    def validate_file_path(
        path: str, allowed_extensions: list[str] | None = None
    ) -> str:
        """Validate file path parameters."""
        if not path:
            raise ValueError("File path cannot be empty")

        path = str(path).strip()

        # Prevent path traversal
        if ".." in path:
            raise ValueError("Path traversal not allowed")

        # Check file extension if specified
        if allowed_extensions:
            file_ext = path.split(".")[-1].lower()
            if file_ext not in allowed_extensions:
                raise ValueError(f"File extension must be one of: {allowed_extensions}")

        return path

    @staticmethod
    def apply_aggressive_preset(
        params: dict, aggressive: bool, tool_preset: dict[str, Any] | None = None
    ) -> dict:
        """Apply aggressive preset to parameters."""
        if not aggressive:
            return params

        # Start with user params
        merged_params = params.copy()

        # Apply common aggressive preset
        preset = tool_preset or ParameterExtractor.COMMON_AGGRESSIVE_PRESETS

        for key, aggressive_value in preset.items():
            if key not in params or params[key] in [None, "", 0, False]:
                merged_params[key] = aggressive_value

        return merged_params

    @staticmethod
    def extract_http_headers(data: dict) -> dict:
        """Extract and validate HTTP headers."""
        headers = {}

        if "headers" in data and data["headers"]:
            headers_raw = data["headers"]
            if isinstance(headers_raw, dict):
                headers = headers_raw
            elif isinstance(headers_raw, str):
                # Parse string headers like "Key: Value"
                for line in headers_raw.split("\n"):
                    if ":" in line:
                        key, value = line.split(":", 1)
                        headers[key.strip()] = value.strip()

        # Add user agent if specified
        if data.get("user_agent"):
            headers["User-Agent"] = data["user_agent"]

        return headers

    @staticmethod
    def validate_wordlist_params(data: dict) -> dict:
        """Validate wordlist-related parameters."""
        wordlist_params = {
            "wordlist": ParameterExtractor.validate_file_path(
                data.get("wordlist", ""), ["txt", "lst", "wordlist"]
            ),
            "extensions": data.get("extensions", ""),
            "recursive": bool(data.get("recursive", False)),
            "depth": ParameterExtractor.validate_int_param(
                data.get("depth", 2), "depth", 1, 10
            ),
        }

        # Clean extensions
        if wordlist_params["extensions"]:
            extensions = str(wordlist_params["extensions"]).strip()
            # Remove dots and split by comma
            extensions = extensions.replace(".", "").replace(" ", "")
            wordlist_params["extensions"] = extensions

        return wordlist_params
