"""Severity mapping utilities for bug bounty findings.

This module provides functionality to map tool-native severities to a unified scale
and implement heuristics for tools without native severity ratings.
"""

import logging
from typing import Any, Literal, cast

logger = logging.getLogger(__name__)

# Unified severity scale
SEVERITY_LEVELS = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

# Tool-specific severity mappings
TOOL_SEVERITY_MAPPINGS = {
    "nuclei": {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
        "unknown": "info",
    },
    "nikto": {
        "4": "critical",  # Nikto uses numeric scale 0-4
        "3": "high",
        "2": "medium",
        "1": "low",
        "0": "info",
    },
    "nmap": {
        # Nmap doesn't have native severity, uses port-based heuristics
    },
    "sqlmap": {
        # SQLMap findings are generally high severity
        "confirmed": "high",
        "possible": "medium",
        "detected": "low",
    },
    "dalfox": {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
    },
}

# Sensitive paths and their severity levels
SENSITIVE_PATHS = {
    # Admin interfaces
    "/admin": "high",
    "/wp-admin": "high",
    "/administrator": "high",
    "/phpmyadmin": "high",
    "/adminer": "high",
    "/cpanel": "high",
    "/plesk": "high",
    # Configuration files
    "/.env": "critical",
    "/config.php": "high",
    "/wp-config.php": "critical",
    "/database.yml": "high",
    "/settings.py": "high",
    "/.git/config": "medium",
    "/.svn": "medium",
    # Backup files
    "/backup": "medium",
    "/.backup": "medium",
    "/db_backup": "high",
    "/database.sql": "high",
    # Debug/test endpoints
    "/debug": "medium",
    "/test": "low",
    "/phpinfo.php": "medium",
    "/info.php": "medium",
    # API endpoints
    "/api": "low",
    "/graphql": "medium",
    "/v1/": "low",
    "/v2/": "low",
    # File managers
    "/filemanager": "high",
    "/files": "medium",
    "/uploads": "medium",
}

# Service-based severity for port scans
SERVICE_SEVERITIES = {
    # High risk services
    "ssh": {"default": "medium", "version_disclosed": "low"},
    "telnet": {"default": "high", "unencrypted": "high"},
    "ftp": {"default": "medium", "anonymous": "high"},
    "smtp": {"default": "low", "open_relay": "high"},
    "pop3": {"default": "low", "unencrypted": "medium"},
    "imap": {"default": "low", "unencrypted": "medium"},
    "snmp": {"default": "high", "community_strings": "critical"},
    "ldap": {"default": "medium", "anonymous_bind": "high"},
    "smb": {"default": "medium", "guest_access": "high"},
    "rdp": {"default": "high", "weak_encryption": "critical"},
    "vnc": {"default": "high", "no_auth": "critical"},
    "mysql": {"default": "medium", "root_access": "critical"},
    "postgresql": {"default": "medium", "weak_auth": "high"},
    "mongodb": {"default": "medium", "no_auth": "critical"},
    "redis": {"default": "medium", "no_auth": "high"},
    # Web services
    "http": {"default": "info", "admin_panel": "high"},
    "https": {"default": "info", "ssl_issues": "medium"},
    "apache": {"default": "info", "version_disclosure": "low"},
    "nginx": {"default": "info", "version_disclosure": "low"},
    "iis": {"default": "info", "version_disclosure": "low"},
    # Other services
    "dns": {"default": "info", "zone_transfer": "medium"},
    "ntp": {"default": "info", "amplification": "medium"},
    "elasticsearch": {"default": "high", "open_access": "critical"},
}

# Vulnerability pattern keywords and their severities
VULNERABILITY_PATTERNS = {
    # Critical patterns
    "rce": "critical",
    "remote code execution": "critical",
    "command injection": "critical",
    "code injection": "critical",
    "deserialization": "critical",
    "template injection": "critical",
    # High severity patterns
    "sql injection": "high",
    "sqli": "high",
    "xxe": "high",
    "xml external entity": "high",
    "ldap injection": "high",
    "xpath injection": "high",
    "file upload": "high",
    "unrestricted file upload": "critical",
    "path traversal": "high",
    "directory traversal": "high",
    "lfi": "high",
    "local file inclusion": "high",
    "rfi": "high",
    "remote file inclusion": "critical",
    # Medium severity patterns
    "xss": "medium",
    "cross-site scripting": "medium",
    "csrf": "medium",
    "cross-site request forgery": "medium",
    "clickjacking": "low",
    "open redirect": "medium",
    "ssrf": "high",
    "server-side request forgery": "high",
    "authentication bypass": "high",
    "authorization bypass": "high",
    "privilege escalation": "high",
    "insecure direct object reference": "medium",
    "idor": "medium",
    # Low/Info severity patterns
    "information disclosure": "low",
    "info disclosure": "low",
    "version disclosure": "low",
    "banner grabbing": "info",
    "directory listing": "low",
    "backup file": "medium",
    "debug mode": "medium",
    "test file": "low",
    "missing security headers": "low",
    "weak ssl": "medium",
    "ssl certificate": "low",
}


class SeverityMapper:
    """Maps tool outputs to unified severity levels."""

    def __init__(self):
        """Initialize severity mapper."""
        self.severity_stats = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

    def _normalize_severity(self, severity: str) -> str:
        """Normalize severity string to standard format.

        Args:
            severity: Raw severity string

        Returns:
            Normalized severity level
        """
        if not severity:
            return "info"

        severity_lower = str(severity).lower().strip()

        # Handle numeric severities
        if severity_lower.isdigit():
            numeric_val = int(severity_lower)
            if numeric_val >= 9:
                return "critical"
            elif numeric_val >= 7:
                return "high"
            elif numeric_val >= 4:
                return "medium"
            elif numeric_val >= 1:
                return "low"
            else:
                return "info"

        # Handle common aliases
        severity_aliases = {
            "crit": "critical",
            "med": "medium",
            "informational": "info",
            "information": "info",
            "notice": "info",
            "warning": "low",
            "warn": "low",
        }

        return severity_aliases.get(severity_lower, severity_lower)

    def _map_tool_severity(self, tool: str, severity: str) -> str:
        """Map tool-specific severity to unified scale.

        Args:
            tool: Tool name
            severity: Tool-specific severity

        Returns:
            Unified severity level
        """
        tool_lower = tool.lower() if tool else ""

        if tool_lower in TOOL_SEVERITY_MAPPINGS:
            mapping = TOOL_SEVERITY_MAPPINGS[tool_lower]
            normalized_severity = self._normalize_severity(severity)
            return mapping.get(normalized_severity, "info")

        # Fallback to direct normalization
        return self._normalize_severity(severity)

    def _assess_path_severity(self, path: str, status_code: int) -> str:
        """Assess severity based on path and HTTP status code.

        Args:
            path: URL path
            status_code: HTTP status code

        Returns:
            Assessed severity level
        """
        if not path:
            return "info"

        path_lower = path.lower()

        # Check for sensitive paths
        for sensitive_path, severity in SENSITIVE_PATHS.items():
            if sensitive_path in path_lower:
                # Adjust based on status code
                if status_code == 200:
                    return severity
                elif status_code in [301, 302, 403]:
                    # Path exists but access restricted - lower severity
                    current_level = SEVERITY_LEVELS.get(severity, 1)
                    if current_level > 1:
                        for level, value in SEVERITY_LEVELS.items():
                            if value == current_level - 1:
                                return level
                    return "low"
                elif status_code == 404:
                    return "info"

        # Default path assessment
        if status_code == 200:
            if any(keyword in path_lower for keyword in ["/api", "/admin", "/config"]):
                return "medium"
            return "low"
        elif status_code in [403, 401]:
            return "low"
        else:
            return "info"

    def _assess_port_severity(
        self, port: int, service: str, details: dict[str, Any]
    ) -> str:
        """Assess severity for port scan findings.

        Args:
            port: Port number
            service: Service name
            details: Additional port/service details

        Returns:
            Assessed severity level
        """
        if not service:
            # Common dangerous ports without service detection
            dangerous_ports = {
                23: "high",  # telnet
                135: "medium",  # rpc
                139: "medium",  # netbios
                445: "high",  # smb
                1433: "high",  # mssql
                1521: "high",  # oracle
                3389: "high",  # rdp
                5432: "medium",  # postgresql
                6379: "medium",  # redis
                27017: "medium",  # mongodb
            }
            return dangerous_ports.get(port, "info")

        service_lower = service.lower()

        # Check service-specific severities
        for service_name, config in SERVICE_SEVERITIES.items():
            if service_name in service_lower:
                base_severity = config.get("default", "info")

                # Check for specific conditions that increase severity
                if details:
                    detail_str = str(details).lower()
                    for condition, severity in config.items():
                        if condition != "default" and condition in detail_str:
                            return severity

                return base_severity

        # Default assessment based on port ranges
        if port in range(1, 1024):  # Well-known ports
            return "low"
        elif port in range(1024, 49152):  # Registered ports
            return "info"
        else:  # Dynamic ports
            return "info"

    def _assess_vulnerability_severity(
        self, name: str, description: str, proof: str | None = None
    ) -> str:
        """Assess vulnerability severity based on name, description, and proof.

        Args:
            name: Vulnerability name
            description: Vulnerability description
            proof: Proof of concept or evidence

        Returns:
            Assessed severity level
        """
        # Combine all text for pattern matching
        parts = [part for part in (name, description, proof) if part]
        combined_text = " ".join(parts).lower()

        if not combined_text:
            return "info"

        # Check for RCE proof patterns
        rce_patterns = ["id command", "whoami", "/etc/passwd", "cmd.exe", "system("]
        if any(pattern in combined_text for pattern in rce_patterns):
            return "critical"

        # Check vulnerability patterns by severity
        for pattern, severity in sorted(
            VULNERABILITY_PATTERNS.items(),
            key=lambda x: SEVERITY_LEVELS.get(x[1], 0),
            reverse=True,
        ):
            if pattern in combined_text:
                return severity

        # Default based on proof existence
        if proof and len(proof.strip()) > 10:
            return "medium"  # Has substantial proof
        elif description and len(description.strip()) > 50:
            return "low"  # Has description but no proof
        else:
            return "info"  # Minimal information

    def map_severity(self, finding: dict[str, Any]) -> str:
        """Map a finding to unified severity level.

        Args:
            finding: Dictionary containing finding data

        Returns:
            Unified severity level (critical|high|medium|low|info)
        """
        try:
            # Check for explicit severity first
            explicit_severity = (
                finding.get("severity") or finding.get("risk") or finding.get("level")
            )

            if explicit_severity:
                tool = finding.get("tool", "")
                mapped_severity = self._map_tool_severity(tool, explicit_severity)
                if mapped_severity in SEVERITY_LEVELS:
                    self.severity_stats[mapped_severity] += 1
                    return mapped_severity

            # Assess based on finding type and content
            finding_type = finding.get("type", "").lower()

            if finding_type == "endpoint" or "path" in finding or "url" in finding:
                path = (
                    finding.get("path") or finding.get("uri") or finding.get("url", "")
                )
                status_code = finding.get("status_code") or finding.get("status") or 200
                severity = self._assess_path_severity(path, int(status_code))

            elif finding_type == "port" or "port" in finding:
                port = finding.get("port", 0)
                service = finding.get("service", "")
                details = finding.get("details", {})
                severity = self._assess_port_severity(int(port), service, details)

            elif finding_type in ["vulnerability", "vuln"] or any(
                key in finding for key in ["cve", "template_id", "vuln_name"]
            ):
                name = (
                    finding.get("name")
                    or finding.get("title")
                    or finding.get("template_id", "")
                )
                description = finding.get("description") or finding.get("info", "")
                proof = (
                    finding.get("proof")
                    or finding.get("evidence")
                    or finding.get("response", "")
                )
                severity = self._assess_vulnerability_severity(name, description, proof)

            else:
                # Default assessment for unknown types
                severity = "info"

            # Ensure valid severity
            if severity not in SEVERITY_LEVELS:
                severity = "info"

            self.severity_stats[severity] += 1
            return severity

        except Exception as e:
            logger.error(f"Error mapping severity: {str(e)}")
            self.severity_stats["info"] += 1
            return "info"

    def get_stats(self) -> dict[str, int]:
        """Get severity mapping statistics.

        Returns:
            Dictionary with severity level counts
        """
        return self.severity_stats.copy()

    def reset_stats(self) -> None:
        """Reset severity mapping statistics."""
        self.severity_stats = dict.fromkeys(SEVERITY_LEVELS, 0)


# Global severity mapper instance
_global_mapper = SeverityMapper()


def map_finding_severity(
    finding: dict[str, Any],
) -> Literal["info", "low", "medium", "high", "critical"]:
    """Convenience function to map finding severity using global instance.

    Args:
        finding: Dictionary containing finding data

    Returns:
        Unified severity level
    """
    severity = _global_mapper.map_severity(finding)
    return cast(Literal["info", "low", "medium", "high", "critical"], severity)


def get_severity_stats() -> dict[str, int]:
    """Get severity mapping statistics from global instance.

    Returns:
        Dictionary with severity level counts
    """
    return _global_mapper.get_stats()


def reset_severity_stats() -> None:
    """Reset severity mapping statistics in global instance."""
    _global_mapper.reset_stats()


def is_high_severity(severity: str) -> bool:
    """Check if severity level is high or critical.

    Args:
        severity: Severity level string

    Returns:
        True if severity is high or critical
    """
    return severity.lower() in ["high", "critical"]


def compare_severities(severity1: str, severity2: str) -> int:
    """Compare two severity levels.

    Args:
        severity1: First severity level
        severity2: Second severity level

    Returns:
        1 if severity1 > severity2, -1 if severity1 < severity2, 0 if equal
    """
    level1 = SEVERITY_LEVELS.get(severity1.lower(), 0)
    level2 = SEVERITY_LEVELS.get(severity2.lower(), 0)

    if level1 > level2:
        return 1
    elif level1 < level2:
        return -1
    else:
        return 0
