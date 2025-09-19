"""Deduplication utilities for bug bounty findings.

This module provides functionality to deduplicate findings using hash keys
and track duplicate statistics across various finding types.
"""

import hashlib
import logging
from typing import Any

logger = logging.getLogger(__name__)


class FindingDeduplicator:
    """Handles deduplication of bug bounty findings using hash-based keys."""

    def __init__(self):
        """Initialize the deduplicator with empty tracking."""
        self.seen_hashes: set[str] = set()
        self.duplicate_stats: dict[str, Any] = {
            "total_processed": 0,
            "duplicates_found": 0,
            "unique_findings": 0,
            "by_type": {},
        }

    def _generate_hash_key(
        self, finding_type: str, host_or_url: str, evidence_key: str
    ) -> str:
        """Generate a hash key for deduplication.

        Args:
            finding_type: Type of finding (subdomain, port, vuln, endpoint, param)
            host_or_url: Host or URL associated with the finding
            evidence_key: Key evidence that identifies the finding

        Returns:
            SHA256 hash string for deduplication
        """
        # Normalize inputs for consistent hashing
        normalized_host = host_or_url.lower().strip()
        normalized_type = finding_type.lower().strip()
        normalized_evidence = str(evidence_key).lower().strip()

        # Create composite key
        composite_key = f"{normalized_host}|{normalized_type}|{normalized_evidence}"

        # Generate SHA256 hash
        return hashlib.sha256(composite_key.encode("utf-8")).hexdigest()

    def _extract_finding_components(
        self, finding: dict[str, Any]
    ) -> tuple[str, str, str]:
        """Extract components needed for hash generation from a finding.

        Args:
            finding: Dictionary containing finding data

        Returns:
            Tuple of (finding_type, host_or_url, evidence_key)
        """
        # Determine finding type
        finding_type = finding.get("type", "unknown")
        if not finding_type and "tool" in finding:
            # Infer type from tool
            tool = finding["tool"].lower()
            if tool in ["subfinder", "amass", "dnsenum"]:
                finding_type = "subdomain"
            elif tool in ["nmap", "masscan", "rustscan"]:
                finding_type = "port"
            elif tool in ["nuclei", "nikto", "sqlmap"]:
                finding_type = "vulnerability"
            elif tool in ["ffuf", "gobuster", "dirb", "feroxbuster"]:
                finding_type = "endpoint"
            elif tool in ["arjun", "paramspider"]:
                finding_type = "parameter"
            else:
                finding_type = "unknown"

        # Extract host/URL
        host_or_url = (
            finding.get("host")
            or finding.get("url")
            or finding.get("target")
            or finding.get("domain")
            or "unknown"
        )

        # Extract evidence key based on finding type
        evidence_key = ""
        if finding_type == "subdomain":
            evidence_key = finding.get("subdomain", finding.get("host", ""))
        elif finding_type == "port":
            port = finding.get("port", "")
            service = finding.get("service", "")
            evidence_key = f"{port}:{service}"
        elif finding_type == "vulnerability":
            vuln_id = finding.get("template_id", finding.get("id", ""))
            vuln_name = finding.get("name", finding.get("title", ""))
            evidence_key = f"{vuln_id}:{vuln_name}"
        elif finding_type == "endpoint":
            path = finding.get("path", finding.get("uri", ""))
            status = finding.get("status_code", finding.get("status", ""))
            evidence_key = f"{path}:{status}"
        elif finding_type == "parameter":
            param_name = finding.get("parameter", finding.get("param", ""))
            param_type = finding.get("param_type", "")
            evidence_key = f"{param_name}:{param_type}"
        else:
            # Fallback: use any available identifying information
            evidence_key = (
                finding.get("name")
                or finding.get("title")
                or finding.get("description", "")[:50]
                or str(finding)[:50]
            )

        return finding_type, host_or_url, evidence_key

    def is_duplicate(self, finding: dict[str, Any]) -> bool:
        """Check if a finding is a duplicate.

        Args:
            finding: Dictionary containing finding data

        Returns:
            True if the finding is a duplicate, False otherwise
        """
        try:
            finding_type, host_or_url, evidence_key = self._extract_finding_components(
                finding
            )
            hash_key = self._generate_hash_key(finding_type, host_or_url, evidence_key)

            self.duplicate_stats["total_processed"] += 1

            # Track by type
            if finding_type not in self.duplicate_stats["by_type"]:
                self.duplicate_stats["by_type"][finding_type] = {
                    "total": 0,
                    "duplicates": 0,
                    "unique": 0,
                }

            self.duplicate_stats["by_type"][finding_type]["total"] += 1

            if hash_key in self.seen_hashes:
                self.duplicate_stats["duplicates_found"] += 1
                self.duplicate_stats["by_type"][finding_type]["duplicates"] += 1
                logger.debug(f"Duplicate found: {finding_type} - {hash_key[:16]}...")
                return True
            else:
                self.seen_hashes.add(hash_key)
                self.duplicate_stats["unique_findings"] += 1
                self.duplicate_stats["by_type"][finding_type]["unique"] += 1
                logger.debug(f"New finding: {finding_type} - {hash_key[:16]}...")
                return False

        except Exception as e:
            logger.error(f"Error checking for duplicate: {str(e)}")
            # On error, consider it not a duplicate to avoid losing data
            return False

    def deduplicate_findings(
        self, findings: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Deduplicate a list of findings.

        Args:
            findings: List of finding dictionaries

        Returns:
            List of unique findings
        """
        if not findings:
            return []

        unique_findings = []
        for finding in findings:
            if not self.is_duplicate(finding):
                unique_findings.append(finding)

        logger.info(
            "Deduplication complete: %d unique out of %d total",
            len(unique_findings),
            len(findings),
        )
        return unique_findings

    def get_stats(self) -> dict[str, Any]:
        """Get deduplication statistics.

        Returns:
            Dictionary containing deduplication statistics
        """
        return self.duplicate_stats.copy()

    def reset_stats(self) -> None:
        """Reset deduplication statistics and seen hashes."""
        self.seen_hashes.clear()
        self.duplicate_stats = {
            "total_processed": 0,
            "duplicates_found": 0,
            "unique_findings": 0,
            "by_type": {},
        }
        logger.info("Deduplication stats reset")


# Global deduplicator instance for convenience
_global_deduplicator = FindingDeduplicator()


def deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convenience function to deduplicate findings using global instance.

    Args:
        findings: List of finding dictionaries

    Returns:
        List of unique findings
    """
    return _global_deduplicator.deduplicate_findings(findings)


def is_duplicate_finding(finding: dict[str, Any]) -> bool:
    """Convenience function to check if finding is duplicate using global instance.

    Args:
        finding: Dictionary containing finding data

    Returns:
        True if the finding is a duplicate, False otherwise
    """
    return _global_deduplicator.is_duplicate(finding)


def get_deduplication_stats() -> dict[str, Any]:
    """Get deduplication statistics from global instance.

    Returns:
        Dictionary containing deduplication statistics
    """
    return _global_deduplicator.get_stats()


def reset_deduplication_stats() -> None:
    """Reset deduplication statistics in global instance."""
    _global_deduplicator.reset_stats()


def create_finding_hash(finding_type: str, host_or_url: str, evidence_key: str) -> str:
    """Create a hash for manual deduplication.

    Args:
        finding_type: Type of finding
        host_or_url: Host or URL
        evidence_key: Evidence key

    Returns:
        SHA256 hash string
    """
    return _global_deduplicator._generate_hash_key(
        finding_type, host_or_url, evidence_key
    )
