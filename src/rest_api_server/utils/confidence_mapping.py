"""Confidence mapping utilities for bug bounty findings.

This module provides functionality to assess the reliability and confidence
level of findings based on detection methods and evidence quality.
"""

import logging
import re
from typing import Any, Literal, cast

logger = logging.getLogger(__name__)

# Confidence levels
CONFIDENCE_LEVELS = {"high": 3, "medium": 2, "low": 1}

# Template-based detection indicators (high confidence)
TEMPLATE_INDICATORS = [
    "nuclei",
    "template",
    "template_id",
    "matcher",
    "json_template",
    "yaml_template",
]

# Pattern matching indicators (medium confidence)
PATTERN_INDICATORS = [
    "regex",
    "pattern",
    "signature",
    "fingerprint",
    "heuristic",
    "keyword_match",
]

# Speculative detection indicators (low confidence)
SPECULATIVE_INDICATORS = [
    "possible",
    "potential",
    "likely",
    "probable",
    "suspected",
    "may_be",
    "could_be",
    "fuzzing",
    "brute_force",
    "dictionary",
]

# HTTP response patterns that increase confidence
RESPONSE_CONFIDENCE_PATTERNS = {
    # High confidence patterns
    "high": [
        r"<title>.*error.*</title>",
        r"stack trace",
        r"exception.*:",
        r"sql.*error",
        r"mysql.*error",
        r"postgresql.*error",
        r"oracle.*error",
        r"debug.*information",
        r"phpinfo\(\)",
        r"<\?php",
        r"root:[x*]:0:0:",
        r"/etc/passwd",
        r"id=.*uid=.*gid=",
        r"\"success\":\s*true",
        r"\"status\":\s*\"ok\"",
        r"admin.*panel",
        r"dashboard.*login",
    ],
    # Medium confidence patterns
    "medium": [
        r"version\s+\d+\.\d+",
        r"server:\s*.+",
        r"x-powered-by:",
        r"set-cookie:",
        r"location:\s*http",
        r"content-type:\s*application",
        r"<input.*password",
        r"<form.*method",
        r"login.*form",
        r"username.*password",
    ],
    # Low confidence patterns
    "low": [
        r"\d+\.\d+\.\d+\.\d+",  # IP addresses
        r"http://.*",
        r"https://.*",
        r"<html.*>",
        r"<body.*>",
        r"content-length:\s*\d+",
        r"200\s+ok",
        r"404\s+not\s+found",
    ],
}

# Tool-specific confidence mappings
TOOL_CONFIDENCE_MAPPINGS = {
    "nuclei": {
        "template_match": "high",
        "info_template": "medium",
        "custom_template": "medium",
        "community_template": "high",
    },
    "nmap": {
        "version_detection": "high",
        "service_detection": "medium",
        "port_scan": "high",
        "os_detection": "medium",
        "script_scan": "medium",
    },
    "nikto": {"cgi_scan": "medium", "plugin_match": "high", "generic_test": "low"},
    "sqlmap": {
        "payload_success": "high",
        "time_based": "medium",
        "boolean_based": "high",
        "error_based": "high",
        "union_based": "high",
    },
    "gobuster": {
        "status_200": "high",
        "status_403": "medium",
        "status_301": "high",
        "status_302": "medium",
        "fuzzing": "low",
    },
    "ffuf": {
        "status_match": "high",
        "size_filter": "medium",
        "word_filter": "medium",
        "regex_filter": "medium",
    },
    "subfinder": {
        "multiple_sources": "high",
        "single_source": "medium",
        "passive_enum": "high",
    },
    "amass": {"active_enum": "high", "passive_enum": "high", "dns_resolution": "high"},
}

# Status code confidence levels
STATUS_CODE_CONFIDENCE = {
    200: "high",  # OK - resource exists
    201: "high",  # Created
    204: "high",  # No Content but processed
    301: "high",  # Moved Permanently - resource exists
    302: "medium",  # Found - temporary redirect
    403: "medium",  # Forbidden - resource exists but access denied
    401: "medium",  # Unauthorized - authentication required
    405: "medium",  # Method Not Allowed - endpoint exists
    500: "medium",  # Internal Server Error - processing attempted
    503: "low",  # Service Unavailable - temporary issue
    404: "low",  # Not Found - may not exist
    400: "low",  # Bad Request - unclear if endpoint exists
    429: "low",  # Rate Limited - unclear
}


class ConfidenceMapper:
    """Maps findings to confidence levels based on detection methods and evidence."""

    def __init__(self):
        """Initialize confidence mapper."""
        self.confidence_stats = {"high": 0, "medium": 0, "low": 0}

    def _analyze_response_content(self, content: str) -> str:
        """Analyze response content for confidence indicators.

        Args:
            content: Response content to analyze

        Returns:
            Confidence level based on content analysis
        """
        if not content:
            return "low"

        content_lower = content.lower()

        # Check high confidence patterns first
        for pattern in RESPONSE_CONFIDENCE_PATTERNS["high"]:
            if re.search(pattern, content_lower, re.IGNORECASE):
                return "high"

        # Check medium confidence patterns
        for pattern in RESPONSE_CONFIDENCE_PATTERNS["medium"]:
            if re.search(pattern, content_lower, re.IGNORECASE):
                return "medium"

        # Default to low if only basic patterns match
        return "low"

    def _assess_tool_confidence(self, tool: str, finding: dict[str, Any]) -> str:
        """Assess confidence based on tool-specific factors.

        Args:
            tool: Tool name
            finding: Finding data

        Returns:
            Confidence level based on tool assessment
        """
        tool_lower = tool.lower() if tool else ""

        if tool_lower in TOOL_CONFIDENCE_MAPPINGS:
            tool_mapping = TOOL_CONFIDENCE_MAPPINGS[tool_lower]

            # Check for specific detection methods
            for method, confidence in tool_mapping.items():
                if method in str(finding).lower():
                    return confidence

            # Tool-specific logic
            if tool_lower == "nuclei":
                template_id = finding.get("template_id") or finding.get("template")
                if template_id:
                    if any(
                        indicator in template_id.lower()
                        for indicator in ["cve-", "exploit", "rce", "sqli"]
                    ):
                        return "high"
                    return "medium"

            elif tool_lower == "nmap":
                if finding.get("version") or finding.get("service"):
                    return "high"
                if finding.get("state") == "open":
                    return "high"

            elif tool_lower in ["gobuster", "ffuf", "dirb", "feroxbuster"]:
                status_code = finding.get("status_code") or finding.get("status")
                if status_code:
                    return STATUS_CODE_CONFIDENCE.get(int(status_code), "low")

        return "medium"  # Default for known tools

    def _detect_detection_method(self, finding: dict[str, Any]) -> str:
        """Detect the primary detection method used.

        Args:
            finding: Finding data

        Returns:
            Confidence level based on detection method
        """
        finding_str = str(finding).lower()

        # Check for template-based detection (high confidence)
        for indicator in TEMPLATE_INDICATORS:
            if indicator in finding_str:
                return "high"

        # Check for speculative detection (low confidence)
        for indicator in SPECULATIVE_INDICATORS:
            if indicator in finding_str:
                return "low"

        # Check for pattern matching (medium confidence)
        for indicator in PATTERN_INDICATORS:
            if indicator in finding_str:
                return "medium"

        return "medium"  # Default

    def _assess_evidence_quality(self, finding: dict[str, Any]) -> str:
        """Assess the quality and quantity of evidence.

        Args:
            finding: Finding data

        Returns:
            Confidence level based on evidence quality
        """
        evidence_score = 0

        # Check for various types of evidence
        evidence_fields = [
            "response",
            "proof",
            "evidence",
            "payload",
            "request",
            "headers",
            "body",
            "output",
        ]

        for field in evidence_fields:
            if field in finding:
                value = finding[field]
                if value and len(str(value).strip()) > 10:
                    evidence_score += 1

        # Check response content if available
        response_content = (
            finding.get("response")
            or finding.get("output")
            or finding.get("stdout")
            or ""
        )

        if response_content:
            content_confidence = self._analyze_response_content(response_content)
            if content_confidence == "high":
                evidence_score += 3
            elif content_confidence == "medium":
                evidence_score += 2
            else:
                evidence_score += 1

        # Map evidence score to confidence
        if evidence_score >= 4:
            return "high"
        elif evidence_score >= 2:
            return "medium"
        else:
            return "low"

    def _assess_status_code_confidence(self, finding: dict[str, Any]) -> str | None:
        """Assess confidence based on HTTP status code.

        Args:
            finding: Finding data

        Returns:
            Confidence level based on status code, or None if not applicable
        """
        status_code = (
            finding.get("status_code") or finding.get("status") or finding.get("code")
        )

        if status_code:
            try:
                code = int(status_code)
                return STATUS_CODE_CONFIDENCE.get(code, "low")
            except (ValueError, TypeError):
                pass

        return None

    def map_confidence(self, finding: dict[str, Any]) -> str:
        """Map a finding to confidence level.

        Args:
            finding: Dictionary containing finding data

        Returns:
            Confidence level (high|medium|low)
        """
        try:
            # Start with a list of confidence assessments
            confidence_assessments = []

            # 1. Check for explicit confidence
            explicit_confidence = (
                finding.get("confidence")
                or finding.get("reliability")
                or finding.get("certainty")
            )
            if explicit_confidence:
                normalized = explicit_confidence.lower().strip()
                if normalized in CONFIDENCE_LEVELS:
                    confidence_assessments.append(normalized)

            # 2. Assess based on tool and detection method
            tool = finding.get("tool", "")
            if tool:
                tool_confidence = self._assess_tool_confidence(tool, finding)
                confidence_assessments.append(tool_confidence)

            # 3. Detect primary detection method
            method_confidence = self._detect_detection_method(finding)
            confidence_assessments.append(method_confidence)

            # 4. Assess evidence quality
            evidence_confidence = self._assess_evidence_quality(finding)
            confidence_assessments.append(evidence_confidence)

            # 5. Check status code if applicable
            status_confidence = self._assess_status_code_confidence(finding)
            if status_confidence:
                confidence_assessments.append(status_confidence)

            # Calculate final confidence using weighted average
            # Give more weight to tool-specific and evidence assessments
            weights = {"high": 3, "medium": 2, "low": 1}

            weighted_score = sum(weights[conf] for conf in confidence_assessments)
            avg_score = weighted_score / len(confidence_assessments)

            # Map average score to confidence level
            if avg_score >= 2.5:
                final_confidence = "high"
            elif avg_score >= 1.5:
                final_confidence = "medium"
            else:
                final_confidence = "low"

            # Additional rules for specific cases
            finding_str = str(finding).lower()

            # Lower confidence for fuzzing/brute force results
            if any(
                term in finding_str
                for term in ["fuzz", "brute", "dictionary", "wordlist"]
            ):
                if final_confidence == "high":
                    final_confidence = "medium"
                elif final_confidence == "medium":
                    final_confidence = "low"

            # Higher confidence for template-based detections
            if any(term in finding_str for term in ["template", "cve-", "nuclei"]):
                if final_confidence == "low":
                    final_confidence = "medium"
                elif final_confidence == "medium" and "cve-" in finding_str:
                    final_confidence = "high"

            self.confidence_stats[final_confidence] += 1
            return final_confidence

        except Exception as e:
            logger.error(f"Error mapping confidence: {str(e)}")
            self.confidence_stats["low"] += 1
            return "low"

    def get_stats(self) -> dict[str, int]:
        """Get confidence mapping statistics.

        Returns:
            Dictionary with confidence level counts
        """
        return self.confidence_stats.copy()

    def reset_stats(self) -> None:
        """Reset confidence mapping statistics."""
        self.confidence_stats = dict.fromkeys(CONFIDENCE_LEVELS, 0)


# Global confidence mapper instance
_global_mapper = ConfidenceMapper()


def map_finding_confidence(finding: dict[str, Any]) -> Literal["low", "medium", "high"]:
    """Convenience function to map finding confidence using global instance.

    Args:
        finding: Dictionary containing finding data

    Returns:
        Confidence level (high|medium|low)
    """
    confidence = _global_mapper.map_confidence(finding)
    return cast(Literal["low", "medium", "high"], confidence)


def get_confidence_stats() -> dict[str, int]:
    """Get confidence mapping statistics from global instance.

    Returns:
        Dictionary with confidence level counts
    """
    return _global_mapper.get_stats()


def reset_confidence_stats() -> None:
    """Reset confidence mapping statistics in global instance."""
    _global_mapper.reset_stats()


def is_high_confidence(confidence: str) -> bool:
    """Check if confidence level is high.

    Args:
        confidence: Confidence level string

    Returns:
        True if confidence is high
    """
    return confidence.lower() == "high"


def combine_confidence_factors(factors: list[str]) -> str:
    """Combine multiple confidence factors into final assessment.

    Args:
        factors: List of confidence level strings

    Returns:
        Combined confidence level
    """
    if not factors:
        return "low"

    weights = {"high": 3, "medium": 2, "low": 1}
    total_weight = sum(weights.get(factor.lower(), 1) for factor in factors)
    avg_weight = total_weight / len(factors)

    if avg_weight >= 2.5:
        return "high"
    elif avg_weight >= 1.5:
        return "medium"
    else:
        return "low"


def enhance_finding_with_confidence(finding: dict[str, Any]) -> dict[str, Any]:
    """Enhance a finding with confidence assessment.

    Args:
        finding: Original finding dictionary

    Returns:
        Enhanced finding with confidence field
    """
    enhanced = finding.copy()
    enhanced["confidence"] = map_finding_confidence(finding)
    return enhanced
