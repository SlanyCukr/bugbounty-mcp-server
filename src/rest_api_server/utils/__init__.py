"""Utility modules for the Bug Bounty MCP Server.

This package provides common utilities including:
- Command execution utilities
- Tool registry functionality
- Deduplication utilities
- Severity and confidence mapping utilities
"""

from .commands import execute_command
from .confidence_mapping import (
    ConfidenceMapper,
    combine_confidence_factors,
    enhance_finding_with_confidence,
    get_confidence_stats,
    is_high_confidence,
    map_finding_confidence,
    reset_confidence_stats,
)
from .deduplication import (
    FindingDeduplicator,
    create_finding_hash,
    deduplicate_findings,
    get_deduplication_stats,
    is_duplicate_finding,
    reset_deduplication_stats,
)
from .registry import get_registered_endpoints, tool
from .severity_mapping import (
    SeverityMapper,
    compare_severities,
    get_severity_stats,
    is_high_severity,
    map_finding_severity,
    reset_severity_stats,
)

__all__ = [
    # Command utilities
    "execute_command",
    # Registry utilities
    "tool",
    "get_registered_endpoints",
    # Deduplication utilities
    "FindingDeduplicator",
    "deduplicate_findings",
    "is_duplicate_finding",
    "get_deduplication_stats",
    "reset_deduplication_stats",
    "create_finding_hash",
    # Severity mapping utilities
    "SeverityMapper",
    "map_finding_severity",
    "get_severity_stats",
    "reset_severity_stats",
    "is_high_severity",
    "compare_severities",
    # Confidence mapping utilities
    "ConfidenceMapper",
    "map_finding_confidence",
    "get_confidence_stats",
    "reset_confidence_stats",
    "is_high_confidence",
    "combine_confidence_factors",
    "enhance_finding_with_confidence",
]
