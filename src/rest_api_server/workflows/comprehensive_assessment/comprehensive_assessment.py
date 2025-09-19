"""Comprehensive assessment workflow combining all bug bounty workflows."""

from datetime import datetime

from flask import request

from src.rest_api_server.logger import get_logger
from src.rest_api_server.utils.registry import workflow

logger = get_logger(__name__)


@workflow()
def create_comprehensive_bugbounty_assessment():
    """Create comprehensive bug bounty assessment combining all workflows."""
    # Import here to avoid circular imports
    from src.rest_api_server.managers import BugBountyTarget, bugbounty_manager

    data = request.get_json()

    domain = data["domain"]
    scope = data.get("scope", [])
    priority_vulns = data.get("priority_vulns", ["rce", "sqli", "xss", "idor", "ssrf"])
    include_osint = data.get("include_osint", True)
    include_business_logic = data.get("include_business_logic", True)

    logger.info(f"Creating comprehensive bug bounty assessment for {domain}")

    # Create bug bounty target
    target = BugBountyTarget(domain=domain, scope=scope, priority_vulns=priority_vulns)

    # Generate all workflows
    assessment = {
        "target": domain,
        "reconnaissance": bugbounty_manager.create_reconnaissance_workflow(target),
        "vulnerability_hunting": (
            bugbounty_manager.create_vulnerability_hunting_workflow(target)
        ),
    }

    if include_osint:
        assessment["osint"] = bugbounty_manager.create_osint_workflow(target)

    if include_business_logic:
        assessment["business_logic"] = (
            bugbounty_manager.create_business_logic_testing_workflow(target)
        )

    # Calculate total estimates
    total_time = sum(
        workflow.get("estimated_time", 0) for workflow in assessment.values()
    )
    total_tools = sum(
        workflow.get("tools_count", 0) for workflow in assessment.values()
    )

    assessment["summary"] = {
        "total_estimated_time": total_time,
        "total_tools": total_tools,
        "workflow_count": len([k for k in assessment.keys() if k != "target"]),
        "priority_score": assessment["vulnerability_hunting"].get("priority_score", 0),
    }

    logger.info(f"Comprehensive bug bounty assessment created for {domain}")

    return {
        "success": True,
        "assessment": assessment,
        "timestamp": datetime.now().isoformat(),
    }
