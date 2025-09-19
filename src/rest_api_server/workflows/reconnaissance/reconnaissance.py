"""Reconnaissance workflow for comprehensive bug bounty target analysis."""

from flask import request

from src.rest_api_server.logger import get_logger
from src.rest_api_server.utils.registry import workflow

logger = get_logger(__name__)


@workflow()
def create_reconnaissance_workflow():
    """Create comprehensive reconnaissance workflow for bug bounty hunting."""
    # Import here to avoid circular imports
    from src.rest_api_server.managers import BugBountyTarget, bugbounty_manager

    data = request.get_json()

    domain = data["domain"]
    scope = data.get("scope", [])
    out_of_scope = data.get("out_of_scope", [])
    program_type = data.get("program_type", "web")

    logger.info(f"Creating reconnaissance workflow for {domain}")

    # Create bug bounty target
    target = BugBountyTarget(
        domain=domain,
        scope=scope,
        out_of_scope=out_of_scope,
        program_type=program_type,
    )

    # Generate reconnaissance workflow
    workflow = bugbounty_manager.create_reconnaissance_workflow(target)

    logger.info(f"Reconnaissance workflow created for {domain}")

    return workflow
