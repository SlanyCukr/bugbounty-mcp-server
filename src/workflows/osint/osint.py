"""OSINT gathering workflow for comprehensive target intelligence."""

import logging

from flask import request

from utils.registry import workflow

logger = logging.getLogger(__name__)


@workflow()
def create_osint_workflow():
    """Create OSINT gathering workflow."""
    # Import here to avoid circular imports
    from server import BugBountyTarget, bugbounty_manager

    data = request.get_json()

    domain = data["domain"]

    logger.info(f"Creating OSINT workflow for {domain}")

    # Create bug bounty target
    target = BugBountyTarget(domain=domain)

    # Generate OSINT workflow
    workflow = bugbounty_manager.create_osint_workflow(target)

    logger.info(f"OSINT workflow created for {domain}")

    return workflow
