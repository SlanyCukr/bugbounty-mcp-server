"""Business logic testing workflow for bug bounty hunting."""

from flask import request

import logger
from utils.registry import workflow

logger = logger.get_logger(__name__)


@workflow()
def create_business_logic_workflow():
    """Create business logic testing workflow."""
    # Import here to avoid circular imports
    from server import BugBountyTarget, bugbounty_manager

    data = request.get_json()

    domain = data["domain"]
    program_type = data.get("program_type", "web")

    logger.info(f"Creating business logic testing workflow for {domain}")

    # Create bug bounty target
    target = BugBountyTarget(domain=domain, program_type=program_type)

    # Generate business logic testing workflow
    workflow = bugbounty_manager.create_business_logic_testing_workflow(target)

    logger.info(f"Business logic testing workflow created for {domain}")

    return workflow
