"""Workflows package - imports all workflow modules to register their endpoints."""

# Import all workflow modules to trigger endpoint registration
from . import (
    business_logic,
    comprehensive_assessment,
    file_upload_testing,
    osint,
    reconnaissance,
    vulnerability_hunting,
)
