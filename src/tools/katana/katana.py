import logging

from flask import request

from utils.commands import execute_command
from utils.registry import tool

logger = logging.getLogger(__name__)


@tool(required_fields=["url"])
def execute_katana():
    """Execute Katana for next-generation crawling and spidering."""
    data = request.get_json()
    url = data["url"]

    logger.info(f"Executing Katana on {url}")

    katana_params = {
        "url": url,
        "depth": data.get("depth", 3),
        "js_crawl": data.get("js_crawl", True),
        "form_extraction": data.get("form_extraction", True),
        "output_format": data.get("output_format", "json"),
        "max_pages": data.get("max_pages", 100),
        "crawl_duration": data.get("crawl_duration", 0),
        "delay": data.get("delay", 0),
        "concurrency": data.get("concurrency", 10),
        "parallelism": data.get("parallelism", 10),
        "scope": data.get("scope", ""),
        "out_of_scope": data.get("out_of_scope", ""),
        "field_scope": data.get("field_scope", ""),
        "no_scope": data.get("no_scope", False),
        "display_out_scope": data.get("display_out_scope", False),
        "output_file": data.get("output_file", ""),
        "store_response": data.get("store_response", False),
        "store_response_dir": data.get("store_response_dir", ""),
        "headers": data.get("headers", ""),
        "cookies": data.get("cookies", ""),
        "user_agent": data.get("user_agent", ""),
        "proxy": data.get("proxy", ""),
        "system_chrome": data.get("system_chrome", False),
        "headless": data.get("headless", True),
        "no_incognito": data.get("no_incognito", False),
        "chrome_data_dir": data.get("chrome_data_dir", ""),
        "show_source": data.get("show_source", False),
        "show_browser": data.get("show_browser", False),
        "timeout": data.get("timeout", 10),
        "retry": data.get("retry", 1),
        "retry_wait": data.get("retry_wait", 1),
        "crawl_scope": data.get("crawl_scope", ""),
        "filter_regex": data.get("filter_regex", ""),
        "match_regex": data.get("match_regex", ""),
        "extension_filter": data.get("extension_filter", ""),
        "mime_filter": data.get("mime_filter", ""),
        "additional_args": data.get("additional_args", ""),
    }

    # Build comprehensive katana command
    command = f"katana -u {url}"

    # Core crawling parameters
    if katana_params["depth"] != 3:
        command += f" -d {katana_params['depth']}"
    if katana_params["concurrency"] != 10:
        command += f" -c {katana_params['concurrency']}"
    if katana_params["parallelism"] != 10:
        command += f" -p {katana_params['parallelism']}"

    # Crawling behavior
    if katana_params["max_pages"] > 0:
        command += f" -kf {katana_params['max_pages']}"
    if katana_params["crawl_duration"] > 0:
        command += f" -ct {katana_params['crawl_duration']}"
    if katana_params["delay"] > 0:
        command += f" -delay {katana_params['delay']}"

    # JavaScript crawling
    if katana_params["js_crawl"]:
        command += " -jc"

    # Form extraction
    if katana_params["form_extraction"]:
        command += " -fx"

    # Scope control
    if katana_params["scope"]:
        command += f" -cs '{katana_params['scope']}'"
    if katana_params["out_of_scope"]:
        command += f" -cos '{katana_params['out_of_scope']}'"
    if katana_params["field_scope"]:
        command += f" -fs '{katana_params['field_scope']}'"
    if katana_params["no_scope"]:
        command += " -ns"
    if katana_params["display_out_scope"]:
        command += " -do"

    # Authentication and headers
    if katana_params["headers"]:
        command += f" -H '{katana_params['headers']}'"
    if katana_params["cookies"]:
        command += f" -cookie '{katana_params['cookies']}'"
    if katana_params["user_agent"]:
        command += f" -ua '{katana_params['user_agent']}'"

    # Proxy settings
    if katana_params["proxy"]:
        command += f" -proxy {katana_params['proxy']}"

    # Chrome options
    if katana_params["system_chrome"]:
        command += " -sc"
    if not katana_params["headless"]:
        command += " -xhr"
    if katana_params["no_incognito"]:
        command += " -ni"
    if katana_params["chrome_data_dir"]:
        command += f" -cdd '{katana_params['chrome_data_dir']}'"
    if katana_params["show_source"]:
        command += " -sr"
    if katana_params["show_browser"]:
        command += " -sb"

    # Timeout and retry settings
    if katana_params["timeout"] != 10:
        command += f" -timeout {katana_params['timeout']}"
    if katana_params["retry"] != 1:
        command += f" -retry {katana_params['retry']}"
    if katana_params["retry_wait"] != 1:
        command += f" -rw {katana_params['retry_wait']}"

    # Output format
    if katana_params["output_format"] == "json":
        command += " -jsonl"

    # Filtering
    if katana_params["filter_regex"]:
        command += f" -fr '{katana_params['filter_regex']}'"
    if katana_params["match_regex"]:
        command += f" -mr '{katana_params['match_regex']}'"
    if katana_params["extension_filter"]:
        command += f" -ef {katana_params['extension_filter']}"
    if katana_params["mime_filter"]:
        command += f" -mf {katana_params['mime_filter']}"

    # Output file
    if katana_params["output_file"]:
        command += f" -o {katana_params['output_file']}"

    # Store response
    if katana_params["store_response"]:
        command += " -sr"
    if katana_params["store_response_dir"]:
        command += f" -srd '{katana_params['store_response_dir']}'"

    # Additional arguments
    if katana_params["additional_args"]:
        command += f" {katana_params['additional_args']}"

    logger.info(f"Executing Katana command: {command}")

    # Execute the actual katana command
    result = execute_command(command, timeout=300)

    # Prepare the response based on execution result
    if result["success"]:
        response_result = {
            "tool": "katana",
            "target": url,
            "parameters": katana_params,
            "command": command,
            "status": "completed" if result["success"] else "failed",
            "stdout": result["stdout"],
            "stderr": result["stderr"],
            "return_code": result["return_code"],
            "execution_success": True,
            "raw_output": result["stdout"],
        }
    else:
        response_result = {
            "tool": "katana",
            "target": url,
            "parameters": katana_params,
            "command": command,
            "status": "failed",
            "stdout": result["stdout"],
            "stderr": result["stderr"],
            "return_code": result["return_code"],
            "execution_success": False,
            "error": result.get("error", "Command execution failed"),
        }

    return response_result
