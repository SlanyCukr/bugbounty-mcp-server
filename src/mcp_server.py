#!/usr/bin/env python3
"""
Bug Bounty MCP Server - Focused Bug Bounty Hunting Tools
"""

import sys
import os
import argparse
import logging
from typing import Dict, Any, Optional, List
import requests
import time
from datetime import datetime
import json

from fastmcp import FastMCP


# Constants
DEFAULT_REQUEST_TIMEOUT = 30
MAX_RETRIES = 3


class BugBountyColors:
    """Color palette for bug bounty hunting"""
    
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    
    # Enhanced colors for security testing
    HACKER_RED = '\033[38;5;196m'
    MATRIX_GREEN = '\033[38;5;46m'
    NEON_BLUE = '\033[38;5;51m'
    CYBER_ORANGE = '\033[38;5;208m'
    TERMINAL_GRAY = '\033[38;5;240m'
    
    # Status colors
    SUCCESS = GREEN
    ERROR = RED
    WARNING = YELLOW
    INFO = CYAN
    DEBUG = TERMINAL_GRAY


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class BugBountyAPIClient:
    """Client for communicating with the Bug Bounty API Server"""
    
    def __init__(self, server_url: str, timeout: int = DEFAULT_REQUEST_TIMEOUT):
        """Initialize the Bug Bounty API Client"""
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        
        # Try to connect to server
        connected = False
        for i in range(MAX_RETRIES):
            try:
                logger.info(f"🔗 Attempting to connect to Bug Bounty API at {server_url} (attempt {i+1}/{MAX_RETRIES})")
                test_response = self.session.get(f"{self.server_url}/health", timeout=5)
                test_response.raise_for_status()
                health_check = test_response.json()
                connected = True
                logger.info(f"🎯 Successfully connected to Bug Bounty API Server")
                logger.info(f"🏥 Server health status: {health_check.get('status', 'unknown')}")
                break
            except requests.exceptions.ConnectionError:
                logger.warning(f"🔌 Connection refused to {server_url}. Make sure the Bug Bounty API server is running.")
                time.sleep(2)
            except Exception as e:
                logger.warning(f"⚠️  Connection test failed: {str(e)}")
                time.sleep(2)
        
        if not connected:
            error_msg = f"Failed to establish connection to Bug Bounty API Server at {server_url} after {MAX_RETRIES} attempts"
            logger.error(error_msg)
    
    def safe_post(self, endpoint: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform a POST request with enhanced error handling"""
        try:
            url = f"{self.server_url}/{endpoint}"
            headers = {'Content-Type': 'application/json'}
            
            logger.debug(f"🌐 POST {url}")
            logger.debug(f"📦 Data: {json.dumps(data, indent=2)}")
            
            response = self.session.post(
                url, 
                json=data, 
                headers=headers, 
                timeout=self.timeout
            )
            
            logger.debug(f"📡 Response Status: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                logger.debug(f"✅ Request successful")
                return result
            else:
                error_msg = f"HTTP {response.status_code}: {response.text}"
                logger.error(f"❌ Request failed: {error_msg}")
                return {
                    'success': False, 
                    'error': error_msg,
                    'status_code': response.status_code
                }
                
        except requests.exceptions.Timeout:
            error_msg = f"Request timeout after {self.timeout} seconds"
            logger.error(f"⏰ {error_msg}")
            return {'success': False, 'error': error_msg}
            
        except requests.exceptions.ConnectionError:
            error_msg = "Connection error - server may be unavailable"
            logger.error(f"🔌 {error_msg}")
            return {'success': False, 'error': error_msg}
            
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            logger.error(f"💥 {error_msg}")
            return {'success': False, 'error': error_msg}


def setup_bug_bounty_mcp_server(api_client: BugBountyAPIClient) -> FastMCP:
    """
    Set up the Bug Bounty MCP server with focused security testing tools
    
    Returns:
        Configured FastMCP instance
    """
    mcp = FastMCP("bugbounty-mcp")
    
    # ============================================================================
    # NETWORK SCANNING
    # ============================================================================

    @mcp.tool()
    def nmap_scan(target: str, scan_type: str = "-sV", ports: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute an enhanced Nmap scan against a target with real-time logging.
        
        Args:
            target: The IP address or hostname to scan
            scan_type: Scan type (e.g., -sV for version detection, -sC for scripts)
            ports: Comma-separated list of ports or port ranges
            additional_args: Additional Nmap arguments
            
        Returns:
            Scan results with enhanced telemetry
        """
        data = {
            "target": target,
            "scan_type": scan_type,
            "ports": ports,
            "additional_args": additional_args
        }
        
        logger.info(f"🔍 Starting Nmap scan on {target}")
        result = api_client.safe_post("api/nmap", data)
        
        if result.get('success'):
            logger.info(f"✅ Nmap scan completed on {target}")
        else:
            logger.error(f"❌ Nmap scan failed")
        
        return result

    @mcp.tool()
    def nmap_advanced_scan(target: str, scan_type: str = "-sS", ports: str = "", 
                          timing: str = "-T4", scripts: str = "", os_detection: bool = False, 
                          service_detection: bool = True, aggressive: bool = False, 
                          stealth: bool = False, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute advanced Nmap scan with comprehensive options for bug bounty hunting.
        
        Args:
            target: Target IP or hostname
            scan_type: Scan technique (-sS, -sT, -sU, etc.)
            ports: Port specification
            timing: Timing template (-T0 to -T5)
            scripts: NSE scripts to run
            os_detection: Enable OS detection
            service_detection: Enable service version detection
            aggressive: Enable aggressive scan mode
            stealth: Enable stealth scan options
            additional_args: Additional arguments
            
        Returns:
            Advanced scan results
        """
        data = {
            "target": target,
            "scan_type": scan_type,
            "ports": ports,
            "timing": timing,
            "scripts": scripts,
            "os_detection": os_detection,
            "service_detection": service_detection,
            "aggressive": aggressive,
            "stealth": stealth,
            "additional_args": additional_args
        }
        
        logger.info(f"🎯 Starting advanced Nmap scan on {target}")
        result = api_client.safe_post("api/nmap-advanced", data)
        
        if result.get('success'):
            logger.info(f"✅ Advanced Nmap scan completed on {target}")
        else:
            logger.error(f"❌ Advanced Nmap scan failed")
        
        return result

    @mcp.tool()
    def rustscan_fast_scan(target: str, ports: str = "", ulimit: int = 5000, 
                          batch_size: int = 4500, timeout: int = 1500, 
                          tries: int = 1, no_nmap: bool = False, 
                          additional_args: str = "") -> Dict[str, Any]:
        """
        Execute RustScan for ultra-fast port scanning.
        
        Args:
            target: Target IP address or hostname
            ports: Custom port range (default: all ports)
            ulimit: File descriptor limit
            batch_size: Batch size for port scanning
            timeout: Socket timeout in milliseconds
            tries: Number of tries per port
            no_nmap: Skip nmap integration
            additional_args: Additional RustScan arguments
            
        Returns:
            Fast port scan results
        """
        data = {
            "target": target,
            "ports": ports,
            "ulimit": ulimit,
            "batch_size": batch_size,
            "timeout": timeout,
            "tries": tries,
            "no_nmap": no_nmap,
            "additional_args": additional_args
        }
        
        logger.info(f"⚡ Starting RustScan fast scan on {target}")
        result = api_client.safe_post("api/rustscan", data)
        
        if result.get('success'):
            logger.info(f"✅ RustScan completed on {target}")
        else:
            logger.error(f"❌ RustScan failed")
        
        return result

    @mcp.tool()
    def masscan_high_speed(target: str, ports: str = "1-65535", rate: int = 1000, 
                          banners: bool = False, exclude_file: str = "", 
                          include_file: str = "", output_format: str = "list", 
                          additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Masscan for high-speed port scanning.
        
        Args:
            target: Target IP address or CIDR range
            ports: Port range to scan
            rate: Packet transmission rate
            banners: Enable banner grabbing
            exclude_file: File containing IPs to exclude
            include_file: File containing IPs to include
            output_format: Output format (list, xml, json)
            additional_args: Additional Masscan arguments
            
        Returns:
            High-speed scan results
        """
        data = {
            "target": target,
            "ports": ports,
            "rate": rate,
            "banners": banners,
            "exclude_file": exclude_file,
            "include_file": include_file,
            "output_format": output_format,
            "additional_args": additional_args
        }
        
        logger.info(f"🚀 Starting Masscan high-speed scan on {target}")
        result = api_client.safe_post("api/masscan", data)
        
        if result.get('success'):
            logger.info(f"✅ Masscan completed on {target}")
        else:
            logger.error(f"❌ Masscan failed")
        
        return result

    # ============================================================================
    # SUBDOMAIN ENUMERATION
    # ============================================================================
    
    @mcp.tool()
    def amass_scan(domain: str, mode: str = "enum", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Amass for subdomain enumeration with enhanced logging.
        
        Args:
            domain: Target domain for enumeration
            mode: Amass mode (enum, intel, viz)
            additional_args: Additional Amass arguments
            
        Returns:
            Subdomain enumeration results
        """
        data = {
            "domain": domain,
            "mode": mode,
            "additional_args": additional_args
        }
        
        logger.info(f"🔍 Starting Amass subdomain enumeration for {domain}")
        result = api_client.safe_post("api/amass", data)
        
        if result.get('success'):
            logger.info(f"✅ Amass enumeration completed for {domain}")
        else:
            logger.error(f"❌ Amass enumeration failed")
        
        return result

    @mcp.tool()
    def subfinder_scan(domain: str, silent: bool = True, all_sources: bool = False, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Subfinder for passive subdomain enumeration with enhanced logging.
        
        Args:
            domain: Target domain
            silent: Run in silent mode
            all_sources: Use all sources
            additional_args: Additional Subfinder arguments
            
        Returns:
            Passive subdomain enumeration results
        """
        data = {
            "domain": domain,
            "silent": silent,
            "all_sources": all_sources,
            "additional_args": additional_args
        }
        
        logger.info(f"🔍 Starting Subfinder passive enumeration for {domain}")
        result = api_client.safe_post("api/subfinder", data)
        
        if result.get('success'):
            logger.info(f"✅ Subfinder enumeration completed for {domain}")
        else:
            logger.error(f"❌ Subfinder enumeration failed")
        
        return result

    # ============================================================================
    # HTTP PROBING
    # ============================================================================

    @mcp.tool()
    def httpx_probe(targets: str = "", target_file: str = "", ports: str = "", methods: str = "GET", 
                   status_code: str = "", content_length: bool = False, output_file: str = "", 
                   additional_args: str = "") -> Dict[str, Any]:
        """
        Execute HTTPx for HTTP probing with enhanced logging.
        
        Args:
            targets: Target URLs or IPs
            target_file: File containing targets
            ports: Ports to probe
            methods: HTTP methods to use
            status_code: Filter by status code
            content_length: Show content length
            output_file: Output file path
            additional_args: Additional HTTPx arguments
            
        Returns:
            HTTP probing results
        """
        data = {
            "targets": targets,
            "target_file": target_file,
            "ports": ports,
            "methods": methods,
            "status_code": status_code,
            "content_length": content_length,
            "output_file": output_file,
            "additional_args": additional_args
        }
        
        logger.info(f"🌐 Starting HTTPx probing")
        result = api_client.safe_post("api/httpx", data)
        
        if result.get('success'):
            logger.info(f"✅ HTTPx probing completed")
        else:
            logger.error(f"❌ HTTPx probing failed")
        
        return result

    # ============================================================================
    # VULNERABILITY SCANNING
    # ============================================================================

    @mcp.tool()
    def nuclei_scan(
        target: str, 
        severity: str = "", 
        tags: str = "", 
        exclude_tags: str = "", 
        template: str = "", 
        template_id: str = "", 
        exclude_id: str = "", 
        author: str = "", 
        protocol_type: str = "", 
        output_format: str = "jsonl", 
        include_requests: bool = True, 
        include_responses: bool = False, 
        include_metadata: bool = True, 
        timestamp_enabled: bool = True, 
        concurrency: int = 25, 
        rate_limit: str = "", 
        timeout: str = "", 
        retries: str = "", 
        bulk_size: str = "", 
        follow_redirects: bool = True, 
        max_redirects: str = "", 
        custom_headers: str = "", 
        proxy: str = "", 
        user_agent: str = "", 
        scan_strategy: str = "", 
        resolver: str = "", 
        system_resolvers: bool = False, 
        methods: str = "", 
        body: str = "", 
        new_templates: bool = False, 
        automatic_scan: bool = False, 
        silent: bool = False, 
        verbose: bool = False, 
        debug: bool = False, 
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Nuclei vulnerability scanner with enhanced logging and comprehensive parameter support.
        """
        data = {
            "target": target,
            "severity": severity,
            "tags": tags,
            "exclude_tags": exclude_tags,
            "template": template,
            "template_id": template_id,
            "exclude_id": exclude_id,
            "author": author,
            "protocol_type": protocol_type,
            "output_format": output_format,
            "include_requests": include_requests,
            "include_responses": include_responses,
            "include_metadata": include_metadata,
            "timestamp_enabled": timestamp_enabled,
            "concurrency": concurrency,
            "rate_limit": rate_limit,
            "timeout": timeout,
            "retries": retries,
            "bulk_size": bulk_size,
            "follow_redirects": follow_redirects,
            "max_redirects": max_redirects,
            "custom_headers": custom_headers,
            "proxy": proxy,
            "user_agent": user_agent,
            "scan_strategy": scan_strategy,
            "resolver": resolver,
            "system_resolvers": system_resolvers,
            "methods": methods,
            "body": body,
            "new_templates": new_templates,
            "automatic_scan": automatic_scan,
            "silent": silent,
            "verbose": verbose,
            "debug": debug,
            "additional_args": additional_args
        }
        
        logger.info(f"🎯 Starting Nuclei vulnerability scan on {target}")
        result = api_client.safe_post("api/nuclei", data)
        
        if result.get('success'):
            logger.info(f"✅ Nuclei scan completed on {target}")
        else:
            logger.error(f"❌ Nuclei scan failed")
        
        return result

    @mcp.tool()
    def gobuster_scan(url: str, mode: str = "dir", wordlist: str = "/usr/share/wordlists/dirb/common.txt", 
                     extensions: str = "", threads: int = 10, timeout: str = "10s", 
                     user_agent: str = "", cookies: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Gobuster to find directories, DNS subdomains, or virtual hosts with enhanced logging.
        
        Args:
            url: Target URL or domain
            mode: Scan mode (dir, dns, vhost, fuzz)
            wordlist: Wordlist file path
            extensions: File extensions to search for
            threads: Number of threads
            timeout: Request timeout
            user_agent: Custom User-Agent
            cookies: Cookies to include
            additional_args: Additional Gobuster arguments
            
        Returns:
            Directory and subdomain discovery results
        """
        data = {
            "url": url,
            "mode": mode,
            "wordlist": wordlist,
            "extensions": extensions,
            "threads": threads,
            "timeout": timeout,
            "user_agent": user_agent,
            "cookies": cookies,
            "additional_args": additional_args
        }
        
        logger.info(f"🔍 Starting Gobuster {mode} scan on {url}")
        result = api_client.safe_post("api/gobuster", data)
        
        if result.get('success'):
            logger.info(f"✅ Gobuster scan completed on {url}")
        else:
            logger.error(f"❌ Gobuster scan failed")
        
        return result

    @mcp.tool()
    def dirb_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", 
                 extensions: str = "", recursive: bool = False, ignore_case: bool = False, 
                 interactive: bool = False, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute DIRB directory scanner with enhanced logging.
        
        Args:
            url: Target URL
            wordlist: Wordlist file path
            extensions: File extensions to test
            recursive: Enable recursive scanning
            ignore_case: Ignore case sensitivity
            interactive: Interactive mode
            additional_args: Additional DIRB arguments
            
        Returns:
            Directory scanning results
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "extensions": extensions,
            "recursive": recursive,
            "ignore_case": ignore_case,
            "interactive": interactive,
            "additional_args": additional_args
        }
        
        logger.info(f"📁 Starting DIRB directory scan on {url}")
        result = api_client.safe_post("api/dirb", data)
        
        if result.get('success'):
            logger.info(f"✅ DIRB scan completed on {url}")
        else:
            logger.error(f"❌ DIRB scan failed")
        
        return result

    @mcp.tool()
    def feroxbuster_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", 
                        threads: int = 10, depth: int = 4, extensions: str = "", 
                        filter_codes: str = "404", timeout: int = 7, 
                        additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Feroxbuster for fast recursive directory scanning.
        
        Args:
            url: Target URL
            wordlist: Wordlist file path
            threads: Number of concurrent threads
            depth: Maximum recursion depth
            extensions: File extensions to search for
            filter_codes: HTTP status codes to filter out
            timeout: Request timeout in seconds
            additional_args: Additional Feroxbuster arguments
            
        Returns:
            Recursive directory discovery results
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "threads": threads,
            "depth": depth,
            "extensions": extensions,
            "filter_codes": filter_codes,
            "timeout": timeout,
            "additional_args": additional_args
        }
        
        logger.info(f"🔥 Starting Feroxbuster recursive scan on {url}")
        result = api_client.safe_post("api/feroxbuster", data)
        
        if result.get('success'):
            logger.info(f"✅ Feroxbuster scan completed on {url}")
        else:
            logger.error(f"❌ Feroxbuster scan failed")
        
        return result

    @mcp.tool()
    def wfuzz_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", 
                  fuzz_parameter: str = "FUZZ", hide_codes: str = "404", 
                  threads: int = 10, follow_redirects: bool = False, 
                  additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Wfuzz for web application fuzzing.
        
        Args:
            url: Target URL with FUZZ keyword
            wordlist: Wordlist file path
            fuzz_parameter: Parameter to fuzz (default: FUZZ)
            hide_codes: HTTP status codes to hide
            threads: Number of concurrent threads
            follow_redirects: Follow HTTP redirects
            additional_args: Additional Wfuzz arguments
            
        Returns:
            Web application fuzzing results
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "fuzz_parameter": fuzz_parameter,
            "hide_codes": hide_codes,
            "threads": threads,
            "follow_redirects": follow_redirects,
            "additional_args": additional_args
        }
        
        logger.info(f"🎯 Starting Wfuzz scan on {url}")
        result = api_client.safe_post("api/wfuzz", data)
        
        if result.get('success'):
            logger.info(f"✅ Wfuzz scan completed on {url}")
        else:
            logger.error(f"❌ Wfuzz scan failed")
        
        return result

    # ============================================================================
    # DIRECTORY AND CONTENT DISCOVERY
    # ============================================================================

    @mcp.tool()
    def dirsearch_scan(url: str, extensions: str = "php,html,js,txt,xml,json", 
                      wordlist: str = "/usr/share/wordlists/dirb/common.txt", 
                      threads: int = 30, recursive: bool = False, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Dirsearch for advanced directory and file discovery with enhanced logging.
        """
        data = {
            "url": url,
            "extensions": extensions,
            "wordlist": wordlist,
            "threads": threads,
            "recursive": recursive,
            "additional_args": additional_args
        }
        
        logger.info(f"📁 Starting Dirsearch directory discovery on {url}")
        result = api_client.safe_post("api/dirsearch", data)
        
        if result.get('success'):
            logger.info(f"✅ Dirsearch scan completed on {url}")
        else:
            logger.error(f"❌ Dirsearch scan failed")
        
        return result

    @mcp.tool()
    def katana_crawl(url: str, depth: int = 3, js_crawl: bool = True, 
                    form_extraction: bool = True, output_format: str = "json", 
                    additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Katana for next-generation crawling and spidering with enhanced logging.
        """
        data = {
            "url": url,
            "depth": depth,
            "js_crawl": js_crawl,
            "form_extraction": form_extraction,
            "output_format": output_format,
            "additional_args": additional_args
        }
        
        logger.info(f"🕷️ Starting Katana crawling on {url}")
        result = api_client.safe_post("api/katana", data)
        
        if result.get('success'):
            logger.info(f"✅ Katana crawling completed on {url}")
        else:
            logger.error(f"❌ Katana crawling failed")
        
        return result

    @mcp.tool()
    def gau_discovery(domain: str, providers: str = "wayback,commoncrawl,otx,urlscan", 
                     include_subs: bool = True, blacklist: str = "png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico", 
                     additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Gau (Get All URLs) for URL discovery from multiple sources with enhanced logging.
        """
        data = {
            "domain": domain,
            "providers": providers,
            "include_subs": include_subs,
            "blacklist": blacklist,
            "additional_args": additional_args
        }
        
        logger.info(f"🔍 Starting Gau URL discovery for {domain}")
        result = api_client.safe_post("api/gau", data)
        
        if result.get('success'):
            logger.info(f"✅ Gau URL discovery completed for {domain}")
        else:
            logger.error(f"❌ Gau URL discovery failed")
        
        return result

    @mcp.tool()
    def waybackurls_discovery(domain: str, get_versions: bool = False, 
                             no_subs: bool = False, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Waybackurls for historical URL discovery with enhanced logging.
        """
        data = {
            "domain": domain,
            "get_versions": get_versions,
            "no_subs": no_subs,
            "additional_args": additional_args
        }
        
        logger.info(f"🕰️ Starting Waybackurls discovery for {domain}")
        result = api_client.safe_post("api/waybackurls", data)
        
        if result.get('success'):
            logger.info(f"✅ Waybackurls discovery completed for {domain}")
        else:
            logger.error(f"❌ Waybackurls discovery failed")
        
        return result

    # ============================================================================
    # PARAMETER DISCOVERY
    # ============================================================================

    @mcp.tool()
    def arjun_parameter_discovery(url: str, method: str = "GET", wordlist: str = "", 
                                 delay: int = 0, threads: int = 25, stable: bool = False, 
                                 additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Arjun for HTTP parameter discovery with enhanced logging.
        """
        data = {
            "url": url,
            "method": method,
            "wordlist": wordlist,
            "delay": delay,
            "threads": threads,
            "stable": stable,
            "additional_args": additional_args
        }
        
        logger.info(f"🔍 Starting Arjun parameter discovery on {url}")
        result = api_client.safe_post("api/arjun-parameter-discovery", data)
        
        if result.get('success'):
            logger.info(f"✅ Arjun parameter discovery completed on {url}")
        else:
            logger.error(f"❌ Arjun parameter discovery failed")
        
        return result

    @mcp.tool()
    def paramspider_mining(domain: str, level: int = 2, 
                          exclude: str = "png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico", 
                          output: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute ParamSpider for parameter mining from web archives with enhanced logging.
        """
        data = {
            "domain": domain,
            "level": level,
            "exclude": exclude,
            "output": output,
            "additional_args": additional_args
        }
        
        logger.info(f"🕸️ Starting ParamSpider parameter mining for {domain}")
        result = api_client.safe_post("api/paramspider-mining", data)
        
        if result.get('success'):
            logger.info(f"✅ ParamSpider mining completed for {domain}")
        else:
            logger.error(f"❌ ParamSpider mining failed")
        
        return result

    @mcp.tool()
    def x8_parameter_discovery(url: str, wordlist: str = "/usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt", 
                              method: str = "GET", body: str = "", headers: str = "", 
                              additional_args: str = "") -> Dict[str, Any]:
        """
        Execute x8 for hidden parameter discovery with enhanced logging.
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "method": method,
            "body": body,
            "headers": headers,
            "additional_args": additional_args
        }
        
        logger.info(f"🔍 Starting x8 parameter discovery on {url}")
        result = api_client.safe_post("api/x8-parameter-discovery", data)
        
        if result.get('success'):
            logger.info(f"✅ x8 parameter discovery completed on {url}")
        else:
            logger.error(f"❌ x8 parameter discovery failed")
        
        return result

    # ============================================================================
    # WEB APPLICATION TESTING
    # ============================================================================

    @mcp.tool()
    def sqlmap_scan(url: str, data: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute SQLMap for SQL injection testing with enhanced logging.
        """
        data_payload = {
            "url": url,
            "data": data,
            "additional_args": additional_args
        }
        
        logger.info(f"💉 Starting SQLMap SQL injection testing on {url}")
        result = api_client.safe_post("api/sqlmap", data_payload)
        
        if result.get('success'):
            logger.info(f"✅ SQLMap scan completed on {url}")
        else:
            logger.error(f"❌ SQLMap scan failed")
        
        return result

    @mcp.tool()
    def dalfox_xss_scan(url: str, pipe_mode: bool = False, blind: bool = False, 
                       mining_dom: bool = True, mining_dict: bool = True, 
                       custom_payload: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Dalfox for advanced XSS vulnerability scanning with enhanced logging.
        """
        data = {
            "url": url,
            "pipe_mode": pipe_mode,
            "blind": blind,
            "mining_dom": mining_dom,
            "mining_dict": mining_dict,
            "custom_payload": custom_payload,
            "additional_args": additional_args
        }
        
        logger.info(f"⚡ Starting Dalfox XSS scanning on {url}")
        result = api_client.safe_post("api/dalfox-xss-scan", data)
        
        if result.get('success'):
            logger.info(f"✅ Dalfox XSS scan completed on {url}")
        else:
            logger.error(f"❌ Dalfox XSS scan failed")
        
        return result

    @mcp.tool()
    def ffuf_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", 
                 mode: str = "directory", match_codes: str = "200,204,301,302,307,401,403", 
                 additional_args: str = "") -> Dict[str, Any]:
        """
        Execute FFuf for web fuzzing with enhanced logging.
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "mode": mode,
            "match_codes": match_codes,
            "additional_args": additional_args
        }
        
        logger.info(f"🔥 Starting FFuf web fuzzing on {url}")
        result = api_client.safe_post("api/ffuf", data)
        
        if result.get('success'):
            logger.info(f"✅ FFuf fuzzing completed on {url}")
        else:
            logger.error(f"❌ FFuf fuzzing failed")
        
        return result

    @mcp.tool()
    def nikto_scan(target: str, port: str = "80", ssl: bool = False, 
                  plugins: str = "", output_format: str = "txt", 
                  evasion: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Nikto web server vulnerability scanner.
        
        Args:
            target: Target hostname or IP address
            port: Port number to scan
            ssl: Use SSL/HTTPS
            plugins: Nikto plugins to run
            output_format: Output format (txt, xml, csv)
            evasion: Evasion techniques to use
            additional_args: Additional Nikto arguments
            
        Returns:
            Web server vulnerability scan results
        """
        data = {
            "target": target,
            "port": port,
            "ssl": ssl,
            "plugins": plugins,
            "output_format": output_format,
            "evasion": evasion,
            "additional_args": additional_args
        }
        
        logger.info(f"🔍 Starting Nikto vulnerability scan on {target}")
        result = api_client.safe_post("api/nikto", data)
        
        if result.get('success'):
            logger.info(f"✅ Nikto scan completed on {target}")
        else:
            logger.error(f"❌ Nikto scan failed")
        
        return result

    @mcp.tool()
    def wafw00f_scan(target: str, findall: bool = False, proxy: str = "", 
                    headers: str = "", output_file: str = "", 
                    additional_args: str = "") -> Dict[str, Any]:
        """
        Execute wafw00f to identify Web Application Firewall (WAF) protection.
        
        Args:
            target: Target URL
            findall: Find all possible WAFs
            proxy: Proxy server to use
            headers: Custom HTTP headers
            output_file: Output file path
            additional_args: Additional wafw00f arguments
            
        Returns:
            WAF detection results
        """
        data = {
            "target": target,
            "findall": findall,
            "proxy": proxy,
            "headers": headers,
            "output_file": output_file,
            "additional_args": additional_args
        }
        
        logger.info(f"🛡️ Starting wafw00f WAF detection on {target}")
        result = api_client.safe_post("api/wafw00f", data)
        
        if result.get('success'):
            logger.info(f"✅ wafw00f scan completed on {target}")
        else:
            logger.error(f"❌ wafw00f scan failed")
        
        return result

    @mcp.tool()
    def wpscan_analyze(url: str, enumerate: str = "ap,at,cb,dbe", 
                      update: bool = True, random_user_agent: bool = True, 
                      api_token: str = "", threads: int = 5, 
                      additional_args: str = "") -> Dict[str, Any]:
        """
        Execute WPScan for WordPress vulnerability analysis.
        
        Args:
            url: WordPress site URL
            enumerate: Enumeration options (ap=all plugins, at=all themes, etc.)
            update: Update WPScan database
            random_user_agent: Use random User-Agent
            api_token: WPVulnDB API token
            threads: Number of threads
            additional_args: Additional WPScan arguments
            
        Returns:
            WordPress vulnerability analysis results
        """
        data = {
            "url": url,
            "enumerate": enumerate,
            "update": update,
            "random_user_agent": random_user_agent,
            "api_token": api_token,
            "threads": threads,
            "additional_args": additional_args
        }
        
        logger.info(f"🔍 Starting WPScan analysis on {url}")
        result = api_client.safe_post("api/wpscan", data)
        
        if result.get('success'):
            logger.info(f"✅ WPScan analysis completed on {url}")
        else:
            logger.error(f"❌ WPScan analysis failed")
        
        return result

    # ============================================================================
    # DNS AND SUBDOMAIN DISCOVERY
    # ============================================================================

    @mcp.tool()
    def fierce_scan(domain: str, dns_server: str = "", wordlist: str = "", 
                   threads: int = 20, delay: int = 0, wide: bool = False, 
                   additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Fierce for DNS reconnaissance and subdomain discovery.
        
        Args:
            domain: Target domain
            dns_server: DNS server to use
            wordlist: Custom wordlist for subdomain brute force
            threads: Number of threads
            delay: Delay between requests
            wide: Wide scan (more comprehensive)
            additional_args: Additional Fierce arguments
            
        Returns:
            DNS reconnaissance results
        """
        data = {
            "domain": domain,
            "dns_server": dns_server,
            "wordlist": wordlist,
            "threads": threads,
            "delay": delay,
            "wide": wide,
            "additional_args": additional_args
        }
        
        logger.info(f"🔍 Starting Fierce DNS reconnaissance on {domain}")
        result = api_client.safe_post("api/fierce", data)
        
        if result.get('success'):
            logger.info(f"✅ Fierce scan completed on {domain}")
        else:
            logger.error(f"❌ Fierce scan failed")
        
        return result

    @mcp.tool()
    def dnsenum_scan(domain: str, dns_server: str = "", wordlist: str = "", 
                    threads: int = 5, delay: int = 0, reverse: bool = False, 
                    additional_args: str = "") -> Dict[str, Any]:
        """
        Execute dnsenum for DNS enumeration and subdomain discovery.
        
        Args:
            domain: Target domain
            dns_server: DNS server to use
            wordlist: Wordlist for brute force
            threads: Number of threads
            delay: Delay between requests
            reverse: Enable reverse DNS lookup
            additional_args: Additional dnsenum arguments
            
        Returns:
            DNS enumeration results
        """
        data = {
            "domain": domain,
            "dns_server": dns_server,
            "wordlist": wordlist,
            "threads": threads,
            "delay": delay,
            "reverse": reverse,
            "additional_args": additional_args
        }
        
        logger.info(f"🔍 Starting dnsenum DNS enumeration on {domain}")
        result = api_client.safe_post("api/dnsenum", data)
        
        if result.get('success'):
            logger.info(f"✅ dnsenum scan completed on {domain}")
        else:
            logger.error(f"❌ dnsenum scan failed")
        
        return result

    # ============================================================================
    # WEB CRAWLING
    # ============================================================================

    @mcp.tool()
    def hakrawler_crawl(url: str, depth: int = 2, forms: bool = True, 
                       robots: bool = True, sitemap: bool = True, 
                       wayback: bool = False, insecure: bool = False, 
                       additional_args: str = "") -> Dict[str, Any]:
        """
        Execute hakrawler for fast web crawling and endpoint discovery.
        
        Args:
            url: Target URL to crawl
            depth: Crawling depth
            forms: Extract form endpoints
            robots: Parse robots.txt
            sitemap: Parse sitemap
            wayback: Include Wayback Machine URLs
            insecure: Skip TLS verification
            additional_args: Additional hakrawler arguments
            
        Returns:
            Web crawling and endpoint discovery results
        """
        data = {
            "url": url,
            "depth": depth,
            "forms": forms,
            "robots": robots,
            "sitemap": sitemap,
            "wayback": wayback,
            "insecure": insecure,
            "additional_args": additional_args
        }
        
        logger.info(f"🕷️ Starting hakrawler crawling on {url}")
        result = api_client.safe_post("api/hakrawler", data)
        
        if result.get('success'):
            logger.info(f"✅ hakrawler crawling completed on {url}")
        else:
            logger.error(f"❌ hakrawler crawling failed")
        
        return result

    # ============================================================================
    # ADVANCED VULNERABILITY TESTING
    # ============================================================================

    @mcp.tool()
    def jaeles_vulnerability_scan(url: str, signatures: str = "", config: str = "", 
                                 threads: int = 20, timeout: int = 20, 
                                 additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Jaeles for advanced vulnerability scanning with custom signatures.
        """
        data = {
            "url": url,
            "signatures": signatures,
            "config": config,
            "threads": threads,
            "timeout": timeout,
            "additional_args": additional_args
        }
        
        logger.info(f"🎯 Starting Jaeles vulnerability scan on {url}")
        result = api_client.safe_post("api/jaeles-vulnerability-scan", data)
        
        if result.get('success'):
            logger.info(f"✅ Jaeles scan completed on {url}")
        else:
            logger.error(f"❌ Jaeles scan failed")
        
        return result

    # ============================================================================
    # BUG BOUNTY WORKFLOWS
    # ============================================================================

    @mcp.tool()
    def bugbounty_reconnaissance_workflow(domain: str, scope: str = "", out_of_scope: str = "", 
                                        program_type: str = "web") -> Dict[str, Any]:
        """
        Create comprehensive reconnaissance workflow for bug bounty hunting.
        """
        data = {
            "domain": domain,
            "scope": scope.split(",") if scope else [],
            "out_of_scope": out_of_scope.split(",") if out_of_scope else [],
            "program_type": program_type
        }
        
        logger.info(f"🎯 Creating reconnaissance workflow for {domain}")
        result = api_client.safe_post("api/bugbounty/reconnaissance-workflow", data)
        
        if result.get('success'):
            logger.info(f"✅ Reconnaissance workflow created for {domain}")
        else:
            logger.error(f"❌ Failed to create reconnaissance workflow for {domain}")
        
        return result

    @mcp.tool()
    def bugbounty_vulnerability_hunting(domain: str, priority_vulns: str = "rce,sqli,xss,idor,ssrf", 
                                       bounty_range: str = "unknown") -> Dict[str, Any]:
        """
        Create vulnerability hunting workflow prioritized by impact and bounty potential.
        """
        data = {
            "domain": domain,
            "priority_vulns": priority_vulns.split(",") if priority_vulns else [],
            "bounty_range": bounty_range
        }
        
        logger.info(f"🎯 Creating vulnerability hunting workflow for {domain}")
        result = api_client.safe_post("api/bugbounty/vulnerability-hunting-workflow", data)
        
        if result.get('success'):
            logger.info(f"✅ Vulnerability hunting workflow created for {domain}")
        else:
            logger.error(f"❌ Failed to create vulnerability hunting workflow for {domain}")
        
        return result

    @mcp.tool()
    def bugbounty_business_logic_workflow(domain: str, program_type: str = "web") -> Dict[str, Any]:
        """
        Create business logic testing workflow for bug bounty hunting.
        
        Args:
            domain: Target domain
            program_type: Type of program (web, api, mobile, iot)
            
        Returns:
            Business logic testing workflow
        """
        data = {
            "domain": domain,
            "program_type": program_type
        }
        
        logger.info(f"🎯 Creating business logic testing workflow for {domain}")
        result = api_client.safe_post("api/bugbounty/business-logic-workflow", data)
        
        if result.get('success'):
            logger.info(f"✅ Business logic testing workflow created for {domain}")
        else:
            logger.error(f"❌ Failed to create business logic testing workflow for {domain}")
        
        return result

    @mcp.tool()
    def bugbounty_osint_workflow(domain: str) -> Dict[str, Any]:
        """
        Create OSINT gathering workflow for bug bounty hunting.
        
        Args:
            domain: Target domain
            
        Returns:
            OSINT gathering workflow
        """
        data = {
            "domain": domain
        }
        
        logger.info(f"🕵️ Creating OSINT workflow for {domain}")
        result = api_client.safe_post("api/bugbounty/osint-workflow", data)
        
        if result.get('success'):
            logger.info(f"✅ OSINT workflow created for {domain}")
        else:
            logger.error(f"❌ Failed to create OSINT workflow for {domain}")
        
        return result

    @mcp.tool()
    def bugbounty_file_upload_testing(target_url: str) -> Dict[str, Any]:
        """
        Create file upload vulnerability testing workflow.
        
        Args:
            target_url: Target URL for file upload testing
            
        Returns:
            File upload testing workflow with test files
        """
        data = {
            "target_url": target_url
        }
        
        logger.info(f"📁 Creating file upload testing workflow for {target_url}")
        result = api_client.safe_post("api/bugbounty/file-upload-testing", data)
        
        if result.get('success'):
            logger.info(f"✅ File upload testing workflow created for {target_url}")
        else:
            logger.error(f"❌ Failed to create file upload testing workflow for {target_url}")
        
        return result

    @mcp.tool()
    def bugbounty_comprehensive_assessment(domain: str, scope: str = "", priority_vulns: str = "rce,sqli,xss,idor,ssrf", 
                                         include_osint: bool = True, include_business_logic: bool = True) -> Dict[str, Any]:
        """
        Create comprehensive bug bounty assessment combining all workflows.
        
        Args:
            domain: Target domain
            scope: Comma-separated list of in-scope domains/IPs
            priority_vulns: Comma-separated list of priority vulnerability types
            include_osint: Include OSINT gathering
            include_business_logic: Include business logic testing
            
        Returns:
            Comprehensive bug bounty assessment workflow
        """
        data = {
            "domain": domain,
            "scope": scope.split(",") if scope else [],
            "priority_vulns": priority_vulns.split(",") if priority_vulns else [],
            "include_osint": include_osint,
            "include_business_logic": include_business_logic
        }
        
        logger.info(f"🎯 Creating comprehensive bug bounty assessment for {domain}")
        result = api_client.safe_post("api/bugbounty/comprehensive-assessment", data)
        
        if result.get('success'):
            logger.info(f"✅ Comprehensive assessment created for {domain}")
        else:
            logger.error(f"❌ Failed to create comprehensive assessment for {domain}")
        
        return result

    # ============================================================================
    # INTELLIGENCE FEATURES
    # ============================================================================

    @mcp.tool()
    def analyze_target(target: str) -> Dict[str, Any]:
        """
        Analyze target and create comprehensive profile using AI.
        
        Args:
            target: Target domain, IP, or URL to analyze
            
        Returns:
            Comprehensive target profile with AI analysis
        """
        data = {
            "target": target
        }
        
        logger.info(f"🧠 Analyzing target: {target}")
        result = api_client.safe_post("api/intelligence/analyze-target", data)
        
        if result.get('success'):
            logger.info(f"✅ Target analysis completed for {target}")
        else:
            logger.error(f"❌ Target analysis failed for {target}")
        
        return result

    @mcp.tool()
    def select_tools(target: str, objective: str = "comprehensive") -> Dict[str, Any]:
        """
        AI-powered tool selection based on target profile.
        
        Args:
            target: Target domain, IP, or URL
            objective: Scan objective (comprehensive, fast, stealth, targeted)
            
        Returns:
            Optimized tool selection with recommendations
        """
        data = {
            "target": target,
            "objective": objective
        }
        
        logger.info(f"🔧 Selecting optimal tools for {target} with {objective} objective")
        result = api_client.safe_post("api/intelligence/select-tools", data)
        
        if result.get('success'):
            logger.info(f"✅ Tool selection completed for {target}")
        else:
            logger.error(f"❌ Tool selection failed for {target}")
        
        return result

    @mcp.tool()
    def optimize_parameters(target: str, tool: str, context: str = "") -> Dict[str, Any]:
        """
        Optimize tool parameters using AI based on target profile.
        
        Args:
            target: Target domain, IP, or URL
            tool: Tool name to optimize parameters for
            context: Additional context or constraints
            
        Returns:
            Optimized parameters and configuration
        """
        data = {
            "target": target,
            "tool": tool,
            "context": context
        }
        
        logger.info(f"⚡ Optimizing {tool} parameters for {target}")
        result = api_client.safe_post("api/intelligence/optimize-parameters", data)
        
        if result.get('success'):
            logger.info(f"✅ Parameter optimization completed for {tool}")
        else:
            logger.error(f"❌ Parameter optimization failed for {tool}")
        
        return result

    @mcp.tool()
    def create_attack_chain(target: str, objective: str = "comprehensive") -> Dict[str, Any]:
        """
        Create intelligent attack chain based on target profile.
        
        Args:
            target: Target domain, IP, or URL
            objective: Attack objective (comprehensive, fast, stealth, targeted)
            
        Returns:
            Intelligent attack chain with sequenced tools
        """
        data = {
            "target": target,
            "objective": objective
        }
        
        logger.info(f"⚔️ Creating attack chain for {target} with {objective} objective")
        result = api_client.safe_post("api/intelligence/create-attack-chain", data)
        
        if result.get('success'):
            logger.info(f"✅ Attack chain created for {target}")
        else:
            logger.error(f"❌ Attack chain creation failed for {target}")
        
        return result

    @mcp.tool()
    def smart_scan(target: str, objective: str = "comprehensive") -> Dict[str, Any]:
        """
        Execute intelligent scan using AI-driven tool selection with parallel execution.
        
        Args:
            target: Target domain, IP, or URL
            objective: Scan objective (comprehensive, fast, stealth, targeted)
            
        Returns:
            Smart scan results with AI-optimized execution
        """
        data = {
            "target": target,
            "objective": objective
        }
        
        logger.info(f"🚀 Executing smart scan for {target} with {objective} objective")
        result = api_client.safe_post("api/intelligence/smart-scan", data)
        
        if result.get('success'):
            logger.info(f"✅ Smart scan completed for {target}")
        else:
            logger.error(f"❌ Smart scan failed for {target}")
        
        return result

    return mcp


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="Bug Bounty MCP Server")
    parser.add_argument("--server-url", default="http://localhost:8000",
                       help="Bug Bounty API server URL (default: http://localhost:8000)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def main():
    """Main entry point for the Bug Bounty MCP server"""
    args = parse_args()
    
    # Configure logging
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("🔍 Debug logging enabled")
    
    logger.info(f"🚀 Starting Bug Bounty MCP Server")
    logger.info(f"🔗 Connecting to Bug Bounty API at {args.server_url}")
    
    try:
        # Initialize Bug Bounty API client
        api_client = BugBountyAPIClient(args.server_url)
        
        # Set up MCP server with bug bounty tools
        mcp = setup_bug_bounty_mcp_server(api_client)
        
        # Start the MCP server
        logger.info(f"🎯 Bug Bounty MCP Server ready for connections")
        mcp.run()
        
    except KeyboardInterrupt:
        logger.info(f"🛑 Bug Bounty MCP Server stopped by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"💥 Error starting Bug Bounty MCP server: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()