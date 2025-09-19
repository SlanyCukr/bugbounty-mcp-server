#!/usr/bin/env python3
"""Test script to validate subdomain discovery tool implementations."""

import os
import sys

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from datetime import datetime

from rest_api_server.tools.amass.amass import (
    _build_amass_command,
    _extract_amass_params,
    _parse_amass_text_output,
)
from rest_api_server.tools.dnsenum.dnsenum import (
    _build_dnsenum_command,
    _extract_dnsenum_params,
    _parse_dnsenum_subdomains,
)
from rest_api_server.tools.fierce.fierce import (
    _build_fierce_command,
    _extract_fierce_params,
    _parse_fierce_subdomains,
)
from rest_api_server.tools.subfinder.subfinder import (
    _build_subfinder_command,
    _extract_subfinder_params,
    _parse_subfinder_json_output,
)


def test_subfinder():
    """Test subfinder implementation."""
    print("=== Testing subfinder ===")

    # Test params
    test_data = {"domain": "slanycukr.com", "silent": True}
    params = _extract_subfinder_params(test_data)
    command = _build_subfinder_command(params)
    print(f"Command: {command}")

    # Test JSON parsing with real data
    json_output = (
        """{"host":"freqtrade.slanycukr.com","input":"slanycukr.com","source":"crtsh"}"""
        """{"host":"bazarr.slanycukr.com","input":"slanycukr.com","source":"crtsh"}"""
        """{"host":"sonarr.slanycukr.com","input":"slanycukr.com","source":"crtsh"}"""
    )

    findings = _parse_subfinder_json_output(json_output)
    print(f"Parsed {len(findings)} findings")
    for f in findings[:2]:
        print(f"  - {f['target']} (source: {f['evidence']['source']})")

    return len(findings) > 0


def test_amass():
    """Test amass implementation."""
    print("\n=== Testing amass ===")

    # Test params
    test_data = {"domain": "slanycukr.com", "passive": True}
    params = _extract_amass_params(test_data)
    command = _build_amass_command(params)
    print(f"Command: {command}")

    # Test text parsing with sample data
    text_output = """freqtrade.slanycukr.com
bazarr.slanycukr.com
sonarr.slanycukr.com
cloud.slanycukr.com"""

    # Create mock execution result
    execution_result = {"success": True, "stdout": text_output}
    started_at = datetime.now()
    ended_at = datetime.now()

    result = _parse_amass_text_output(
        execution_result, params, command, started_at, ended_at
    )
    findings = result.get("findings", [])
    print(f"Parsed {len(findings)} findings")
    for f in findings[:2]:
        print(f"  - {f['target']}")

    return len(findings) > 0


def test_dnsenum():
    """Test dnsenum implementation."""
    print("\n=== Testing dnsenum ===")

    # Test params
    test_data = {"domain": "slanycukr.com"}
    params = _extract_dnsenum_params(test_data)
    command = _build_dnsenum_command(params)
    print(f"Command: {' '.join(command)}")

    # Test parsing with sample data (format from actual dnsenum output)
    dns_output = (
        "slanycukr.com. 300 IN A 104.21.26.26\n"
        "slanycukr.com. 300 IN A 172.67.135.53\n"
        "mail.slanycukr.com. 300 IN A 172.67.135.53\n"
        "cloud.slanycukr.com. 300 IN A 104.21.26.26\n"
        "www.slanycukr.com A record query failed: NOERROR"
    )

    findings = _parse_dnsenum_subdomains(dns_output, "slanycukr.com")
    print(f"Parsed {len(findings)} findings")
    for f in findings:
        print(f"  - {f['target']} -> {f['evidence']['ip_address']}")

    return len(findings) > 0


def test_fierce():
    """Test fierce implementation."""
    print("\n=== Testing fierce ===")

    # Test params
    test_data = {"domain": "slanycukr.com"}
    params, error = _extract_fierce_params(test_data)
    if error:
        print(f"Error: {error}")
        return False

    command = _build_fierce_command(params)
    print(f"Command: {command}")

    # Test parsing with sample data
    fierce_output = """NS: ullis.ns.cloudflare.com. remy.ns.cloudflare.com.
SOA: remy.ns.cloudflare.com. (172.64.35.115)
Zone: failure
Found: mail.slanycukr.com
Found: www.slanycukr.com
Wildcard: failure"""

    findings = _parse_fierce_subdomains(fierce_output, "slanycukr.com")
    print(f"Parsed {len(findings)} findings")
    for f in findings:
        print(f"  - {f['target']}")

    return len(findings) > 0


def main():
    """Run all tests."""
    print("Testing subdomain discovery tool implementations...\n")

    tests = [
        ("subfinder", test_subfinder),
        ("amass", test_amass),
        ("dnsenum", test_dnsenum),
        ("fierce", test_fierce),
    ]

    results = {}
    for name, test_func in tests:
        try:
            results[name] = test_func()
        except Exception as e:
            print(f"ERROR in {name}: {e}")
            results[name] = False

    print("\n=== SUMMARY ===")
    for name, passed in results.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{name}: {status}")

    total_passed = sum(results.values())
    print(f"\nPassed: {total_passed}/{len(results)} tests")

    return total_passed == len(results)


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
