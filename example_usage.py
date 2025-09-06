#!/usr/bin/env python3
"""
Example usage of the Bug Bounty MCP Server API endpoints
"""

import requests
import json
from pprint import pprint

# Server configuration
BASE_URL = "http://127.0.0.1:8888"

def test_health():
    """Test health endpoint"""
    print("🔍 Testing health endpoint...")
    response = requests.get(f"{BASE_URL}/health")
    print(f"Status: {response.status_code}")
    pprint(response.json())
    print("-" * 60)

def test_reconnaissance_workflow():
    """Test reconnaissance workflow creation"""
    print("🔍 Testing reconnaissance workflow...")
    payload = {
        "domain": "example.com",
        "scope": ["*.example.com", "api.example.com"],
        "out_of_scope": ["internal.example.com"],
        "program_type": "web"
    }
    
    response = requests.post(f"{BASE_URL}/api/bugbounty/reconnaissance-workflow", 
                           json=payload)
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        result = response.json()
        print(f"Target: {result['workflow']['target']}")
        print(f"Phases: {len(result['workflow']['phases'])}")
        print(f"Estimated time: {result['workflow']['estimated_time']} seconds")
        print(f"Tools count: {result['workflow']['tools_count']}")
    else:
        print("Error:", response.json())
    print("-" * 60)

def test_vulnerability_hunting_workflow():
    """Test vulnerability hunting workflow creation"""
    print("🔍 Testing vulnerability hunting workflow...")
    payload = {
        "domain": "example.com",
        "priority_vulns": ["rce", "sqli", "xss", "ssrf"],
        "bounty_range": "medium"
    }
    
    response = requests.post(f"{BASE_URL}/api/bugbounty/vulnerability-hunting-workflow", 
                           json=payload)
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        result = response.json()
        workflow = result['workflow']
        print(f"Target: {workflow['target']}")
        print(f"Vulnerability tests: {len(workflow['vulnerability_tests'])}")
        print(f"Priority score: {workflow['priority_score']}")
        print(f"Estimated time: {workflow['estimated_time']} seconds")
        
        for test in workflow['vulnerability_tests']:
            print(f"  - {test['vulnerability_type']}: Priority {test['priority']}")
    else:
        print("Error:", response.json())
    print("-" * 60)

def test_comprehensive_assessment():
    """Test comprehensive assessment creation"""
    print("🔍 Testing comprehensive assessment...")
    payload = {
        "domain": "example.com",
        "scope": ["*.example.com"],
        "priority_vulns": ["rce", "sqli", "xss"],
        "include_osint": True,
        "include_business_logic": True
    }
    
    response = requests.post(f"{BASE_URL}/api/bugbounty/comprehensive-assessment", 
                           json=payload)
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        result = response.json()
        assessment = result['assessment']
        summary = assessment['summary']
        
        print(f"Target: {assessment['target']}")
        print(f"Total estimated time: {summary['total_estimated_time']} seconds")
        print(f"Total tools: {summary['total_tools']}")
        print(f"Workflows included: {summary['workflow_count']}")
        print(f"Priority score: {summary['priority_score']}")
        
        print("\nWorkflows included:")
        for key in assessment.keys():
            if key not in ['target', 'summary']:
                print(f"  - {key}")
    else:
        print("Error:", response.json())
    print("-" * 60)

def test_file_upload_testing():
    """Test file upload testing workflow"""
    print("🔍 Testing file upload testing workflow...")
    payload = {
        "target_url": "https://example.com/upload"
    }
    
    response = requests.post(f"{BASE_URL}/api/bugbounty/file-upload-testing", 
                           json=payload)
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        result = response.json()
        workflow = result['workflow']
        print(f"Target: {workflow['target']}")
        print(f"Test phases: {len(workflow['test_phases'])}")
        print(f"Risk level: {workflow['risk_level']}")
        print(f"Estimated time: {workflow['estimated_time']} seconds")
        
        print("\nTest files generated:")
        test_files = workflow['test_files']
        print(f"  - Web shells: {len(test_files['web_shells'])}")
        print(f"  - Bypass files: {len(test_files['bypass_files'])}")
        print(f"  - Polyglot files: {len(test_files['polyglot_files'])}")
    else:
        print("Error:", response.json())
    print("-" * 60)

if __name__ == "__main__":
    print("🎯 Bug Bounty MCP Server API Test Suite")
    print("=" * 60)
    
    try:
        test_health()
        test_reconnaissance_workflow()
        test_vulnerability_hunting_workflow()
        test_comprehensive_assessment()
        test_file_upload_testing()
        
        print("✅ All tests completed!")
        
    except requests.ConnectionError:
        print("❌ Error: Cannot connect to server. Make sure the server is running:")
        print("   python server.py --debug")
        print(f"   Server should be accessible at {BASE_URL}")
    except Exception as e:
        print(f"❌ Error: {e}")