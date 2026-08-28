"""Shared pytest fixtures for Cartographer tests."""

import pytest
from app.models.entity import RawFinding


@pytest.fixture
def dns_finding():
    payload = {
        "Status": 0, "TC": False, "RD": True, "RA": True, "AD": False,
        "Question": [{"name": "example.com.", "type": 1}],
        "Answer": [
            {"name": "example.com.", "type": 1, "TTL": 300, "data": "93.184.216.34"},
            {"name": "www.example.com.", "type": 1, "TTL": 300, "data": "93.184.216.34"},
        ],
    }
    return RawFinding(source="dns", query="example.com", payload=payload)


@pytest.fixture
def crtsh_finding():
    payload = {
        "certificates": [
            {
                "issuer_ca_id": 1301,
                "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
                "name_value": "example.com\n*.example.com",
                "entry_timestamp": "2024-01-01T00:00:00",
                "not_before": "2024-01-01",
                "not_after": "2024-04-01",
            }
        ]
    }
    return RawFinding(source="crtsh", query="example.com", payload=payload)


@pytest.fixture
def github_finding():
    payload = {
        "total_count": 1,
        "items": [{
            "name": "example.com",
            "repository": {
                "name": "my-repo",
                "full_name": "octocat/my-repo",
                "html_url": "https://github.com/octocat/my-repo",
                "owner": {"login": "octocat", "type": "Organization"},
            },
        }],
    }
    return RawFinding(source="github", query="example.com", payload=payload)


@pytest.fixture
def shodan_finding():
    payload = {
        "matches": [{
            "ip_str": "93.184.216.34",
            "port": 80,
            "hostnames": ["example.com"],
            "org": "Example Corp",
            "product": "nginx",
        }],
        "total": 1,
    }
    return RawFinding(source="shodan", query="example.com", payload=payload)


@pytest.fixture
def virustotal_finding():
    payload = {
        "data": {
            "id": "example.com",
            "type": "domain",
            "attributes": {
                "resolutions": [{"ip_address": "93.184.216.34"}],
                "subdomains": ["www.example.com", "api.example.com"],
                "whois": "Registrant: Example Corp",
                "reputation": 100,
                "last_analysis_stats": {"harmless": 85, "malicious": 0},
            },
        }
    }
    return RawFinding(source="virustotal", query="example.com", payload=payload)


@pytest.fixture
def hibp_finding():
    payload = {
        "breaches": [{
            "Name": "ExampleBreach2024",
            "Title": "Example Site Breach 2024",
            "Domain": "example.com",
            "BreachDate": "2024-01-01",
            "DataClasses": ["Email addresses", "Passwords"],
            "IsVerified": True,
        }]
    }
    return RawFinding(source="hibp", query="user@example.com", payload=payload)


@pytest.fixture
def sample_findings(dns_finding, crtsh_finding, github_finding, shodan_finding, virustotal_finding, hibp_finding):
    return [dns_finding, crtsh_finding, github_finding, shodan_finding, virustotal_finding, hibp_finding]
