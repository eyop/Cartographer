"""Tests for the normalization layer — RawFinding[] -> graph dict."""

from app.collectors.normalize import GraphBuilder, _entity_id, normalize


class TestGraphBuilder:
    def test_entity_dedup_merges_sources(self):
        b = GraphBuilder()
        b.add_entity("ip", "1.2.3.4", 1.0, ["dns"])
        b.add_entity("ip", "1.2.3.4", 0.8, ["shodan"])
        assert len(b._entities) == 1
        ent = list(b._entities.values())[0]
        assert ent.confidence == 1.0
        assert set(ent.sources) == {"dns", "shodan"}

    def test_relationship_dedup(self):
        b = GraphBuilder()
        b.add_relationship("domain", "a.com", "ip", "1.2.3.4", "resolves_to", 0.9, ["dns"])
        b.add_relationship("domain", "a.com", "ip", "1.2.3.4", "resolves_to", 0.8, ["shodan"])
        assert len(b._relationships) == 1

    def test_build_serializes(self):
        b = GraphBuilder()
        b.add_entity("domain", "a.com", 1.0, ["dns"])
        result = b.build()
        assert "entities" in result and "relationships" in result
        assert result["entities"][0]["value"] == "a.com"

    def test_entity_id_deterministic(self):
        assert _entity_id("ip", "1.2.3.4") == _entity_id("ip", "1.2.3.4")
        assert _entity_id("ip", "1.2.3.4") != _entity_id("ip", "5.6.7.8")


class TestNormalizeDNS:
    def test_dns_finds_domain_and_ip(self, dns_finding):
        result = normalize([dns_finding])
        assert len(result["entities"]) == 2
        assert any(e["type"] == "domain" and e["value"] == "example.com" for e in result["entities"])
        assert any(e["type"] == "ip" and e["value"] == "93.184.216.34" for e in result["entities"])
        assert len(result["relationships"]) == 1
        assert result["relationships"][0]["type"] == "resolves_to"


class TestNormalizeCrtSh:
    def test_finds_wildcard_subdomains(self, crtsh_finding):
        result = normalize([crtsh_finding])
        domains = [e["value"] for e in result["entities"] if e["type"] == "domain"]
        assert "example.com" in domains
        # org entity from issuer
        orgs = [e for e in result["entities"] if e["type"] == "org"]
        assert len(orgs) >= 1


class TestNormalizeGitHub:
    def test_finds_repo_and_org(self, github_finding):
        result = normalize([github_finding])
        assert any(e["type"] == "repo" and e["value"] == "octocat/my-repo" for e in result["entities"])
        assert any(e["type"] == "org" and e["value"] == "octocat" for e in result["entities"])
        assert any(r["type"] == "mentions" for r in result["relationships"])


class TestNormalizeShodan:
    def test_finds_ip_hostnames_org(self, shodan_finding):
        result = normalize([shodan_finding])
        assert any(e["type"] == "ip" and e["value"] == "93.184.216.34" for e in result["entities"])
        assert any(e["type"] == "org" and e["value"] == "Example Corp" for e in result["entities"])
        assert len(result["relationships"]) >= 2


class TestNormalizeVirusTotal:
    def test_finds_subdomains_and_resolutions(self, virustotal_finding):
        result = normalize([virustotal_finding])
        subdomains = [e["value"] for e in result["entities"] if e["type"] == "domain" and e["confidence"] < 1.0]
        assert "www.example.com" in subdomains
        assert "api.example.com" in subdomains
        assert any(e["value"] == "93.184.216.34" and e["type"] == "ip" for e in result["entities"])


class TestNormalizeHIBP:
    def test_finds_email_and_breach(self, hibp_finding):
        result = normalize([hibp_finding])
        assert any(e["type"] == "email" and e["value"] == "user@example.com" for e in result["entities"])
        assert any(e["type"] == "domain" and e["value"] == "example.com" for e in result["entities"])
        assert any(r["type"] == "leaked_in" for r in result["relationships"])


class TestMultiSourceDedup:
    def test_same_ip_deduped_across_sources(self, dns_finding, virustotal_finding):
        result = normalize([dns_finding, virustotal_finding])
        ips = [e for e in result["entities"]
               if e["type"] == "ip" and e["value"] == "93.184.216.34"]
        assert len(ips) == 1
        assert set(ips[0]["sources"]) == {"dns", "virustotal"}


class TestNormalizeEmpty:
    def test_empty_findings(self):
        result = normalize([])
        assert result["entities"] == []
        assert result["relationships"] == []

    def test_unknown_source_skipped(self):
        from app.models.entity import RawFinding
        f = RawFinding(source="unknown", query="test", payload={})
        result = normalize([f])
        assert result["entities"] == []
