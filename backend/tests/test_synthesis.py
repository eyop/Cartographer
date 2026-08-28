"""Tests for the synthesis chain, including fallback (no API key) mode."""

import pytest
from app.models.entity import RawFinding
from app.synthesis.chain import ThreatSynthesisChain, synthesize_threat_profile


@pytest.fixture
def sample_graph():
    return {
        "entities": [
            {"id": "ent:ip:abc", "type": "ip", "value": "1.2.3.4",
             "confidence": 1.0, "sources": ["dns"]},
            {"id": "ent:domain:def", "type": "domain", "value": "example.com",
             "confidence": 1.0, "sources": ["dns", "crtsh"]},
        ],
        "relationships": [
            {"source_entity_id": "ent:domain:def",
             "target_entity_id": "ent:ip:abc",
             "type": "resolves_to", "confidence": 0.95},
        ],
    }


@pytest.fixture
def sample_findings():
    return [
        RawFinding(source="dns", query="example.com", payload={}),
        RawFinding(source="crtsh", query="example.com", payload={}),
    ]


class TestFallbackSynthesis:
    async def test_no_api_key_falls_back(self):
        chain = ThreatSynthesisChain()
        # In test env without OPENAI_API_KEY, client should be None
        assert chain._client is None

    async def test_fallback_produces_valid_profile(self, sample_graph, sample_findings):
        chain = ThreatSynthesisChain()
        profile = await chain.synthesize("example.com", sample_graph, sample_findings)

        assert profile.target == "example.com"
        assert profile.model_version == "fallback-v1"
        assert len(profile.entities) == 2
        assert len(profile.relationships) == 1
        assert len(profile.risk_indicators) >= 1
        assert len(profile.summary) > 0

    async def test_fallback_risk_indicators(self, sample_graph, sample_findings):
        chain = ThreatSynthesisChain()
        profile = await chain.synthesize("example.com", sample_graph, sample_findings)
        # resolves_to relationship should produce a risk indicator
        assert any("resolves" in ri.lower() for ri in profile.risk_indicators)


class TestFallbackSummary:
    def test_summary_contains_target(self):
        graph = {
            "entities": [{"id": "x", "type": "domain", "value": "evil.com",
                          "confidence": 1.0, "sources": ["crtsh"]}],
            "relationships": [],
        }
        summary = ThreatSynthesisChain._fallback_summary("evil.com", graph, [])
        assert "evil.com" in summary

    def test_empty_graph_summary(self):
        graph = {"entities": [], "relationships": []}
        summary = ThreatSynthesisChain._fallback_summary("test.com", graph, [])
        assert "test.com" in summary


class TestModuleEntryPoint:
    async def test_synthesize_threat_profile_function(self, sample_graph, sample_findings):
        profile = await synthesize_threat_profile(
            "example.com", sample_graph, sample_findings
        )
        assert profile.target == "example.com"
