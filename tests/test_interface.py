"""Tests for Sprint 5 — Advisory CLI outputs, /feed endpoint, and live dashboard."""

import json
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner
from fastapi.testclient import TestClient

from swarmsec.cli.dashboard import generate_dashboard_renderable, render_dashboard_once
from swarmsec.cli.main import ADVISORY_DISCLAIMER, cli
from swarmsec.node.app import app as node_app
from swarmsec.node.models import SignableEnvelopeFields, StixIndicator, StixOpinion, SwarmSecMessage, TLPMarking


@pytest.fixture
def client():
    return TestClient(node_app)


@pytest.fixture
def runner():
    return CliRunner()


def make_test_indicator(pattern: str, cred_id: str, message_id: str, timestamp: str = "2026-10-02T12:00:00Z"):
    payload = StixIndicator(
        pattern=pattern,
        object_marking_refs=[TLPMarking.GREEN],
    )
    envelope = SignableEnvelopeFields(
        message_id=message_id,
        credential_id=cred_id,
        sequence_number=1,
        timestamp=timestamp,
        payload_hash="",
    )
    return SwarmSecMessage(envelope=envelope, payload=payload, signature="dummy-sig")


def test_node_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_feed_empty(client):
    resp = client.get("/feed")
    assert resp.status_code == 200
    data = resp.json()
    assert "ranked_indicators" in data
    assert "advisory_disclaimer" in data
    assert "ADVISORY ONLY" in data["advisory_disclaimer"]


def test_feed_and_query_with_indicators(client):
    from swarmsec.node.app import _INDICATORS, _MESSAGES

    # Reset state
    _INDICATORS.clear()
    _MESSAGES.clear()

    # Org A reports SHA-256 hash (high entropy = 1.0)
    msg1 = make_test_indicator(
        pattern="[file:hashes.'SHA-256' = 'aaaabbbbccccdddd']",
        cred_id="cred-org-a",
        message_id="msg-1",
        timestamp="2026-10-02T12:00:00Z",
    )
    # Org B reports same hash (corroboration!)
    msg2 = make_test_indicator(
        pattern="[file:hashes.'SHA-256' = 'aaaabbbbccccdddd']",
        cred_id="cred-org-b",
        message_id="msg-2",
        timestamp="2026-10-02T12:01:00Z",
    )

    # Org C reports low entropy IP alone (score 0.0)
    msg3 = make_test_indicator(
        pattern="[ipv4-addr:value = '198.51.100.1']",
        cred_id="cred-org-c",
        message_id="msg-3",
        timestamp="2026-10-02T12:02:00Z",
    )

    for msg in (msg1, msg2, msg3):
        _MESSAGES[msg.envelope.message_id] = msg
        pat = msg.payload.pattern
        if pat not in _INDICATORS:
            _INDICATORS[pat] = []
        _INDICATORS[pat].append(msg.envelope.message_id)

    # Query feed
    resp = client.get("/feed")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_indicators"] == 2
    assert len(data["ranked_indicators"]) == 2

    # High rank should be the corroborated hash (score 1.0)
    top_item = data["ranked_indicators"][0]
    assert top_item["pattern"] == "[file:hashes.'SHA-256' = 'aaaabbbbccccdddd']"
    assert top_item["local_corroboration_score"] == 1.0
    assert top_item["status"] == "CONFIRMED"
    assert top_item["independent_sources"] == 2

    # Second item should be single-source IP (score 0.0)
    second_item = data["ranked_indicators"][1]
    assert second_item["pattern"] == "[ipv4-addr:value = '198.51.100.1']"
    assert second_item["local_corroboration_score"] == 0.0

    # Query endpoint
    query_resp = client.get("/query", params={"pattern": "[file:hashes.'SHA-256' = 'aaaabbbbccccdddd']"})
    assert query_resp.status_code == 200
    qdata = query_resp.json()
    assert qdata["local_corroboration_score"] == 1.0
    assert "ADVISORY ONLY" in qdata["advisory_disclaimer"]


def test_cli_query_and_feed_advisory_text(runner):
    # Test query command with mock
    mock_query_response = {
        "pattern": "[ipv4-addr:value = '198.51.100.22']",
        "local_corroboration_score": 0.5,
        "status": "CONFIRMED",
        "independent_sources": 2,
        "flags": [],
        "sources": ["msg-1", "msg-2"],
        "advisory_disclaimer": ADVISORY_DISCLAIMER,
    }

    mock_feed_response = {
        "ranked_indicators": [
            {
                "pattern": "[ipv4-addr:value = '198.51.100.22']",
                "local_corroboration_score": 0.5,
                "status": "CONFIRMED",
                "independent_sources": 2,
                "flags": [],
                "downweighted": False,
            }
        ],
        "total_indicators": 1,
        "total_messages": 2,
        "advisory_disclaimer": ADVISORY_DISCLAIMER,
    }

    with patch("httpx.get") as mock_get:
        # 1. Test query command
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_query_response
        mock_get.return_value = mock_resp

        result = runner.invoke(cli, ["query", "--node", "http://localhost:8001", "--pattern", "[ipv4-addr:value = '198.51.100.22']"])
        assert result.exit_code == 0
        assert "SwarmSec Local Corroboration & Trust Ranking Report" in result.output
        assert "0.50" in result.output
        assert "CLEAN (independent observations)" in result.output
        assert "ADVISORY ONLY:" in result.output
        assert "NOT an automated block/allow decision" in result.output

        # 2. Test feed command
        mock_resp.json.return_value = mock_feed_response
        feed_result = runner.invoke(cli, ["feed", "--node", "http://localhost:8001"])
        assert feed_result.exit_code == 0
        assert "Rank" in feed_result.output
        assert "Score" in feed_result.output
        assert "0.50" in feed_result.output
        assert "ADVISORY ONLY:" in feed_result.output
        assert "NOT an automated block/allow decision" in feed_result.output


def test_cli_query_correlated_evidence_downweighted_flag(runner):
    # When correlated-evidence down-weighting triggers
    mock_collusion_response = {
        "pattern": "[ipv4-addr:value = '203.0.113.99']",
        "local_corroboration_score": 0.12,
        "status": "CONFIRMED",
        "independent_sources": 3,
        "flags": ["feedback_downweighted"],
        "sources": ["msg-attack-1"],
        "advisory_disclaimer": ADVISORY_DISCLAIMER,
    }

    with patch("httpx.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_collusion_response
        mock_get.return_value = mock_resp

        result = runner.invoke(cli, ["query", "--node", "http://localhost:8001", "--pattern", "[ipv4-addr:value = '203.0.113.99']"])
        assert result.exit_code == 0
        assert "TRIGGERED (correlated-evidence down-weighting)" in result.output
        assert "Dense cluster or mutual endorsement detected by formula" in result.output
        assert "ADVISORY ONLY:" in result.output


def test_dashboard_renderable():
    # Test generation of rich renderable for dashboard
    feed_data = {
        "ranked_indicators": [
            {
                "pattern": "[file:hashes.'SHA-256' = '1111222233334444']",
                "local_corroboration_score": 1.0,
                "status": "CONFIRMED",
                "independent_sources": 2,
                "flags": [],
                "downweighted": False,
            },
            {
                "pattern": "[ipv4-addr:value = '198.51.100.99']",
                "local_corroboration_score": 0.15,
                "status": "CONFIRMED",
                "independent_sources": 4,
                "flags": ["feedback_downweighted"],
                "downweighted": True,
                "reports_count": 1,
                "feedback_count": 3,
            },
        ],
        "total_indicators": 2,
        "total_messages": 5,
    }

    renderable = generate_dashboard_renderable("http://localhost:8001", feed_data)
    assert renderable is not None

    with patch("swarmsec.cli.dashboard.fetch_node_feed", return_value=feed_data):
        # Test render_dashboard_once runs cleanly
        render_dashboard_once("http://localhost:8001")
