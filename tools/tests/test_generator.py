from honeytrap_test_generator import DOCUMENTATION_IPS, generate_test_data


def test_generated_events_use_documentation_addresses(tmp_path):
    output = tmp_path / "events.jsonl"
    events = generate_test_data(output, num_sessions=6, mode="compromise", clear=True)
    assert events
    prefixes = ("203.0.113.", "198.51.100.", "192.0.2.")
    for event in events:
        ip = event["source"]["ip"]
        assert ip.startswith(prefixes)
        assert ip in DOCUMENTATION_IPS or ip.startswith(prefixes)
        assert event["protocol"] == "ssh"
        assert event["category"] in {"connection", "authentication", "command"}
    text = output.read_text(encoding="utf-8")
    assert "uname -a" in text or "cat /etc/passwd" in text
    assert "http://" in text
