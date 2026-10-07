"""Push HoneyTrap indicators into SentinelForge.

The API base URL and key come from the environment:

    SENTINELFORGE_API_URL   default http://127.0.0.1:8080/api/v1
    SENTINELFORGE_API_KEY   sent as the X-API-Key header
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

import requests

DEFAULT_API_URL = "http://127.0.0.1:8080/api/v1"
DEFAULT_EVENTS_FILE = "data/events/ssh.jsonl"
DEFAULT_TIMEOUT = 10.0
LOCAL_IPS = {"127.0.0.1", "::1", "0.0.0.0"}


class Tracker:
    """In-memory view of attackers seen in one run."""

    def __init__(self) -> None:
        self.processed_events: set[str] = set()
        self.ip_stats: dict[str, dict[str, Any]] = defaultdict(_empty_stats)

    def observe(self, event: dict[str, Any]) -> str | None:
        event_id = event.get("id")
        if not event_id or event_id in self.processed_events:
            return None
        self.processed_events.add(event_id)

        ip = event.get("source", {}).get("ip")
        if not ip or ip in LOCAL_IPS:
            return None

        stats = self.ip_stats[ip]
        stats["attempts"] += 1
        stats["sessions"].add(event.get("session_id", ""))
        stats["protocols"].add(event.get("protocol", "unknown"))

        timestamp = event.get("timestamp")
        if timestamp:
            if not stats["first_seen"]:
                stats["first_seen"] = timestamp
            stats["last_seen"] = timestamp

        creds = event.get("credentials") or {}
        if creds.get("username"):
            stats["usernames"].add(creds["username"])
        if creds.get("password"):
            stats["passwords"].add(creds["password"])

        command = (event.get("command") or {}).get("command")
        if command:
            stats["commands"].append(command)
        return ip


def _empty_stats() -> dict[str, Any]:
    return {
        "attempts": 0,
        "usernames": set(),
        "passwords": set(),
        "commands": [],
        "first_seen": None,
        "last_seen": None,
        "sessions": set(),
        "protocols": set(),
    }


def calculate_severity(ip_data: dict[str, Any]) -> str:
    """Score attacker behavior into a SentinelForge severity."""
    score = 0
    attempts = ip_data["attempts"]
    if attempts >= 10:
        score += 40
    elif attempts >= 5:
        score += 25
    elif attempts >= 2:
        score += 10

    if len(ip_data["usernames"]) >= 5 or len(ip_data["passwords"]) >= 5:
        score += 30
    elif len(ip_data["usernames"]) >= 2 or len(ip_data["passwords"]) >= 2:
        score += 15

    if ip_data["commands"]:
        score += 30
        dangerous = (
            "wget",
            "curl",
            "chmod",
            "rm ",
            "cat /etc",
            "uname",
            "whoami",
            "passwd",
            "shadow",
            "nc ",
            "bash -i",
            "python",
            "perl",
            "sh -c",
        )
        if any(any(token in cmd.lower() for token in dangerous) for cmd in ip_data["commands"]):
            score += 10

    if score >= 70:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 30:
        return "medium"
    if score >= 10:
        return "low"
    return "unknown"


def generate_tags(ip_data: dict[str, Any], event: dict[str, Any]) -> list[str]:
    tags = {"honeypot", event.get("protocol", "unknown")}
    if ip_data["attempts"] >= 5:
        tags.add("brute-force")
    if len(ip_data["usernames"]) >= 3:
        tags.add("credential-stuffing")
    if ip_data["commands"]:
        tags.add("shell-access")
        for cmd in ip_data["commands"]:
            lowered = cmd.lower()
            if "wget" in lowered or "curl" in lowered:
                tags.add("download-attempt")
            if "passwd" in lowered or "shadow" in lowered:
                tags.add("credential-harvest")
            if "chmod" in lowered or "rm " in lowered:
                tags.add("destructive")
            if "uname" in lowered or "whoami" in lowered:
                tags.add("recon")
    common_users = {"root", "admin", "administrator", "test", "guest", "user", "ubuntu", "pi"}
    if ip_data["usernames"] & common_users:
        tags.add("automated-scan")
    return sorted(tags)


def build_indicator(ip: str, ip_data: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
    return {
        "value": ip,
        "severity": calculate_severity(ip_data),
        "confidence": min(50 + ip_data["attempts"] * 5, 95),
        "tags": generate_tags(ip_data, event),
    }


def should_submit(event: dict[str, Any], ip_data: dict[str, Any]) -> bool:
    category = event.get("category", "")
    return (
        category in {"authentication", "command"}
        or ip_data["attempts"] >= 3
        or len(ip_data["commands"]) > 0
    )


def api_settings(timeout: float) -> tuple[str, str, float]:
    api_url = os.environ.get("SENTINELFORGE_API_URL", DEFAULT_API_URL).rstrip("/")
    api_key = os.environ.get("SENTINELFORGE_API_KEY", "")
    if not api_key:
        raise SystemExit("SENTINELFORGE_API_KEY is required")
    return api_url, api_key, timeout


def auth_headers(api_key: str) -> dict[str, str]:
    return {"X-API-Key": api_key, "Accept": "application/json"}


def check_health(api_url: str, api_key: str, timeout: float) -> bool:
    health_url = api_url.removesuffix("/api/v1") + "/health"
    try:
        response = requests.get(
            health_url,
            headers=auth_headers(api_key),
            timeout=(min(3.0, timeout), timeout),
        )
    except requests.RequestException as exc:
        print(f"[-] Cannot connect to SentinelForge at {health_url}: {exc}", file=sys.stderr)
        return False
    if response.status_code != 200:
        print(f"[!] SentinelForge health returned {response.status_code}", file=sys.stderr)
        return False
    print("[+] Connected to SentinelForge")
    return True


def submit_indicator(
    api_url: str,
    api_key: str,
    payload: dict[str, Any],
    timeout: float,
    session: requests.Session | None = None,
) -> bool:
    poster = session.post if session is not None else requests.post
    try:
        response = poster(
            f"{api_url}/indicators",
            json=payload,
            headers=auth_headers(api_key),
            timeout=(min(3.0, timeout), timeout),
        )
    except requests.RequestException as exc:
        print(f"  [-] Error submitting {payload.get('value')}: {exc}", file=sys.stderr)
        return False
    if response.status_code in {200, 201}:
        print(
            f"  [+] Submitted: {payload['value']} "
            f"({payload['severity']}, {payload['confidence']}%)"
        )
        return True
    print(
        f"  [-] Failed to submit {payload.get('value')}: {response.status_code}",
        file=sys.stderr,
    )
    return False


def process_event(
    event: dict[str, Any],
    tracker: Tracker,
    api_url: str,
    api_key: str,
    timeout: float,
) -> bool:
    ip = tracker.observe(event)
    if ip is None:
        return False
    stats = tracker.ip_stats[ip]
    if not should_submit(event, stats):
        return False
    payload = build_indicator(ip, stats, event)
    return submit_indicator(api_url, api_key, payload, timeout)


def iter_events(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def process_once(path: Path, tracker: Tracker, api_url: str, api_key: str, timeout: float) -> int:
    if not path.exists():
        print(f"[-] Events file not found: {path}", file=sys.stderr)
        return 0
    submitted = 0
    for event in iter_events(path):
        if process_event(event, tracker, api_url, api_key, timeout):
            submitted += 1
    return submitted


def watch_events(path: Path, tracker: Tracker, api_url: str, api_key: str, timeout: float) -> None:
    print(f"[*] Watching {path}")
    last_size = path.stat().st_size if path.exists() else 0
    if path.exists():
        count = process_once(path, tracker, api_url, api_key, timeout)
        print(f"[*] Processed {count} indicators from the existing file")
    try:
        while True:
            time.sleep(5)
            if not path.exists():
                continue
            current_size = path.stat().st_size
            if current_size < last_size:
                print("[!] Events file was reset")
                tracker.processed_events.clear()
                tracker.ip_stats.clear()
                last_size = 0
                continue
            if current_size == last_size:
                continue
            with path.open(encoding="utf-8") as handle:
                handle.seek(last_size)
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    process_event(event, tracker, api_url, api_key, timeout)
            last_size = current_size
    except KeyboardInterrupt:
        print("\n[*] Stopping")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Feed HoneyTrap events into SentinelForge threat intelligence"
    )
    parser.add_argument(
        "--events-file",
        "-f",
        default=DEFAULT_EVENTS_FILE,
        help=f"Path to events JSONL (default: {DEFAULT_EVENTS_FILE})",
    )
    parser.add_argument(
        "--watch",
        "-w",
        action="store_true",
        help="Keep watching the file for new events",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"HTTP timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    api_url, api_key, timeout = api_settings(args.timeout)
    print(f"[*] SentinelForge API: {api_url}")
    if not check_health(api_url, api_key, timeout):
        return 1
    tracker = Tracker()
    path = Path(args.events_file)
    if args.watch:
        watch_events(path, tracker, api_url, api_key, timeout)
        return 0
    count = process_once(path, tracker, api_url, api_key, timeout)
    print(f"[+] Submitted {count} indicators")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
