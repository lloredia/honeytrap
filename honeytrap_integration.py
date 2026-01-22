#!/usr/bin/env python3
"""
HoneyTrap → SentinelForge Integration

Watches honeypot events and feeds attacker IPs into the threat intelligence platform.

Usage:
    python honeytrap_integration.py --events-file /path/to/events.jsonl
    python honeytrap_integration.py --watch  # Watch mode (continuous)
"""

import json
import time
import argparse
import requests
from pathlib import Path
from collections import defaultdict

# Configuration
DEFAULT_API = "http://localhost:8080/api/v1"
DEFAULT_EVENTS_FILE = "events.jsonl"
POLL_INTERVAL = 5  # seconds

# Track processed events and IP statistics
processed_events = set()
ip_stats = defaultdict(lambda: {
    "attempts": 0,
    "usernames": set(),
    "passwords": set(),
    "commands": [],
    "first_seen": None,
    "last_seen": None,
    "sessions": set(),
    "protocols": set()
})


def calculate_severity(ip_data):
    """Calculate threat severity based on attacker behavior"""
    attempts = ip_data["attempts"]
    unique_usernames = len(ip_data["usernames"])
    unique_passwords = len(ip_data["passwords"])
    commands_count = len(ip_data["commands"])
    
    score = 0
    
    if attempts >= 10:
        score += 40
    elif attempts >= 5:
        score += 25
    elif attempts >= 2:
        score += 10
    
    if unique_usernames >= 5 or unique_passwords >= 5:
        score += 30
    elif unique_usernames >= 2 or unique_passwords >= 2:
        score += 15
    
    if commands_count > 0:
        score += 30
        dangerous = ["wget", "curl", "chmod", "rm ", "cat /etc", "uname", "whoami", 
                     "passwd", "shadow", "nc ", "bash -i", "python", "perl", "sh -c"]
        for cmd in ip_data["commands"]:
            if any(d in cmd.lower() for d in dangerous):
                score += 10
                break
    
    if score >= 70:
        return "critical"
    elif score >= 50:
        return "high"
    elif score >= 30:
        return "medium"
    elif score >= 10:
        return "low"
    return "unknown"


def generate_tags(ip_data, event):
    """Generate tags based on attacker behavior"""
    tags = ["honeypot"]
    
    protocol = event.get("protocol", "unknown")
    tags.append(protocol)
    
    if ip_data["attempts"] >= 5:
        tags.append("brute-force")
    
    if len(ip_data["usernames"]) >= 3:
        tags.append("credential-stuffing")
    
    if ip_data["commands"]:
        tags.append("shell-access")
        for cmd in ip_data["commands"]:
            cmd_lower = cmd.lower()
            if "wget" in cmd_lower or "curl" in cmd_lower:
                tags.append("download-attempt")
            if "passwd" in cmd_lower or "shadow" in cmd_lower:
                tags.append("credential-harvest")
            if "chmod" in cmd_lower or "rm " in cmd_lower:
                tags.append("destructive")
            if "uname" in cmd_lower or "whoami" in cmd_lower:
                tags.append("recon")
    
    common_users = {"root", "admin", "administrator", "test", "guest", "user", "ubuntu", "pi"}
    if ip_data["usernames"] & common_users:
        tags.append("automated-scan")
    
    return list(set(tags))


def submit_to_sentinelforge(ip, ip_data, event, api_url):
    """Submit an IOC to SentinelForge"""
    severity = calculate_severity(ip_data)
    tags = generate_tags(ip_data, event)
    confidence = min(50 + ip_data["attempts"] * 5, 95)
    
    payload = {
        "value": ip,
        "severity": severity,
        "confidence": confidence,
        "tags": tags
    }
    
    try:
        response = requests.post(
            f"{api_url}/indicators",
            json=payload,
            timeout=10
        )
        
        if response.status_code in (200, 201):
            print(f"  [+] Submitted: {ip}")
            print(f"      Severity: {severity} | Confidence: {confidence}% | Tags: {', '.join(tags)}")
            return True
        else:
            print(f"  [-] Failed to submit {ip}: {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError:
        print(f"  [-] Cannot connect to SentinelForge API at {api_url}")
        return False
    except requests.exceptions.RequestException as e:
        print(f"  [-] Error submitting {ip}: {e}")
        return False


def process_event(event, api_url):
    """Process a single honeypot event"""
    event_id = event.get("id")
    if not event_id or event_id in processed_events:
        return False
    
    processed_events.add(event_id)
    
    source = event.get("source", {})
    ip = source.get("ip")
    
    if not ip or ip in ("127.0.0.1", "::1", "0.0.0.0"):
        return False
    
    stats = ip_stats[ip]
    stats["attempts"] += 1
    stats["sessions"].add(event.get("session_id", ""))
    stats["protocols"].add(event.get("protocol", "unknown"))
    
    timestamp = event.get("timestamp")
    if timestamp:
        if not stats["first_seen"]:
            stats["first_seen"] = timestamp
        stats["last_seen"] = timestamp
    
    creds = event.get("credentials", {})
    if creds.get("username"):
        stats["usernames"].add(creds["username"])
    if creds.get("password"):
        stats["passwords"].add(creds["password"])
    
    cmd = event.get("command", {})
    if cmd.get("command"):
        stats["commands"].append(cmd["command"])
    
    category = event.get("category", "")
    should_submit = (
        category in ("authentication", "command") or 
        stats["attempts"] >= 3 or
        len(stats["commands"]) > 0
    )
    
    if should_submit:
        return submit_to_sentinelforge(ip, stats, event, api_url)
    
    return False


def print_banner():
    """Print startup banner"""
    print("""
+---------------------------------------------------------------+
|     HoneyTrap -> SentinelForge Integration                    |
+---------------------------------------------------------------+
|  Feeding honeypot attackers into threat intelligence          |
+---------------------------------------------------------------+
    """)


def print_stats():
    """Print current statistics"""
    total_ips = len(ip_stats)
    total_events = len(processed_events)
    total_commands = sum(len(s["commands"]) for s in ip_stats.values())
    
    print(f"\n[*] Statistics:")
    print(f"    Events processed: {total_events}")
    print(f"    Unique IPs: {total_ips}")
    print(f"    Commands captured: {total_commands}")
    
    if ip_stats:
        print(f"\n[*] Top Attackers:")
        sorted_ips = sorted(ip_stats.items(), key=lambda x: x[1]["attempts"], reverse=True)[:5]
        for ip, data in sorted_ips:
            severity = calculate_severity(data)
            print(f"    {ip}: {data['attempts']} attempts, {len(data['commands'])} commands [{severity}]")


def process_existing_events(filepath, api_url):
    """Process all existing events in the file"""
    path = Path(filepath)
    if not path.exists():
        return 0
    
    count = 0
    with open(path, 'r') as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    event = json.loads(line)
                    if process_event(event, api_url):
                        count += 1
                except json.JSONDecodeError:
                    continue
    return count


def watch_events_file(filepath, api_url):
    """Watch the events file for new events"""
    path = Path(filepath)
    
    print(f"[*] Watching: {filepath}")
    print(f"    (Press Ctrl+C to stop)\n")
    
    if path.exists():
        print("[*] Processing existing events...")
        count = process_existing_events(filepath, api_url)
        print(f"    Processed {count} indicators\n")
        print_stats()
        print("\n" + "-" * 60)
        print("[*] Watching for new events...\n")
        last_size = path.stat().st_size
    else:
        print(f"[*] Waiting for events file to be created...")
        last_size = 0
    
    try:
        while True:
            time.sleep(POLL_INTERVAL)
            
            if not path.exists():
                continue
                
            current_size = path.stat().st_size
            
            if current_size > last_size:
                with open(path, 'r') as f:
                    f.seek(last_size)
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                event = json.loads(line)
                                category = event.get("category", "")
                                source_ip = event.get("source", {}).get("ip", "?")
                                
                                print(f"[>] New event: {category} from {source_ip}")
                                process_event(event, api_url)
                            except json.JSONDecodeError:
                                continue
                last_size = current_size
                
            elif current_size < last_size:
                print("[!] Events file was reset, reprocessing...")
                processed_events.clear()
                ip_stats.clear()
                last_size = 0
                
    except KeyboardInterrupt:
        print("\n\n[*] Stopping...")
        print_stats()
        print("\nGoodbye!")


def process_once(filepath, api_url):
    """Process events file once and exit"""
    path = Path(filepath)
    
    if not path.exists():
        print(f"[-] Events file not found: {filepath}")
        return
    
    print(f"[*] Processing: {filepath}\n")
    count = process_existing_events(filepath, api_url)
    print(f"\n[+] Done! Submitted {count} indicators to SentinelForge")
    print_stats()


def main():
    parser = argparse.ArgumentParser(
        description="Feed HoneyTrap events into SentinelForge threat intelligence"
    )
    parser.add_argument(
        "--events-file", "-f",
        default=DEFAULT_EVENTS_FILE,
        help=f"Path to events.jsonl file (default: {DEFAULT_EVENTS_FILE})"
    )
    parser.add_argument(
        "--watch", "-w",
        action="store_true",
        help="Watch mode: continuously monitor for new events"
    )
    parser.add_argument(
        "--api", "-a",
        default=DEFAULT_API,
        help=f"SentinelForge API URL (default: {DEFAULT_API})"
    )
    
    args = parser.parse_args()
    api_url = args.api
    
    print_banner()
    print(f"[*] SentinelForge API: {api_url}")
    
    # Test connection
    try:
        health_url = api_url.replace("/api/v1", "") + "/health"
        response = requests.get(health_url, timeout=5)
        if response.status_code == 200:
            print("[+] Connected to SentinelForge\n")
        else:
            print("[!] SentinelForge returned unexpected status\n")
    except requests.exceptions.ConnectionError:
        print("[-] Cannot connect to SentinelForge - make sure it's running!\n")
        return
    
    if args.watch:
        watch_events_file(args.events_file, api_url)
    else:
        process_once(args.events_file, api_url)


if __name__ == "__main__":
    main()