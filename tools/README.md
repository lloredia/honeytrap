# HoneyTrap tools

Python helpers that sit next to the Rust honeypot. They are not part of the
internet-facing process.

```bash
python -m pip install -e ".[dev]"
```

## SentinelForge

`SENTINELFORGE_API_URL` (default `http://127.0.0.1:8080/api/v1`) and
`SENTINELFORGE_API_KEY` (sent as `X-API-Key`) come from the environment.

```bash
export SENTINELFORGE_API_URL=http://127.0.0.1:8080/api/v1
export SENTINELFORGE_API_KEY=replace-me
python honeytrap_integration.py --events-file ../data/events/ssh.jsonl
python honeytrap_integration.py --events-file ../data/events/live.jsonl --watch
```

## Synthetic events

Generated addresses stay inside the RFC 5737 documentation ranges.

```bash
python honeytrap_test_generator.py --output ../events.jsonl --sessions 50
python honeytrap_test_generator.py -o ../events.jsonl -n 20 --mode compromise --clear
```
