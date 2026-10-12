#!/usr/bin/env python3
"""Poll the AI bridge queue for new delegated tasks.

The bridge server appends tasks to queue.jsonl; this script prints any lines
added since the last run. State lives in .poll_state next to this script.

Environment:
  BRIDGE_HOST   SSH target for the bridge host (default: bridge-host)
  BRIDGE_DIR    Remote directory holding queue.jsonl (default: /opt/ai-bridge)

Prints new tasks as JSON lines, or NO_NEW_TASKS when the queue is empty.
Designed to run on a tight loop (e.g. every 120s) as a cheap shell script,
waking your agent/worker only when tasks actually arrive.
"""
import json
import os
import subprocess
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(BASE, ".poll_state")
HOST = os.environ.get("BRIDGE_HOST", "bridge-host")
REMOTE_DIR = os.environ.get("BRIDGE_DIR", "/opt/ai-bridge")
QUEUE = f"{REMOTE_DIR}/queue.jsonl"


def remote(cmd):
    r = subprocess.run(["ssh", HOST, cmd], capture_output=True, text=True, timeout=30)
    return r.stdout.strip()


def main():
    try:
        claimed = int(open(STATE_FILE).read().strip())
    except Exception:
        claimed = 0
    try:
        total = int(remote(f"wc -l < {QUEUE} 2>/dev/null || echo 0") or 0)
    except Exception as e:
        print(f"POLL_ERROR host unreachable: {e}")
        return 1
    if total <= claimed:
        print("NO_NEW_TASKS")
        return 0
    lines = remote(f"tail -n +{claimed + 1} {QUEUE}").splitlines()
    for line in lines:
        line = line.strip()
        if line:
            print(line)
    with open(STATE_FILE, "w") as f:
        f.write(str(total))


if __name__ == "__main__":
    sys.exit(main())
