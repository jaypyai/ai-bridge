#!/usr/bin/env python3
"""Store a reply for the voice agent to fetch via get_reply.

Usage: reply.py <request_id> <reply text>
Appends {"request_id", "reply", "ts"} to replies.jsonl on the bridge host.

Environment:
  BRIDGE_HOST   SSH target for the bridge host (default: bridge-host)
  BRIDGE_DIR    Remote directory holding replies.jsonl (default: /opt/ai-bridge)
"""
import base64
import json
import os
import subprocess
import sys
import time

HOST = os.environ.get("BRIDGE_HOST", "bridge-host")
REMOTE_DIR = os.environ.get("BRIDGE_DIR", "/opt/ai-bridge")
REMOTE = f"{REMOTE_DIR}/replies.jsonl"


def main():
    if len(sys.argv) != 3:
        print("usage: reply.py <request_id> <reply text>", file=sys.stderr)
        sys.exit(2)
    request_id, text = sys.argv[1], sys.argv[2]
    entry = json.dumps({"request_id": request_id,
                        "reply": text[:8000],
                        "ts": time.time()}) + "\n"
    b64 = base64.b64encode(entry.encode()).decode()
    subprocess.run(["ssh", HOST, f"echo {b64} | base64 -d >> {REMOTE}"],
                   check=True, timeout=30)
    print(f"reply stored for {request_id}")


if __name__ == "__main__":
    main()
