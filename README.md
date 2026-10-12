# AI Bridge

A secure MCP bridge between two AI assistants that can't talk to each other directly.

## The problem

I use a live voice agent day-to-day — great for talking through ideas hands-free, but it has real coding limitations. My other agent is the all-arounder: it writes code, runs tools, manages files, handles the heavy lifting. But I can't talk to that one by voice.

So while I'm on a call with the voice agent, I had no way to hand real work to the capable one. I was describing code tasks out loud with no path to get them done.

## The fix

This bridge. The voice agent connects as an MCP client and gets two tools:

- **`delegate_task`** — hand a task to the assistant agent, in the user's own words. It gets queued instantly with a request ID.
- **`get_reply`** — pull the assistant's reply with that request ID. Poll until it's ready.

Now I can be mid-conversation — driving, cooking, whatever — say "have the assistant build that script," and the work starts within minutes. The voice agent fetches the result and reads it back to me. Two specialists, one conversation.

## How it works

```
voice agent --MCP/HTTPS--> bridge_server.py --queue.jsonl--> poll.py --> assistant agent
     ^                                                              |
     └------------------ get_reply <-- replies.jsonl <-- reply.py <--┘
```

- **Transport:** Streamable HTTP MCP, stdlib only (no dependencies).
- **Auth:** Full single-user OAuth 2.1 — dynamic client registration (RFC 7591), PKCE-S256 code flow, approve page gated by a 256-bit bridge secret only the owner knows. The voice agent's platform required OAuth metadata at the standard root paths, so it's all implemented there.
- **Security model:** tools can only append to the queue and read replies. They can't send messages, run commands, or touch anything else. Auth codes are single-use with 10-minute expiry, bound to client + redirect URI + PKCE challenge. Tokens are opaque and stored server-side.
- **Polling:** a lightweight shell script (`poll.py`) checks the queue every couple minutes and wakes the assistant only when tasks arrive — no heavyweight worker per check.

## Run it

```bash
# 1. Set a secret (or create a .bridge_secret file)
export BRIDGE_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# 2. Start the server
python3 bridge_server.py   # listens on 127.0.0.1:8133 by default

# 3. Point your voice agent's MCP client at https://<your-host>/mcp
#    and complete the OAuth grant on the approve page.
```

See `.env.example` for all options (`BRIDGE_PORT`, `BRIDGE_BIND`, `BRIDGE_HOST`, `BRIDGE_DIR`).

## Project notes

Built with AI-assisted development: I directed the architecture (protocol choice, OAuth flow, security model, polling pattern) and verified the implementation, including the strict metadata-path validation some voice platforms require.

## License

MIT
