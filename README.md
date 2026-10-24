# agent-action-risk-patterns

A plain, editable list of the kinds of actions an AI agent takes that deserve a second look, with a tiny scanner that matches them in command logs or tool-call logs.

## The classes

| Class | What it catches | Severity |
|---|---|---|
| `credential-access` | Reading `.env` files, SSH keys, cloud credential files | high |
| `cloud-metadata` | Calling a cloud metadata endpoint (a route to short-lived credentials) | high |
| `outbound-transfer` | Uploads, posts, paste sites, copying files to other machines | medium |
| `privilege-escalation` | `sudo`, world-writable permissions, unrestricted script policies | high |
| `destructive-change` | Recursive deletes, force pushes, hard resets, dropping tables | high |
| `oversight-tampering` | Clearing logs or history, disabling audit or antivirus, skipping hooks | high |
| `persistence` | Scheduled tasks, start-up entries, services that outlive the session | medium |
| `unapproved-communication` | Sending mail, opening issues or PRs, publishing packages, webhooks | medium |

All of them live in `patterns.json`; edit freely for your environment. The categories echo widely published guidance on agent and LLM application risk, such as the OWASP Top 10 for LLM Applications and MITRE ATLAS.

## Use

```bash
python scan.py commands.txt                    # one command per line
python scan.py tool_calls.jsonl --min-severity high
python scan.py tool_calls.jsonl --json
```

Exit code `1` when anything matches, so it can sit in a review script.

## Limits

- **Pattern matching sees text, not intent.** Many matches are harmless (a `.env.example`, a test that posts to a local server), and a determined actor can avoid any fixed pattern.
- It is for reviewing logs and flagging actions for a person, not a security boundary. Pair it with least-privilege credentials and human approval for anything outbound.

## Tests

```bash
python -m unittest -v
```

Python 3.9+, standard library only. Apache-2.0, see `LICENSE` and `NOTICE`.
