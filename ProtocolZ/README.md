# ProtocolZ

**One Platform. Every Layer. Resilient by Design.**

Open-source defense platform for infrastructure you own or are authorized to protect.
Founder: KingBrezz. Status: **pre-alpha (v0.1.0). One module implemented.**

> ProtocolZ makes no claim of beating any commercial product, of "AI-powered" protection, or of
> any mitigation capacity. A small VPS cannot absorb traffic beyond its own uplink; volumetric
> attacks need upstream scrubbing. Claims will be added only with measured evidence in
> [docs/benchmarks.md](docs/benchmarks.md).

## Status (what is real today)

| Component | State | Notes |
|---|---|---|
| nftables firewall (`integrations/nftables`) | **Implemented, unit-tested** | Policy validation, default-deny render, `nft -c` dry-run, snapshot, confirm-or-rollback. **Not yet run against a real kernel/nft** (see limitations). |
| Security event log | Implemented (firewall events only) | JSON lines, mode 0600 |
| Control plane (auth, assets, providers) | Not started | `control-plane/STATUS.md` |
| Reverse-proxy rate limiting / Web Shield | Not started | |
| Service health monitoring | Not started (hook exists: `health_check`) | |
| Dashboard | Not started | |
| Game Shield (Minecraft), provider adapters, detection | Not started | Later milestones |
| Docker dev environment | File present, **untested** (no Docker in the authoring sandbox) | |
| CI workflow | File present, **untested** on GitHub | |
| Benchmarks | **None run. No numbers published.** | |

## Quick start (firewall module)

Requires Python 3.10+, no third-party packages. Applying rules requires Linux, root, and `nft`.

```bash
make test                                   # 33 tests, stdlib unittest
export PYTHONPATH=integrations/nftables
python3 -m protocolz_nft validate policy.json
python3 -m protocolz_nft render   policy.json
sudo python3 -m protocolz_nft dry-run policy.json            # nft -c, changes nothing
sudo python3 -m protocolz_nft apply --yes policy.json        # rolls back in 60s unless confirmed
sudo python3 -m protocolz_nft confirm                        # from a SECOND ssh session
sudo python3 -m protocolz_nft rollback --yes
```

Example `policy.json`:

```json
{
  "management_cidrs": ["203.0.113.0/24"],
  "services": [
    {"name": "mc-java", "proto": "tcp", "port": 25565, "new_conn_rate": 100},
    {"name": "mc-bedrock", "proto": "udp", "port": 19132, "new_conn_rate": 200}
  ]
}
```

## Safety design

- `management_cidrs` is mandatory: no policy can be built that omits admin access.
- `apply` needs `--yes` and root; nothing changes a host silently.
- Every apply is preceded by `nft -c`, then a snapshot; failure, failed health check, or no
  confirmation within the window restores the snapshot.
- Only the `inet protocolz` table (input hook) is replaced, atomically. Other tables (e.g. Docker) are untouched.

## Known limitations

1. Ruleset syntax is verified by unit tests on structure only; `nft -c` on the target host is the
   real check. Integration tests in a network namespace are the next task.
2. Rate limits are per rule (per address family), **not per source IP**. They protect the service
   from overload, but a flood can still consume the budget and starve legitimate new connections.
   Per-source limiting (dynamic sets) is planned.
3. `apply` waits for `confirm` in the foreground. If your SSH session dies, the process dies and
   no auto-rollback happens. Run it inside `tmux`/`systemd-run` until a detached watchdog exists.
4. The default health check is none; a local probe cannot prove remote reachability. The
   confirm step is the real guard.
5. IPv4/IPv6 only on the input hook; no forward/output filtering.

See [docs/architecture.md](docs/architecture.md), [docs/threat-model.md](docs/threat-model.md),
[docs/deployment.md](docs/deployment.md), [SECURITY.md](SECURITY.md).

## License

MIT (placeholder choice by the author of this scaffold; the founder should confirm).
