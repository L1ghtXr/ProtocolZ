# Architecture

## Planes
```
 Admin dashboard ──► Control plane (auth, tenants, assets, policy, audit) ──► Postgres
                          │ signed policy bundles (pull, cached)
                          ▼
 Node:  policy agent ─► Data plane enforcement (nftables, reverse proxy, game proxy)
                          ▲                │
              Detection / analytics ◄──── telemetry ──► Monitoring & alerting
                          │
                Provider adapters ──► upstream scrubbing / routing (needed for volumetric attacks)
```
Seven separations from the spec: control plane, data plane, provider adapters, detection,
monitoring, dashboard, tenant management.

## Design rules
1. **Local defense survives control-plane loss.** Nodes enforce the last verified policy from local
   state. The kernel keeps loaded nftables rules regardless of any ProtocolZ process. The control
   plane only distributes policy; it is never in the packet path.
2. **Fail safe on change, fail static on outage.** Policy *changes* require validation, dry-run and
   rollback. A control-plane outage changes nothing.
3. **Local vs upstream is explicit.** Each mitigation records whether it was handled locally or needs
   upstream scrubbing/provider action. Local filtering cannot exceed the node's link capacity.
4. **Explainable detection.** Statistical baselines first; add complexity only with measured gains.
5. **No silent changes.** Administrative changes need explicit authorization (`--yes`, later RBAC + MFA).
6. **Minimal dependencies.** Python stdlib for the MVP. Go/Rust only where a benchmark justifies it.

## Implemented now: nftables integration
`policy.py` (validated model) → `render.py` (ruleset text) → `manager.py` (`nft -c`, snapshot, apply,
health, confirm-or-rollback) → `events.py` (JSONL audit) ← `cli.py`.
The `Runner` interface lets tests (and later the policy agent) inject a fake or remote executor.

## Milestones
| # | Milestone | State |
|---|---|---|
| M0 | Scaffold, architecture, threat model, firewall module | **done (this commit)** |
| M1 | nft integration tests in a network namespace (real kernel) | next |
| M2 | Control plane MVP: admin auth (+TOTP), asset + provider registry, audit | planned |
| M3 | Reverse-proxy rate limiting, service health monitor, dashboard | planned |
| M4 | Game Shield (Minecraft Java/Bedrock) | planned |
| M5 | Detection engine with baselines + benchmark harness | planned |
| M6 | Provider adapters + upstream mitigation, regional nodes | planned |

## Capacity (to be measured — currently unknown)
Per-node capacity, max tested throughput, pps limits, failover time, and cost: **not measured**.
They will be reported in `docs/benchmarks.md` with hardware and method.
