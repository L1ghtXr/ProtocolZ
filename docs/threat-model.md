# Threat Model (v0.1, firewall module + planned platform)

## Assets
Host reachability (esp. admin access), integrity of firewall policy, audit log, future: tenant data,
provider API credentials, admin sessions.

## Actors
Remote unauthenticated attacker; low-privilege local user; malicious/compromised tenant; compromised
control plane or provider API; careless administrator (the most likely cause of outages).

## Trust boundaries
Operator ↔ CLI; CLI ↔ `nft` (root); node ↔ control plane (future); tenant ↔ tenant (future).

## Threats and status
| Threat | Mitigation | Status |
|---|---|---|
| Admin locks self out with default-deny | Mandatory `management_cidrs`; `nft -c`; snapshot; confirm-or-rollback | Implemented, unit-tested; not yet tested on real kernel |
| Rule injection via policy fields | Strict schema, unknown fields rejected, names regex, ports int-only, CIDRs parsed and re-rendered from objects (not raw strings) | Implemented, tested |
| Partial/torn apply | Single atomic `nft -f` with table replace idiom | Implemented (kernel behaviour unverified here) |
| Rollback itself fails | Reported loudly with manual recovery command; `rollback_failed` event | Implemented |
| Crash during confirm window | No auto-rollback if process killed | **Known gap** (README limitation 3) |
| Tampering with backups/staged rules/logs | State dir 0700, files 0600, root-only apply | Implemented; log is not tamper-evident |
| Shell/command injection | `subprocess` without shell, argv lists | Implemented |
| Flood exhausts rate budget (per-rule limit) | Per-source limiting | **Planned** |
| Volumetric DDoS beyond uplink | Upstream scrubbing via provider adapters | **Planned; local code cannot mitigate** |
| Control-plane compromise pushes bad policy | Signed bundles, RBAC, MFA, audit, local validation + rollback | Planned |
| Tenant isolation failure | Per-tenant authz on every query, tests | Planned |
| Secrets leakage | No secrets in repo; `.env.example` only; secret manager | Partial |
| Misuse as offensive tool | No packet generation or offensive features in scope; test generators must have rate caps + target allow-list + kill switch | Policy only |

## Out of scope for v0.1
Hardware/kernel vulnerabilities, physical access, attacks above the host's network capacity.
