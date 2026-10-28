# Incident response guide

Principle: **restore reachability first, investigate second, and never retaliate** (no counter-attacks, no packet generation).

## A. You are locked out after a firewall change
1. Wait out the confirm window (default 60 s): the snapshot or the detached watchdog restores the previous rules.
2. Still locked out? Use the provider console: `nft -f /var/lib/protocolz/backups/<newest>.nft` or `nft delete table inet protocolz`.
3. Check `events.jsonl` (`firewall.applied`, `firewall.rollback`, `firewall.watchdog_rollback`, `firewall.rollback_failed`); fix `management_cidrs`; retry with `dry-run`.

## B. Suspected DDoS
1. Classify **locally mitigable** vs **needs upstream**: if the uplink is saturated (check provider graphs / `vps watch`), local rules cannot help; contact the provider and request mitigation (dashboard → Mitigations, or `POST /api/mitigations`; only targets inside your registered assets are accepted).
2. Application-layer: tighten `--rate`, add `--block` rules on the Web Shield; per-service `new_conn_rate` / `per_source_rate` in the firewall policy (dry-run, then apply with confirm).
3. Game servers: lower `--conn-rate` / `--login-rate`; confirm the backend is only reachable from the shield.
4. Record: time, metrics, actions, effect. `GET /api/events` and `/api/audit` hold the trail. Withdraw provider mitigation when over.

## C. Suspected host compromise
1. `vps fim-check` and `vps audit`; review `[high]` findings. Preserve evidence (copy `events.jsonl`, baseline, logs) before changing anything.
2. Rotate credentials: user passwords/MFA, provider webhook secrets, node credentials (re-register the node; master-key rotation is not implemented).
3. Rebuild from a trusted image if integrity is in doubt; ProtocolZ's read-only checks are indicators, not proof.

## D. Control plane compromised or unavailable
- Unavailable: nodes keep enforcing the last policy (tested). Restore from DB + key backup; bump policy versions afterwards.
- Compromised: isolate it, run `python3 -m protocolz_cp verify-audit` on a copy of the DB, rotate the master key by rebuilding (all node credentials must be re-issued), review every `set_node_policy` entry.

## E. Reporting a ProtocolZ vulnerability
See SECURITY.md.
