# nftables integration — module report

**Implemented:** policy validation, default-deny renderer (input hook only), `nft -c` dry-run,
snapshot, atomic apply, health check hook, confirm-or-rollback, manual rollback, JSONL events, CLI.
**Tests:** 33 unit tests passing (`make test`), using a fake command runner.
**Known limitations:** see top-level README (not run on a real kernel; per-rule not per-source limits;
foreground confirm; no persistence across reboot; IPv4/IPv6 input only).
**External requirements:** Linux, root, nftables, Python ≥ 3.10.
**Deploy:** docs/deployment.md.
**Remaining:** netns integration tests, per-source dynamic-set limits, reboot persistence, detached
rollback watchdog, SYN-specific rules, remote/agent runner.
