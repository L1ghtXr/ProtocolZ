# Control plane

Code: `control-plane/protocolz_cp` (stdlib + SQLite). Run: `python3 -m protocolz_cp serve`. API: [docs/api.md](../docs/api.md). Tests: `tests/test_controlplane.py`, `tests/test_agent.py`.
Limits: single instance, no TLS, no HA, no migrations. See README "Known limitations".
