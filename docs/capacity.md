# Capacity, failure behaviour and operations (honest status)

**Measured:** only the Python-level microbenchmarks in [benchmarks.md](benchmarks.md), on one vCPU. **Everything else below is design intent or
explicitly unknown.**

| Topic | Status |
|---|---|
| Capacity per node (pps / Gbit/s / connections) | **Unknown.** Never measured. Bounded above by the host's NIC and uplink; ProtocolZ cannot exceed it. |
| Max tested throughput | Proxy: ≈2.3k req/s on 1 shared vCPU, loopback, one request per connection (lower bound). Kernel rules: not measured. |
| Packet-rate limits | nftables rate/per-source limits exist; their effect under attack traffic is untested. |
| Control-plane failure behaviour | **Tested:** the agent keeps the rules already loaded and makes zero `nft` calls during an outage; it re-applies its cached, signature-checked bundle after a reboot even with the control plane down; events queue and flush later. |
| Regional failover | **Not implemented.** Nodes are independent; moving traffic between regions needs DNS/anycast/provider routing that this repo does not provide. |
| Routing / upstream mitigation requirements | Volumetric floods require an upstream scrubber or provider; ProtocolZ can only send a signed webhook request. Vendor adapters are not written or tested. |
| Data consistency | SQLite, one control-plane instance, single writer. No replication/HA. Policy versions are monotonic per node: **restoring an old DB backup can leave nodes ignoring "older" versions** — bump versions after a restore. |
| Secret distribution | Node credentials are derived from the control-plane master key and shown once at registration; transport to the node is manual. Master-key rotation is **not implemented** (rotating invalidates every node credential). Key file is 0600. |
| Operational cost | Not measured. Runtime is stdlib Python + SQLite; no external services required. |
| Deployment and recovery | See [deployment.md](deployment.md) and [incident-response.md](incident-response.md). Back up the DB **and** the key file together. |

A small VPS must never be represented as capable of absorbing traffic beyond its available network capacity. Do not advertise
global or national-scale mitigation until the capacity and provider integrations exist and have been tested.
