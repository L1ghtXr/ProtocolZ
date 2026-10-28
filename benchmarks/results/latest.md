Measured 2026-10-27 at commit `447eb09` on Intel(R) Xeon(R) Processor @ 2.10GHz, 1 logical CPU(s), Python 3.12.3, kernel 6.18.44-fc-v165. 3 runs; values are min / median / max.

| Metric | min | median | max |
|---|---:|---:|---:|
| ratelimiter_decisions_per_sec | 1,193,316 | 1,310,713 | 1,370,298 |
| detector_observations_per_sec | 216,752 | 219,764 | 230,352 |
| java_handshake_parses_per_sec | 207,412 | 225,064 | 241,629 |
| bedrock_classifications_per_sec | 4,848,849 | 5,710,476 | 6,641,075 |
| nft_renders_per_sec_20_services | 3,560 | 4,057 | 4,622 |
| proxy.direct_to_origin.rps | 4,631 | 5,416 | 6,238 |
| proxy.direct_to_origin.p50_ms | 3.15 | 3.29 | 4.04 |
| proxy.direct_to_origin.p99_ms | 4.00 | 7.69 | 9.72 |
| proxy.via_protocolz_proxy.rps | 2,239 | 2,276 | 2,315 |
| proxy.via_protocolz_proxy.p50_ms | 8.35 | 8.41 | 8.56 |
| proxy.via_protocolz_proxy.p99_ms | 13.01 | 15.14 | 16.11 |
| proxy.proxy_rejecting_with_429.rps | 5,032 | 5,425 | 5,439 |
| proxy.proxy_rejecting_with_429.p50_ms | 3.51 | 3.54 | 3.90 |
| proxy.proxy_rejecting_with_429.p99_ms | 5.29 | 5.56 | 8.21 |

Synthetic detection test (seeded; stationary Gaussian noise, 200,000 samples): 0 suspect and 0 attack verdicts.

Samples until an `attack` verdict after a step change (confirm=3):

- 1.5x baseline: not detected in 30 samples
- 2x baseline: 3
- 3x baseline: 3
- 5x baseline: 3
- 8x baseline: 3
