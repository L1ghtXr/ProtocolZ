"""Reproducible microbenchmarks for ProtocolZ components.  Run: make bench

SAFETY: every network target is hard-wired to 127.0.0.1 and every workload has a fixed request count and an
overall wall-clock cap (--max-seconds). There is no option to aim traffic at another host. Ctrl-C stops it.

SCOPE (read before quoting numbers): single-process Python on whatever machine runs it. The load generator,
proxy and origin share the same interpreter and CPU, so proxy numbers are a conservative lower bound dominated
by asyncio overhead. This is NOT a comparison against nginx/HAProxy/Cloudflare etc. -- none were available in
the authoring sandbox -- and it measures no kernel-level (nftables) packet performance.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import random
import statistics
import subprocess
import sys
import time
from pathlib import Path

from protocolz_common.ratelimit import TokenBucketLimiter
from protocolz_detect.baseline import Detector, MetricConfig
from protocolz_dp.minecraft import classify_bedrock, parse_java_handshake, RAKNET_MAGIC
from protocolz_dp.proxy import ProxyConfig, ReverseProxy
from protocolz_nft.policy import FirewallPolicy
from protocolz_nft.render import render

HOST = "127.0.0.1"


def rate_of(fn, n: int) -> float:
    t = time.perf_counter()
    fn(n)
    return n / (time.perf_counter() - t)


def micro() -> dict:
    keys = [f"10.0.{i // 256}.{i % 256}" for i in range(1000)]
    lim = TokenBucketLimiter(1e9, 1e9)

    def rl(n):
        a = lim.allow
        for i in range(n):
            a(keys[i % 1000])

    det = Detector([MetricConfig("pps"), MetricConfig("conn"), MetricConfig("cpu", floor_abs=2.0)])
    rng = random.Random(1)
    samples = [{"pps": rng.gauss(1000, 50), "conn": rng.gauss(200, 10), "cpu": rng.gauss(20, 2)} for _ in range(1000)]

    def dt(n):
        o = det.observe
        for i in range(n):
            o(samples[i % 1000])

    addr = b"mc.example.org"
    body = b"\x00" + b"\xf5\x05" + bytes([len(addr)]) + addr + (25565).to_bytes(2, "big") + b"\x02"
    hs = bytes([len(body)]) + body

    def jp(n):
        p = parse_java_handshake
        for _ in range(n):
            p(hs)

    ping = b"\x01" + b"\x00" * 8 + RAKNET_MAGIC + b"\x00" * 8

    def bc(n):
        c = classify_bedrock
        for _ in range(n):
            c(ping)

    pol = FirewallPolicy.from_dict({"management_cidrs": ["203.0.113.0/24", "2001:db8::/32"], "services": [
        {"name": f"svc-{i}", "proto": "tcp" if i % 2 else "udp", "port": 20000 + i, "allow_cidrs": ["198.51.100.0/24"],
         "new_conn_rate": 100, "per_source_rate": 10} for i in range(20)]})

    def rn(n):
        for _ in range(n):
            render(pol)

    return {"ratelimiter_decisions_per_sec": rate_of(rl, 300_000), "detector_observations_per_sec": rate_of(dt, 100_000),
            "java_handshake_parses_per_sec": rate_of(jp, 200_000), "bedrock_classifications_per_sec": rate_of(bc, 300_000),
            "nft_renders_per_sec_20_services": rate_of(rn, 1_500)}


def detection_quality() -> dict:
    """Deterministic (seeded) SYNTHETIC results. Real-traffic false-positive rates are unmeasured."""
    cfg = [MetricConfig("pps"), MetricConfig("cpu", floor_abs=2.0)]
    rng = random.Random(42)
    det = Detector(cfg)
    n, levels = 200_000, {"suspect": 0, "attack": 0}
    for i in range(n):
        v = det.observe({"pps": max(0, rng.gauss(1000, 50)), "cpu": max(0, rng.gauss(20, 2))})
        if v.level in levels:
            levels[v.level] += 1
    latency = {}
    for mult in (1.5, 2, 3, 5, 8):
        d, r = Detector(cfg), random.Random(7)
        for _ in range(100):
            d.observe({"pps": max(0, r.gauss(1000, 50)), "cpu": 20})
        found = None
        for i in range(1, 31):
            if d.observe({"pps": r.gauss(1000 * mult, 50 * mult), "cpu": 20}).level == "attack":
                found = i
                break
        latency[f"{mult}x"] = found if found else "not detected in 30 samples"
    return {"stationary_gaussian_samples": n, "false_suspect_samples": levels["suspect"],
            "false_attack_samples": levels["attack"], "samples_to_attack_verdict_by_spike": latency}


async def _origin(reader, writer):
    try:
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        await writer.drain()
    finally:
        writer.close()


async def _load(port: int, total: int, concurrency: int) -> dict:
    lat, codes, idx = [], {}, iter(range(total))

    async def worker():
        for _ in idx:
            t = time.perf_counter()
            r, w = await asyncio.open_connection(HOST, port)
            w.write(b"GET / HTTP/1.1\r\nHost: bench\r\n\r\n")
            await w.drain()
            data = await r.read()
            w.close()
            lat.append((time.perf_counter() - t) * 1000)
            code = data.split(b" ", 2)[1].decode() if data else "none"
            codes[code] = codes.get(code, 0) + 1

    t0 = time.perf_counter()
    await asyncio.gather(*(worker() for _ in range(concurrency)))
    dur = time.perf_counter() - t0
    lat.sort()
    return {"rps": total / dur, "p50_ms": lat[len(lat) // 2], "p99_ms": lat[int(len(lat) * 0.99) - 1], "codes": codes}


async def proxy_bench(total: int = 1500, concurrency: int = 20) -> dict:
    origin = await asyncio.start_server(_origin, HOST, 0)
    oport = origin.sockets[0].getsockname()[1]
    out = {"direct_to_origin": await _load(oport, total, concurrency)}
    open_cfg = ProxyConfig(listen_host=HOST, listen_port=0, origin_host=HOST, origin_port=oport, rate=1e9, burst=1e9,
                           max_conns_per_ip=10_000)
    p = ReverseProxy(open_cfg)
    out["via_protocolz_proxy"] = await _load(await p.start(), total, concurrency)
    await p.stop()
    lim_cfg = ProxyConfig(listen_host=HOST, listen_port=0, origin_host=HOST, origin_port=oport, rate=0.0001, burst=1,
                          max_conns_per_ip=10_000)
    p = ReverseProxy(lim_cfg)
    out["proxy_rejecting_with_429"] = await _load(await p.start(), total, concurrency)
    await p.stop()
    origin.close()
    await origin.wait_closed()
    return out


def environment() -> dict:
    cpu = next((l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name")), platform.processor())
    try:
        commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True,
                                cwd=Path(__file__).parent).stdout.strip()
    except OSError:
        commit = ""
    return {"cpu": cpu, "logical_cpus": os.cpu_count(), "python": platform.python_version(), "kernel": platform.release(),
            "date_utc": time.strftime("%Y-%m-%d", time.gmtime()), "commit": commit or "unknown"}


def summarize(runs: list) -> dict:
    return {k: [min(r[k] for r in runs), statistics.median(r[k] for r in runs), max(r[k] for r in runs)] for k in runs[0]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--max-seconds", type=float, default=300)
    args = ap.parse_args()
    start = time.monotonic()
    micro_runs, proxy_runs = [], []
    try:
        for i in range(args.runs):
            print(f"run {i + 1}/{args.runs}", flush=True)
            micro_runs.append(micro())
            proxy_runs.append(asyncio.run(asyncio.wait_for(proxy_bench(), max(5, args.max_seconds - (time.monotonic() - start)))))
    except (KeyboardInterrupt, asyncio.TimeoutError):
        print("stopped early (emergency stop / time cap); partial results discarded", file=sys.stderr)
        return 1
    flat = {}
    for scen in proxy_runs[0]:
        for m in ("rps", "p50_ms", "p99_ms"):
            flat[f"proxy.{scen}.{m}"] = [r[scen][m] for r in proxy_runs]
    result = {"environment": environment(), "runs": args.runs, "micro": summarize(micro_runs),
              "proxy": summarize([{k: v for k, v in zip(flat, [flat[k][i] for k in flat])} for i in range(args.runs)]),
              "proxy_status_codes_run1": {s: proxy_runs[0][s]["codes"] for s in proxy_runs[0]},
              "detection_synthetic": detection_quality()}
    outdir = Path(__file__).parent / "results"
    outdir.mkdir(exist_ok=True)
    (outdir / "latest.json").write_text(json.dumps(result, indent=2))
    env = result["environment"]
    md = [f"Measured {env['date_utc']} at commit `{env['commit']}` on {env['cpu']}, {env['logical_cpus']} logical CPU(s), "
          f"Python {env['python']}, kernel {env['kernel']}. {args.runs} runs; values are min / median / max.\n",
          "| Metric | min | median | max |", "|---|---:|---:|---:|"]
    for section in ("micro", "proxy"):
        for k, (lo, med, hi) in result[section].items():
            f = (lambda x: f"{x:,.0f}") if med >= 100 else (lambda x: f"{x:,.2f}")
            md.append(f"| {k} | {f(lo)} | {f(med)} | {f(hi)} |")
    dq = result["detection_synthetic"]
    md += ["", f"Synthetic detection test (seeded; stationary Gaussian noise, {dq['stationary_gaussian_samples']:,} samples): "
           f"{dq['false_suspect_samples']} suspect and {dq['false_attack_samples']} attack verdicts.",
           "", "Samples until an `attack` verdict after a step change (confirm=3):", ""]
    md += [f"- {k} baseline: {v}" for k, v in dq["samples_to_attack_verdict_by_spike"].items()]
    (outdir / "latest.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
