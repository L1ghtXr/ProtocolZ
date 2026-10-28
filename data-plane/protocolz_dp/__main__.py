"""Runnable entry points: python -m protocolz_dp {proxy,java,bedrock,health}"""
from __future__ import annotations

import argparse
import asyncio
import json
import signal
import sys

from protocolz_common.events import EventLog
from protocolz_detect.baseline import Detector, MetricConfig
from protocolz_nft.policy import FirewallPolicy, PolicyError

from .health import HttpCheck, TcpCheck, run_check
from .minecraft import BedrockRelay, BedrockShieldConfig, JavaShield, JavaShieldConfig
from .proxy import ProxyConfig, ReverseProxy
from . import vps


async def _serve(start, stop_fn, label: str) -> None:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    port = await start()
    print(f"{label} listening on port {port}; Ctrl-C to stop", flush=True)
    await stop.wait()
    await stop_fn()


def _hostport(value: str):
    host, _, port = value.rpartition(":")
    return host, int(port)


def _vps(args, events) -> int:
    if args.vcmd == "audit":
        policy = None
        if args.policy:
            try:
                policy = FirewallPolicy.from_dict(json.load(open(args.policy)))
            except (OSError, ValueError, PolicyError) as exc:
                print(f"cannot use policy: {exc}", file=sys.stderr)
                return 2
        findings = vps.audit_ports(vps.listening_ports(), policy) + vps.check_sshd_config(args.sshd_config)
        for f in findings:
            print(f"[{f.severity}] {f.what}" + (f"  -> {f.advice}" if f.advice else ""))
        print(f"{len(findings)} finding(s). Read-only: nothing was changed.")
        return 1 if any(f.severity in ("high", "warn") for f in findings) else 0
    if args.vcmd == "fim-init":
        print(f"baseline of {vps.fim_init(args.paths, args.baseline)} file(s) written to {args.baseline}")
        return 0
    if args.vcmd == "fim-check":
        findings = vps.fim_check(args.baseline)
        for f in findings:
            print(f"[{f.severity}] {f.what}")
        print(f"{len(findings)} change(s) since baseline.")
        return 1 if findings else 0
    det = Detector([MetricConfig("rx_pps", floor_abs=50), MetricConfig("rx_bytes_per_sec", floor_abs=5000),
                    MetricConfig("cpu_pct", floor_abs=5), MetricConfig("mem_pct", floor_abs=5)], warmup=args.warmup)
    sampler, attacked, n = vps.HostSampler(), False, 0
    import time
    while n < args.samples:
        m = sampler.sample()
        if m is not None:
            n += 1
            up = True
            if args.service_tcp:
                host, port = _hostport(args.service_tcp)
                up = run_check(TcpCheck(host, port, 1.0)).ok
            v = det.observe(m, service_up=up)
            print(f"{n:4d} {v.explain()}  [pps={m['rx_pps']:.0f} cpu={m['cpu_pct']:.0f}% mem={m['mem_pct']:.0f}%]", flush=True)
            if v.level == "attack":
                attacked = True
                if events:
                    events.emit("detect.attack", reasons=[str(r) for r in v.reasons], service_impacted=v.service_impacted)
        time.sleep(args.interval)
    return 1 if attacked else 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="protocolz-dp")
    p.add_argument("--events", help="append JSON-lines security events to this file")
    sub = p.add_subparsers(dest="cmd", required=True)

    w = sub.add_parser("proxy", help="Web Shield reverse proxy (plain HTTP in, plain HTTP to origin)")
    w.add_argument("--listen-host", default="127.0.0.1")
    w.add_argument("--listen-port", type=int, default=8080)
    w.add_argument("--origin", default="127.0.0.1:8081", metavar="HOST:PORT")
    w.add_argument("--rate", type=float, default=20.0, help="requests/second per client IP")
    w.add_argument("--burst", type=float, default=40.0)
    w.add_argument("--max-conns-per-ip", type=int, default=50)
    w.add_argument("--block", action="append", default=[], metavar="REGEX", help="block targets matching REGEX (repeatable)")

    j = sub.add_parser("java", help="Minecraft Java shield")
    j.add_argument("--listen-host", default="127.0.0.1")
    j.add_argument("--listen-port", type=int, default=25565)
    j.add_argument("--backend", default="127.0.0.1:25566", metavar="HOST:PORT")
    j.add_argument("--proxy-protocol", action="store_true", help="send PROXY v1 header so the backend sees client IPs")
    j.add_argument("--conn-rate", type=float, default=5.0)
    j.add_argument("--login-rate", type=float, default=0.5)

    b = sub.add_parser("bedrock", help="Minecraft Bedrock (RakNet/UDP) shield")
    b.add_argument("--listen-host", default="127.0.0.1")
    b.add_argument("--listen-port", type=int, default=19132)
    b.add_argument("--backend", default="127.0.0.1:19133", metavar="HOST:PORT")

    h = sub.add_parser("health", help="one-shot health check; exit 1 if any target is down")
    h.add_argument("--tcp", action="append", default=[], metavar="HOST:PORT")
    h.add_argument("--http", action="append", default=[], metavar="HOST:PORT[/path]")

    vp = sub.add_parser("vps", help="VPS Shield: READ-ONLY host audit and monitoring")
    vs = vp.add_subparsers(dest="vcmd", required=True)
    a = vs.add_parser("audit", help="exposed ports vs policy + SSH hardening advice")
    a.add_argument("--policy", help="firewall policy JSON to judge listeners against")
    a.add_argument("--sshd-config", default="/etc/ssh/sshd_config")
    fi = vs.add_parser("fim-init", help="record a file-integrity baseline")
    fi.add_argument("--baseline", required=True)
    fi.add_argument("paths", nargs="+")
    fc = vs.add_parser("fim-check", help="compare against a baseline; exit 1 on any change")
    fc.add_argument("--baseline", required=True)
    wt = vs.add_parser("watch", help="sample host metrics and run the explainable detector")
    wt.add_argument("--interval", type=float, default=1.0)
    wt.add_argument("--samples", type=int, default=60)
    wt.add_argument("--warmup", type=int, default=30)
    wt.add_argument("--service-tcp", metavar="HOST:PORT", help="correlate with this service's availability")

    args = p.parse_args(argv)
    events = EventLog(args.events) if args.events else None

    if args.cmd == "vps":
        return _vps(args, events)

    if args.cmd == "health":
        results = {}
        for t in args.tcp:
            host, port = _hostport(t)
            results[f"tcp:{t}"] = run_check(TcpCheck(host, port))
        for t in args.http:
            hp, _, path = t.partition("/")
            host, port = _hostport(hp)
            results[f"http:{t}"] = run_check(HttpCheck(host, port, "/" + path))
        print(json.dumps({k: {"ok": r.ok, "latency_ms": round(r.latency_ms, 1), "detail": r.detail} for k, r in results.items()}, indent=2))
        return 0 if results and all(r.ok for r in results.values()) else 1

    if args.cmd == "proxy":
        oh, op = _hostport(args.origin)
        srv = ReverseProxy(ProxyConfig(listen_host=args.listen_host, listen_port=args.listen_port, origin_host=oh,
                                       origin_port=op, rate=args.rate, burst=args.burst,
                                       max_conns_per_ip=args.max_conns_per_ip, block_patterns=tuple(args.block)), events)
        asyncio.run(_serve(srv.start, srv.stop, "web shield"))
    elif args.cmd == "java":
        bh, bp = _hostport(args.backend)
        srv = JavaShield(JavaShieldConfig(listen_host=args.listen_host, listen_port=args.listen_port, backend_host=bh,
                                          backend_port=bp, proxy_protocol_v1=args.proxy_protocol,
                                          conn_rate=args.conn_rate, login_rate=args.login_rate), events)
        asyncio.run(_serve(srv.start, srv.stop, "java shield"))
    else:
        bh, bp = _hostport(args.backend)
        srv = BedrockRelay(BedrockShieldConfig(listen_host=args.listen_host, listen_port=args.listen_port,
                                               backend_host=bh, backend_port=bp), events)
        asyncio.run(_serve(srv.start, srv.stop, "bedrock shield"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
