from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from .server import make_server
from .service import ControlPlane, Invalid, load_or_create_master_key

LOOPBACK = {"127.0.0.1", "::1", "localhost"}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="protocolz-cp")
    p.add_argument("--db", default=os.environ.get("PROTOCOLZ_CP_DB", "protocolz-cp.db"))
    p.add_argument("--key-file", default=os.environ.get("PROTOCOLZ_CP_KEY_FILE", "protocolz-cp.key"))
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--bind", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8443)
    s.add_argument("--dashboard", default=str(Path(__file__).resolve().parents[2] / "dashboard"))
    s.add_argument("--behind-tls-proxy", action="store_true",
                   help="required to bind a non-loopback address: you confirm TLS is terminated in front")
    s.add_argument("--trusted-proxy", action="append", default=[], metavar="IP",
                   help="peer address of your TLS proxy; its rightmost X-Forwarded-For entry is used as the client IP "
                        "(repeatable). Without this, all clients behind a proxy share one login rate-limit bucket.")
    c = sub.add_parser("create-superadmin")
    c.add_argument("--username", required=True)
    sub.add_parser("verify-audit")
    args = p.parse_args(argv)

    cp = ControlPlane(args.db, load_or_create_master_key(args.key_file))
    if args.cmd == "create-superadmin":
        pw = os.environ.get("PROTOCOLZ_ADMIN_PASSWORD") or getpass.getpass("Password (min 12 chars): ")
        try:
            cp.bootstrap_superadmin(args.username, pw)
        except Invalid as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(f"superadmin {args.username} created")
        return 0
    if args.cmd == "verify-audit":
        ok, bad = cp.verify_audit()
        print("audit chain intact" if ok else f"AUDIT CHAIN BROKEN at row {bad}")
        return 0 if ok else 1
    if args.bind not in LOOPBACK and not args.behind_tls_proxy:
        print("refusing to serve plain HTTP on a non-loopback address; terminate TLS in front and pass "
              "--behind-tls-proxy", file=sys.stderr)
        return 2
    srv = make_server(cp, args.bind, args.port, args.dashboard, args.trusted_proxy)
    print(f"ProtocolZ control plane on http://{args.bind}:{srv.server_address[1]} (plain HTTP)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
