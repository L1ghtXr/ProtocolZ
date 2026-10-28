from __future__ import annotations

import argparse
import json
import os
import sys

from .manager import FirewallManager, SubprocessRunner
from .policy import FirewallPolicy, PolicyError
from .render import render


def _load(path: str) -> FirewallPolicy:
    try:
        with open(path, encoding="utf-8") as fh:
            return FirewallPolicy.from_dict(json.load(fh))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"cannot read policy {path}: {exc}") from None


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="protocolz-nft", description="Safe nftables policy management.")
    p.add_argument("--state-dir", default=os.environ.get("PROTOCOLZ_STATE_DIR", "/var/lib/protocolz"))
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, help_ in (("validate", "validate policy only"), ("render", "print the nft ruleset"),
                        ("dry-run", "render + `nft -c`; never changes live rules")):
        sub.add_parser(name, help=help_).add_argument("policy")
    ap = sub.add_parser("apply", help="apply with confirm-or-rollback")
    ap.add_argument("policy")
    ap.add_argument("--yes", action="store_true", help="explicit authorization to change this host's firewall")
    ap.add_argument("--confirm-timeout", type=float, default=60.0,
                    help="seconds to wait for `confirm` before auto-rollback (0 disables; default 60)")
    sub.add_parser("confirm", help="confirm a pending apply (run from a second session)")
    rb = sub.add_parser("rollback", help="restore the most recent pre-apply state")
    rb.add_argument("--yes", action="store_true")
    return p


def _manager(args) -> FirewallManager:
    return FirewallManager(SubprocessRunner(), args.state_dir, nft_bin=os.environ.get("PROTOCOLZ_NFT_BIN", "nft"))


def main(argv=None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.cmd == "validate":
            policy = _load(args.policy)
            for w in policy.warnings():
                print(f"warning: {w}")
            print("policy valid")
            return 0
        if args.cmd == "render":
            print(render(_load(args.policy)), end="")
            return 0
        if args.cmd in ("apply", "rollback"):
            if not args.yes:
                print(f"{args.cmd} changes the live firewall and requires --yes", file=sys.stderr)
                return 2
            if hasattr(os, "geteuid") and os.geteuid() != 0:
                print(f"{args.cmd} requires root", file=sys.stderr)
                return 2
        mgr = _manager(args)
        if args.cmd == "dry-run":
            res = mgr.dry_run(_load(args.policy))
        elif args.cmd == "apply":
            policy = _load(args.policy)
            if args.confirm_timeout > 0:
                print(f"Applying. Run `protocolz-nft confirm` from ANOTHER session within "
                      f"{args.confirm_timeout:g}s or the previous rules are restored.", flush=True)
            res = mgr.apply(policy, confirm_timeout=args.confirm_timeout)
        elif args.cmd == "confirm":
            res = mgr.confirm()
        else:
            res = mgr.rollback()
    except PolicyError as exc:
        print(f"policy error: {exc}", file=sys.stderr)
        return 2
    except PermissionError as exc:
        print(f"permission error: {exc} (use --state-dir or run as root)", file=sys.stderr)
        return 2
    for w in res.warnings:
        print(f"warning: {w}")
    print(("OK: " if res.ok else "FAIL: ") + res.message)
    return 0 if res.ok else 1
