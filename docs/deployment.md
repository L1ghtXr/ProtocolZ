# Deployment (firewall module only)

1. Prerequisites: Linux, root, `nft` (nftables ≥ 0.9), Python ≥ 3.10.
2. Keep an out-of-band console (provider VNC/rescue) available for the first rollout.
3. Write `policy.json`; always include your real admin IP/CIDR in `management_cidrs`.
4. `protocolz-nft validate` → `render` (review) → `dry-run`.
5. Run `apply --yes` inside `tmux` (see README limitation 3). Within the window, open a **new** SSH
   session and run `confirm`. If you cannot connect, wait: the previous rules return automatically.
6. Persistence: ProtocolZ does **not yet** write to `/etc/nftables.conf`; rules are lost on reboot.
   (Persistent config management is remaining work.)
7. Recovery: `protocolz-nft rollback --yes`, or `nft -f /var/lib/protocolz/backups/<latest>.nft`, or
   `nft delete table inet protocolz`.

Control plane, nodes, Docker deployment, and regional failover are not implemented.
