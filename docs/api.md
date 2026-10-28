# Control-plane API (v0.2.0)

JSON over HTTP, default `127.0.0.1:8443` (**plain HTTP; terminate TLS in front**). Auth: `Authorization: Bearer <token>` from `POST /api/login`.
Roles: `superadmin` (global), `tenant_admin` (own tenant, read/write), `viewer` (own tenant, read-only). Every query is tenant-scoped in the
service layer; foreign objects return `404`, not `403`. Errors: `{"error": "..."}` with 400/401/403/404/413/429/502. Request bodies ≤ 64 KB.
Responses carry a strict CSP, `nosniff`, `no-store`, `X-Frame-Options: DENY`.

| Method & path | Role | Notes |
|---|---|---|
| `GET /healthz` | public | `{"ok": true}` |
| `POST /api/login` `{username,password,otp?}` | public | Per-IP rate limit, per-account lockout (5 failures → 15 min), one generic error. Returns `{token, expires}`. |
| `POST /api/logout`, `GET /api/me` | any | |
| `POST /api/totp/enroll`, `POST /api/totp/confirm {code}` | any | RFC 6238; used codes cannot be replayed. |
| `GET/POST /api/tenants` | read: any (own); create: superadmin | |
| `POST /api/users {username,password,role,tenant_id?}` | superadmin; tenant_admin (own tenant, not superadmin) | Password ≥ 12 chars, scrypt-hashed. |
| `GET/POST /api/assets {name,kind,address,tenant_id?}`, `DELETE /api/assets/{id}` | write: admin roles | `address` = IP or CIDR; overlaps with other tenants refused; prefix limits (tenant ≥ /16 v4, ≥ /32 v6). |
| `GET/POST /api/providers` | create: superadmin | `{name, kind:"webhook", config:{url, secret_env, allow_insecure_loopback?, timeout?}}`; secret is an env-var **name**. |
| `GET/POST /api/nodes {name,region,tenant_id?}` | write: admin roles | POST returns `node_id`, `auth_token`, `sign_key` **once**. |
| `PUT /api/nodes/{id}/policy {policy}` | admin roles | Validated like `protocolz_nft` policies; bumps `version`. |
| `GET /api/events?limit=` | any | Node-reported + control-plane events. |
| `GET /api/audit?limit=`, `GET /api/audit/verify` | admin roles; verify: superadmin | Hash-chained. |
| `GET/POST /api/mitigations {provider,target,reason?,ttl_seconds?}`, `DELETE /api/mitigations/{id}` | write: admin roles | Target must be inside the caller's own asset; request is sent to the provider normalized. |
| `GET /node/v1/policy` | node | Headers `X-Node-Id`, `Authorization: Bearer <auth_token>`. `200` signed envelope `{bundle:{node_id,version,policy}, sig}` or `204`. |
| `POST /node/v1/events {events:[{type,data}]}` | node | ≤ 100 events/batch, ≤ 2 KB data each. |

Policy JSON: `management_cidrs` (required), `ssh_port`, `allow_icmp`, `services[]` with `name, proto (tcp|udp), port, allow_cidrs, new_conn_rate, burst, per_source_rate, per_source_burst`.

Webhook provider contract: `POST` JSON `{action:"mitigate"|"withdraw", target|handle, reason, ttl_seconds}`; headers `X-ProtocolZ-Timestamp`,
`X-ProtocolZ-Signature: sha256=HMAC(secret, timestamp + "." + body)`; reply 2xx JSON with `{"handle": "..."}` for `mitigate`. Redirects are not followed.
