# radius-payment-gateway

A reverse proxy that enforces a [Radius Platform](https://platform-api.radiustech.xyz) compiled
policy in front of an API. It sits behind your TLS terminator (nginx, Caddy) and in front of your
service, and for every request decides what the project's policy says: forward it, refuse it,
rate-limit it, or charge for it with [x402](https://github.com/x402-foundation/x402) (version 2,
HTTP transport, the `exact` scheme).

```
client ── https ──▶ nginx ── http ──▶ radius-gateway ── http ──▶ your API
                                          │
                                          ├── polls  platform-api.radiustech.xyz  (compiled policy)
                                          └── calls  the policy's facilitator     (/verify, /settle)
```

It implements the platform's [gate standard](https://github.com/radiustechsystems/radius-platform/blob/main/docs/gates/standard.md)
and embeds the platform's reference evaluator (`crates/policy`), so matching, limits and
decisions are the reference implementation. Accepted policy formats: `radius.policy/0.1` and
`radius.policy/0.2` (logged at startup).

## What it does with a request

1. Reads the policy in force (lock-free; fetched in the background, never while handling a
   request).
2. Selects the first rule whose `match` holds, counts the request against the rule's rate limit
   and free quota, and decides. HEAD is evaluated as GET.
3. `allow`: forwards to the upstream, streaming both ways, with `RateLimit-*` headers when the
   rule has a limit. `deny`: answers the rule's status with `{"code": …}`. Unmatched requests get
   `defaults.unmatched`.
4. `charge`: answers `402` with a `PAYMENT-REQUIRED` challenge. A retry carrying
   `PAYMENT-SIGNATURE` is matched against the offer, claimed against replay, verified with the
   option's facilitator, forwarded, and settled after a 2xx. The response carries
   `PAYMENT-RESPONSE`. An upstream error is never charged, and a payment whose request ends
   before `/settle` is called (an upstream error, a buyer that disconnects) can be tried again.
   A payment that names a `resource.url` must name this request's, the URL its challenge gives,
   compared as URLs (scheme and host in any case, a default port or not); the field isn't
   signed, so this only catches a payment sent to the wrong route.

The challenge offers every payment option of the rule as the policy compiled it (network, token,
amount, recipient). What a buyer has to sign for a token (its transfer method and EIP-712 domain)
comes from the option's facilitator: the gateway reads `GET /supported` from every facilitator a
policy names when the policy loads, and again hourly. On Radius that means SBC through Permit2
with the `eip2612GasSponsoring` extension declared, so a wallet holding only SBC can pay with no
approval transaction. When a facilitator can't be read, SBC on Radius still gets the Permit2
offer from a built-in table; other tokens get an empty `extra`, which buyers can't sign.

Error responses are JSON `{"code": "…", "message": "…"}`:

| Situation | Status | `code` |
| --- | --- | --- |
| `PAYMENT-SIGNATURE` isn't a base64 JSON payload | 400 | `invalid_payment` |
| Percent-decoding the path would select another rule | 400 | `ambiguous_path` |
| Payment required, or a payment that wasn't accepted / named another resource / didn't verify / was refused at settlement | 402 | (the body is the x402 challenge, with `error`) |
| Unmatched request under `unmatched: deny` | 403 | `no_matching_rule` |
| Over a rate limit | 429 | `rate_limited` |
| Upstream unreachable / didn't answer in time | 502 / 504 | `upstream_unavailable` / `upstream_timeout` |
| Facilitator unreachable at `/verify`, or answered a 5xx or without a verdict | 502 | `facilitator_unavailable` |
| Settlement's outcome unknown: `settlement_pending`, a failure other than `invalid_transaction_state` that names a transaction, or no verdict from `/settle` (timeout, 5xx). The content is withheld, the payment stays claimed, `PAYMENT-RESPONSE` carries the transaction when there is one, and a repeat of the payment gets the same answer | 503 | `settlement_unknown` |
| No policy ever loaded, under `NO_POLICY=deny` (the default) | 503 | `policy_unavailable` |
| The claim store failed | 503 | `payment_unavailable` |

## Running it

Every setting is a flag or an environment variable; flags win.

| Flag | Env | Default | Meaning |
| --- | --- | --- | --- |
| `--listen` | `LISTEN` | `0.0.0.0:8080` | Where nginx sends traffic |
| `--admin-listen` | `ADMIN_LISTEN` | `127.0.0.1:9901` | `/healthz`, `/readyz`, `/policy`, `POST /policy/refresh`. Unauthenticated: keep it private |
| `--upstream` | `UPSTREAM` | required | Your API: `http://127.0.0.1:3000`, `https://api.internal/v1` (a path is a prefix) |
| `--upstream-timeout` | `UPSTREAM_TIMEOUT` | `30s` | Time to the upstream's response headers, and again to the buffered part of a paid response's body |
| `--upstream-connect-timeout` | `UPSTREAM_CONNECT_TIMEOUT` | `5s` | |
| `--platform-api-url` | `PLATFORM_API_URL` | `https://platform-api.radiustech.xyz` | |
| `--platform-api-key` | `PLATFORM_API_KEY` | required | An organization API key with `endpoints:read` |
| `--organization-id` | `ORGANIZATION_ID` | required | `org_…` |
| `--project-id` | `PROJECT_ID` | required | The project whose policy is enforced |
| `--poll-interval` | `POLL_INTERVAL` | `30s` | How often to ask for a newer policy (at least `1s`) |
| `--startup-policy-wait` | `STARTUP_POLICY_WAIT` | `5s` | How long startup waits for the first policy |
| `--public-url` | `PUBLIC_URL` | | The URL buyers reach you at (`https://api.example.com`), the base of `resource.url` in challenges. Set it in production |
| `--no-policy` | `NO_POLICY` | `deny` | What happens before the first policy loads: `deny` (503) or `allow` (every request is forwarded, paid routes free) |
| `--max-timeout-seconds` | `MAX_TIMEOUT_SECONDS` | `60` | `maxTimeoutSeconds` offered to buyers |
| `--facilitator-timeout` | `FACILITATOR_TIMEOUT` | `20s` | Per `/verify` or `/settle` call |
| `--paid-body-limit` | `PAID_BODY_LIMIT` | `10485760` | Bytes of a paid response buffered before settling; larger responses settle on status and stream |
| `--claim-ttl` | `CLAIM_TTL` | `24h` | How long a used payment stays claimed |
| `--log-filter` | `RUST_LOG` | `info,radius_gateway=debug` | |
| `--log-format` | `LOG_FORMAT` | `text` | `text` or `json` |

```sh
UPSTREAM=http://127.0.0.1:3000 \
PLATFORM_API_KEY=sk_… ORGANIZATION_ID=org_… PROJECT_ID=… \
PUBLIC_URL=https://api.example.com \
radius-gateway
```

An nginx site in front of it:

```nginx
server {
    listen 443 ssl;
    server_name api.example.com;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;
    }
}
```

The policy's `defaults.client_ip` decides which address rate limits key on: `remote_addr` is the
connection's peer (nginx), `{ "header": "X-Forwarded-For" }` reads the header nginx sets. Only
run the gateway directly on the internet with `remote_addr`.

### Admin endpoints

- `GET /healthz`: the process is up.
- `GET /readyz`: a policy is loaded (or requests pass through without one).
- `GET /policy`: the loaded policy's version, age and project, and how fetching is going.
- `POST /policy/refresh`: fetch now, outside the schedule.

### Logging

One line per request with the policy version, the deciding rule, the decision (`allow`,
`deny:<code>`, `payment_required`, `paid`, …) and the status; a settled payment logs its
transaction hash, network and payer. `PAYMENT-SIGNATURE`, `Authorization` and payment payloads
are never logged.

## Limits

- **Counters and claims are per instance.** Rate limits, free quotas and the payment replay
  guard live in the process's memory. With two replicas, a limit applies twice and a payment could
  be replayed once per replica. Run one replica until a shared store (Redis) is added.
- WebSockets and other upgrades aren't proxied.
- `OPTIONS` goes through the policy like any method; a catch-all `charge` rule charges it. Add an
  `allow` rule for preflight routes if browsers call the API directly.
- `radius.policy/0.2` agent rules (`match.agent`) never match: the gateway has no way to verify
  an agent's identity yet.

## Development

```sh
cargo test            # unit, integration and conformance tests
cargo clippy --all-targets
```

The policy evaluator comes from the private `radius-platform` repository, pinned by revision in
`Cargo.toml`; both `policy` and `domain` must point at the same revision. Fetching uses the git
CLI (`.cargo/config.toml`), so your ssh setup applies. To build against a local checkout,
uncomment the `[patch]` block in `.cargo/config.toml`.

`policy::Compiled` rejects fields it doesn't know. When the platform adds a field, this gateway
logs `update the pinned radius-platform revision` and keeps enforcing the policy it has until the
pin is bumped. Watch the platform's `docs/gates/changes.md`.

The conformance vectors in `tests/vectors/` are copied from the platform at the commit in
`tests/vectors/VECTORS_COMMIT`; copy them again when bumping the pin.
