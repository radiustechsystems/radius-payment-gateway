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
   signed, so this only catches a payment sent to the wrong route. A paid response carries
   `Cache-Control: private` (replacing a `public`) unless the upstream's already says `private`
   or `no-store`, so a shared cache can't give it to another buyer; challenges and the
   `settlement_unknown` answer carry `no-store`.

The challenge offers every payment option of the rule as the policy compiled it (network, token,
amount, recipient). What a buyer has to sign for a token (its transfer method and EIP-712 domain)
comes from the option's facilitator: the gateway reads `GET /supported` from every facilitator a
policy names when the policy loads, and again hourly. EIP-3009 is offered whenever the
facilitator settles it, as it does for SBC on Radius: one signature moves the tokens, with no
allowance to arrange. A token the facilitator only settles through Permit2 is offered that way,
with the `eip2612GasSponsoring` extension declared when the facilitator sponsors the approval.
When a facilitator can't be read, SBC on Radius still gets its EIP-3009 offer from a built-in
table; other tokens get an empty `extra`, which buyers can't sign.

## The payment page

A browser that opens a paid URL gets a page instead of JSON: every way the policy accepts
payment (SBC on Radius, USDC on Base, …), each with its price, network and recipient, and a
single button. **Connect wallet** connects an injected wallet (MetaMask or any EIP-1193 wallet)
and reads its balance for each option from that network's public RPC, marking what the wallet
can and can't cover and selecting the first option it can. The button then pays the selected
option: the wallet is asked to switch to (or add) that network, signs the payment, the page
sends it and reloads once the gateway has settled it. Options paid only through Permit2 are
listed but marked "terminal only". Below the button, collapsed, are the `radius-cli` command
for a terminal (with `--networks radius,base` when Base is offered) and the raw challenge for a
program. Agents, SDKs and `radius-cli` never see the page: the body is HTML only when the
request's `Accept` prefers `text/html` over `application/json`, and the `PAYMENT-REQUIRED`
header is the same either way.

The reload is delivered through a **ticket**: when a payment sent from the page settles, the
paid response carries a `radius_ticket` cookie (single use, bound to the exact method and URL,
60 seconds, `HttpOnly`, `SameSite=Strict`, `Secure` over https). The reload presents it, the
gateway strips it, forwards the request once without charging or counting it, and clears the
cookie. A reload the upstream fails to answer keeps the ticket; a ticket used, expired, or
presented for another URL falls back to the normal policy answer. The upstream therefore sees
two GETs for a browser purchase: the paid one, whose body the browser discards and which carries
`Radius-Page: 1`, and the reload. The page pays EIP-3009 offers; a token offered only through
Permit2 can still be paid from the terminal.

### Customizing the page

The page and its assets are files inside the binary. To change them, export them and point the
gateway at the directory:

```sh
radius-gateway --export-pages ./pages
# edit pages/402.html, pages/assets/style.css, pages/assets/pay.js, add images under assets/
radius-gateway --pages-dir ./pages …
```

Files in the directory replace the built-in ones by name; the rest stay built in. `402.html`
is a template with `{{placeholders}}`, every one escaped for HTML: `brand`, `brand_url`,
`brand_html` (the brand line, ready to drop in), `price` (`0.01 SBC`), `amount` (`0.01`),
`asset_symbol`, `description` (the rule's), `resource_url`, `network_name`, `pay_to`, `error`
(empty on a plain challenge; the facilitator's reason after a refused payment), `cli_command`,
`options_html` (the ways to pay as a radio group the script drives), `challenge_json` and
`page_json` (for the `<script type="application/json">` blocks `x402-challenge` and
`x402-page` the script reads: the challenge, and each option's token, decimals and network
with its RPC and explorer), and `assets_base` (where `assets/` is served). The headline
variables `price`, `network_name` and `pay_to` describe the first option a browser can pay. Everything under `assets/` is
served at `/_radius/assets/` with an `ETag` and a five-minute cache lifetime, before the policy
sees the request, so a catch-all `charge` rule never charges the page's own files. The prefix is
reserved: an upstream route under `/_radius/` can't be reached through the gateway. The page is
served with a Content Security Policy that only allows scripts and styles from `/_radius/assets/`
and connections to the gateway and the offered networks' RPCs, so keep scripts and styles there
rather than inline. `--brand` and `--brand-url` put a name at the top of the
default page.

`node --test pages/assets/pay.test.mjs` checks the script's pure parts; the wallet flow itself
is tested by hand with MetaMask on Radius testnet.

Error responses are JSON `{"code": "…", "message": "…"}`:

| Situation | Status | `code` |
| --- | --- | --- |
| `PAYMENT-SIGNATURE` isn't a base64 JSON payload | 400 | `invalid_payment` |
| Percent-decoding the path would select another rule | 400 | `ambiguous_path` |
| Payment required, or a payment that wasn't accepted / named another resource / didn't verify / was refused at settlement | 402 | (the body is the x402 challenge, with `error`) |
| Unmatched request under `unmatched: deny` | 403 | `no_matching_rule` |
| Over a rate limit | 429 | `rate_limited` |
| Upstream unreachable / didn't answer in time | 502 / 504 | `upstream_unavailable` / `upstream_timeout` |
| Facilitator unreachable at `/verify`, or answered a 5xx, a redirect (never followed) or without a verdict | 502 | `facilitator_unavailable` |
| Settlement's outcome unknown: `settlement_pending`, a failure other than `invalid_transaction_state` that names a transaction, or no verdict from `/settle` (timeout, 5xx, redirect). The content is withheld, the payment stays claimed, `PAYMENT-RESPONSE` carries the transaction when there is one, and a repeat of the payment gets the same answer | 503 | `settlement_unknown` |
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
| `--startup-policy-wait` | `STARTUP_POLICY_WAIT` | `5s` | How long startup waits for the first policy. Until one loads, a failed fetch is retried after 1s, doubling up to 15s |
| `--public-url` | `PUBLIC_URL` | | The URL buyers reach you at (`https://api.example.com`), the base of `resource.url` in challenges. Set it in production |
| `--no-policy` | `NO_POLICY` | `deny` | What happens before the first policy loads: `deny` (503) or `allow` (every request is forwarded, paid routes free) |
| `--max-timeout-seconds` | `MAX_TIMEOUT_SECONDS` | `60` | `maxTimeoutSeconds` offered to buyers |
| `--facilitator-timeout` | `FACILITATOR_TIMEOUT` | `20s` | Per `/verify` or `/settle` call |
| `--paid-body-limit` | `PAID_BODY_LIMIT` | `10485760` | Bytes of a paid response buffered before settling; larger responses settle on status and stream |
| `--claim-ttl` | `CLAIM_TTL` | `24h` | How long a used payment stays claimed |
| `--pages-dir` | `PAGES_DIR` | | A directory of page files overriding the built-in ones (see "Customizing the page") |
| `--export-pages` | | | Write the built-in page files to a directory and exit |
| `--brand` | `BRAND` | | A name shown at the top of the payment page |
| `--brand-url` | `BRAND_URL` | | Where the brand name links to |
| `--log-filter` | `RUST_LOG` | `info,radius_gateway=debug` | |
| `--log-format` | `LOG_FORMAT` | `text` | `text` or `json` |

```sh
UPSTREAM=http://127.0.0.1:3000 \
PLATFORM_API_KEY=sk_… ORGANIZATION_ID=org_… PROJECT_ID=… \
PUBLIC_URL=https://api.example.com \
radius-gateway
```

### Docker

A published image is built from `main` and from version tags:

```sh
docker run --rm -p 127.0.0.1:8080:8080 -p 127.0.0.1:9901:9901 \
  -e UPSTREAM=http://host.docker.internal:3000 \
  -e PLATFORM_API_KEY=sk_… -e ORGANIZATION_ID=org_… -e PROJECT_ID=… \
  -e PUBLIC_URL=https://api.example.com \
  ghcr.io/radiustechsystems/radius-gateway:main
```

Or build it yourself; the image runs the gateway as a non-root user in a distroless image:

```sh
docker build --build-arg RADIUS_GATEWAY_COMMIT=$(git rev-parse --short=9 HEAD) \
  -t radius-gateway .

docker run --rm … radius-gateway
```

Or with compose: copy `.env.example` to `.env`, fill it in, then `docker compose build` and
`docker compose up -d`. Inside the container the gateway listens on `0.0.0.0:8080` and the admin
listener on `0.0.0.0:9901`; publish the admin port on loopback only, as the compose file does,
since it's unauthenticated. `host.docker.internal` reaches an API running on the Docker host.
To customize the payment page, mount a directory, export the built-in files into it with
`--export-pages`, and set `PAGES_DIR`.

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
- `GET /version`: the crate version and git commit this binary was built from, as
  `{"build": "0.1.0+abc123def"}`. The same id is in `--version`, the startup log line, the
  `/policy` answer, the `radius-gateway` header of every 402, and a comment at the top of the
  payment page, so a deployment can be checked with `curl -sI … | grep radius-gateway`. A build
  from a modified tree says `-dirty`; one without a checkout says `unknown`, or what
  `RADIUS_GATEWAY_COMMIT` was set to.
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
- Tickets live with the counters, per instance: a reload that lands on another replica pays
  again.
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

The policy evaluator (the platform's `policy` and `domain` crates) is vendored under
`vendor/radius-platform/` from the `radius-platform` repository at the commit in
`vendor/radius-platform/COMMIT`, together with the conformance vectors in `tests/vectors/`. To
move to a newer platform commit:

```sh
scripts/vendor-platform.sh ../radius-platform <commit>
```

then check `vendor/radius-platform/Cargo.toml` (the stand-in for the platform's workspace) still
declares what the crates inherit, and run the tests. `policy::Compiled` rejects fields it doesn't
know, so when the platform adds a field this gateway logs `update the pinned radius-platform
revision` and keeps enforcing the policy it has until the vendored copy is refreshed. Watch the
platform's `docs/gates/changes.md`.

## License

MIT.
