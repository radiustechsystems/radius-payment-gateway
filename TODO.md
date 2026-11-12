# TODO

What the gateway doesn't do yet, roughly in the order it's worth doing. Each item says what
changes and what it unblocks.

## Shared store for counters, claims and tickets

Rate limits, free quotas, the payment replay guard and page tickets live in the process's
memory (`src/counters/memory.rs`). With two replicas a limit applies twice, a payment can be
replayed once per replica, and a reload that lands on another replica pays again. Add a Redis
implementation of `CounterStore`, `ClaimGuard` and `TicketStore` (`src/counters/mod.rs`): an
atomic `INCR` with `EXPIRE` for counters, `SET NX EX` for claims and tickets, a `GETDEL` for
redeeming. Selected by a `--store redis://…` flag; the memory store stays the default. Unblocks
running more than one replica.

## Multi-project

One gateway serves one project (`AppState.gates` has one entry, `select_gate` returns it).
List the organization's projects (`GET /organizations/{org}/projects`, `projects:read`), run one
policy poller and one upstream per project, and route a request to its gate by `Host` (each
project's `base_url` from the listing, or a `--project <id>=<host>=<upstream>` list). The gate
standard has no "all projects" document, so it stays one compiled policy per project. Unblocks
one deployment in front of several APIs.

## Prometheus metrics

The admin listener has `/healthz`, `/readyz`, `/policy` and `/version` but no `/metrics`. Count
requests by decision (`allow`, `deny:<code>`, `payment_required`, `paid`, `ticket`,
`settlement_unknown`), rule id and status; time upstream and facilitator calls; expose the
loaded policy's version and age and the time of the last successful fetch (gate standard,
section 7). Low cardinality: rule ids and route patterns, never paths or addresses.

## Web Bot Auth

`radius.policy/0.2` rules that match on `agent` never match: the gate sends `agent: None`.
Verify RFC 9421 signatures against the key directories of the origins a policy names
(`match.agent.signature_agent`), as the standard's section 4.1 describes, and count
`key: agent` limits by the verified origin. Cloudflare's verified-bot categories aren't
available outside Workers, so `category` stays unverified. Unblocks agent-specific pricing.

## WebSocket passthrough

`Upgrade` is a hop-by-hop header the proxy strips, so WebSocket and other upgrades fail. Decide
the policy semantics first (charge the upgrade request once, then pass the connection through),
then forward the upgrade with hyper's `on_upgrade` on both sides and copy bytes.

## Smaller

- The signed-terms check (`PaymentRequirements::signed_mismatch`) reads `authorization.to` as
  the recipient, which holds for EIP-3009 but not for Stablecoin.xyz's `erc2612` method, where
  it's the settlement wallet. Apply the `authorization` branch only when `assetTransferMethod`
  is `eip3009` or absent.
- `OPTIONS` goes through the policy, so a catch-all `charge` rule charges CORS preflights.
  Decide whether the gateway should answer preflights itself for browser clients.
- Permit2 signing on the payment page is only needed for the SBC test deployment on Base
  Sepolia (`0xf9FB…0F16`), which lacks EIP-3009 (its `transferWithAuthorization` functions
  revert, and the testnet facilitator offers it through Permit2 only). SBC on Base mainnet
  (`0xfdcC…0798`) implements EIP-3009 and the mainnet facilitator settles it that way, as do SBC
  on Radius and USDC on both Base networks. Redeploying the Base Sepolia test token with
  EIP-3009 would make the page cover every option without Permit2.

## Elsewhere

- `radius-platform`: the gate standard amendment (no-policy default, settlement outcomes,
  claim keys) is in review; the platform SDK then needs the same settlement semantics and
  Permit2 claim keys.
