# policy

`radius.policy/0.1` and `0.2` (which adds `match.agent`): how a project decides what happens to each request to its endpoints. Pure
Rust, no IO and no async.

- **Authored form** (`spec`): what sellers write, as YAML or JSON (canonical), and what the
  platform stores. Defaults, then rules grouped under the endpoint they're for
  (`endpoints.<slug>.rules`), plus top-level `rules` for every endpoint (an IP block, a
  first-party allow), which are tried first. A rule is a `match`, an optional `rate_limit`
  (beyond it, requests are denied with `429 rate_limited`), an optional `free_quota` (within it,
  requests are allowed free) and an `action` (`allow`, `deny` or `charge`; `x402`, its former name, is still read) for the rest. Rule ids are unique within their list.
- **Compiled form** (`compiled`): one self-contained document per project that enforcement points
  (gates) read; what they must do with it is in `docs/gates/` at the repository root, and changes to
  either form follow `docs/gates/changes.md`. Endpoints, windows, wallets, prices (in each token's atomic units), decimals and
  facilitators are resolved, so evaluating it needs no lookups. Networks without a facilitator
  (Base, for now) are refused. It is the wire contract. Its
  rules are one ordered list: the top-level rules, then each endpoint's, named
  `<endpoint>/<id>` (`tx-lookup/freemium`), the most specific route's first (a literal segment
  before `:name`, `:name` before a trailing `*`; `domain::matching::cmp_specificity`). Where a
  less specific endpoint's rules would follow, an endpoint's rules end with
  `<endpoint>/_unmatched`, which gives its other requests `defaults.unmatched`. So a request is
  governed by the most specific endpoint it matches and never falls through to another
  endpoint's rules, and gates need only first-match.
- **Compiler** (`compile`): `compile(&spec, &context)` checks a policy against the project's
  endpoints and the organization's wallets (loaded by the caller) and returns the compiled form,
  or every problem keyed by field (`rules[1].match.ip_in[0]`,
  `endpoints.tx-lookup.rules[0].free_quota.window`). `warnings(&spec)` lists rules that can
  never apply, and `overlaps(&spec, &endpoints)` endpoints whose route overlaps a less specific
  one with rules, saying which endpoint's rules govern the requests both match.

- **Evaluator** (`eval`): the reference implementation of the compiled form, in two pure steps.
  `select(&compiled, &request)` finds the deciding rule and, when it has a rate limit or a free
  quota, the counters to increment (the rate limit's, then the free quota's);
  `decide(&compiled, &count, &counts)` turns the new counts (or the counter store's failures) into
  an allow, a deny with status, code and headers, or a payment requirement.

## Schemas

`schema/radius.policy-0.2.schema.json` (authored) and
`schema/radius.policy-0.2.compiled.schema.json` (compiled) are generated from the types with
schemars and checked in. They describe the newest version, `0.2`, and read `0.1` documents too,
since `0.2` only adds fields and values. A test fails when they drift; regenerate them with:

```sh
UPDATE_SCHEMAS=1 cargo test -p policy --test schema
```

## Tests

- `tests/compile.rs` compiles `tests/fixtures/example.yaml` and snapshots the result.
- `tests/errors.rs` covers every validation error and the warnings about rules.
- `tests/overlaps.rs` covers overlapping endpoints: the compiled order, `_unmatched` rules,
  pricing.md's listings and the overlaps.
- `tests/vectors/*.json` are the conformance vectors (format in `tests/vectors/README.md`);
  `tests/vectors.rs` runs them against the reference evaluator.
- `tests/eval_properties.rs` checks that evaluation never panics.
- `tests/conversion.rs` checks, as a property, that USD prices convert exactly to every catalog
  token's atomic units, including 18-decimal SBC on Base.
