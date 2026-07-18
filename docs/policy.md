# Policy Engine

The policy engine decides what every flow is allowed to do: whether it is
permitted, which egress it uses, whether it is decrypted for inspection, and how
it is logged. It is **identity- and IP-aware** — rules match on who the user is
*and* on network attributes of the flow.

## Model

```
Policy (priority, default_action)
└── PolicyRule[]  (ordered; first match wins within a policy)
      match_*  ...conditions (ALL specified must match — logical AND)
      action   ...what to do
      action_params ...action arguments (e.g. redirect URL, egress node)
```

Policies are evaluated in ascending `priority`; within a policy, rules are
evaluated in `order` and the **first matching rule wins**. If no rule matches, the
policy's `default_action` applies.

## Match conditions

An empty condition means "any". A rule matches only if **every** populated
condition matches the flow.

| Field              | Matches on                                             |
|--------------------|--------------------------------------------------------|
| `match_roles`      | user's McNutt Cloud roles (any overlap)                |
| `match_users`      | user uid                                               |
| `match_src_cidrs`  | source IP ∈ CIDR                                        |
| `match_endpoints`  | specific endpoint id                                   |
| `match_node_roles` | processing node role (ingress/egress/connector)        |
| `match_dst_cidrs`  | destination IP ∈ CIDR                                   |
| `match_domains`    | SNI/DNS name (exact, suffix, or glob)                  |
| `match_categories` | classified category (streaming, malware, finance, …)   |
| `match_ports`      | destination port                                       |
| `match_protocols`  | tcp/udp/…                                               |
| `match_countries`  | GeoIP country of destination                           |
| `match_asns`       | destination ASN                                        |
| `match_time`       | time-of-day / day-of-week window                       |

## Actions

| Action       | Effect                                                        |
|--------------|--------------------------------------------------------------|
| `allow`      | permit (metadata only, no decryption)                        |
| `deny`       | drop; flow recorded with verdict `denied`                    |
| `inspect`    | force TLS MITM decryption for classification                 |
| `bypass`     | explicitly never inspect (e.g. banking, health)              |
| `steer`      | select egress/connector via `action_params`                  |
| `redirect`   | DNS/HTTP hijack to a URL in `action_params`                  |
| `block_page` | serve an explanatory block page                              |
| `log`        | record only, continue evaluation                             |
| `alert`      | raise an alert, continue                                      |

DNS-layer decisions map onto `DnsAction` (`resolve`, `block`, `redirect`,
`sinkhole`) — a `deny`/`block_page` rule matched at DNS time becomes a `block`.

## Evaluation surfaces

The same policy is enforced at two layers:

1. **Manager (authoritative).** `POST /api/v1/policy/evaluate` returns the
   decision for a given `PolicyContext` (user, roles, dst, category, …). Used for
   previews and server-side checks.
2. **Data plane (line rate).** `GET /node/policy` returns a compact `hints`
   bundle. The agent's `PolicyBundle` re-implements the same first-match-wins
   semantics so DNS filtering and per-flow verdicts happen locally without a round
   trip. The bundle is refreshed on the config poll interval and on the
   `policy.changed` realtime event.

## Example (seeded "Default Corporate Policy")

| Order | Match                       | Action        | Rationale                     |
|-------|-----------------------------|---------------|-------------------------------|
| 1     | category = malware/phishing | `block_page`  | Threat protection             |
| 2     | category = finance          | `bypass`      | No decryption of banking      |
| 3     | roles = contractor, category = social-media | `deny` | Contractor AUP     |
| 4     | category = web/uncategorized| `inspect`     | Decrypt for classification    |
| 5     | (default)                   | `allow`       | Default-allow with logging    |

## Authoring tips

* Put the most specific / highest-risk rules first (lowest `order`).
* Use `bypass` before any broad `inspect` to carve out privacy-sensitive traffic.
* Prefer `match_categories`/`match_domains` over raw CIDRs where possible — they
  survive IP churn and CDNs.
* `steer` + `action_params.egress_node` pins a flow to a specific internet exit
  (e.g. for geo-consistent egress IPs).
