# Agent Verification API

Confirms that an AI agent/service is who it claims to be. NEXUS candidate #3 -- **manual build, not
FORGE-generated**, extending the domain-verification engine already live in production on
`live-entity-verification` (Railway, free -- see below) with two new agent-specific signals.

- `POST /verify-agent-identity {"domain": "...", "entity_name": "...", "agent_endpoint_url": "..." (optional)}`
  -- charged **$0.35 via x402** (Base Sepolia testnet).
- MCP tool `verify_agent_identity` at `/mcp` -- **currently free**, see "Known limitations".
- `GET /health`, `GET /.well-known/agent-card.json`, `GET /openapi.json` (has `x-payment-info`).

## What it actually checks

Fuses two independent lenses into one verdict:

1. **Domain existence** (the `live-entity-verification` engine, ported unchanged -- WHOIS + Certificate
   Transparency + Wayback Machine + DNS operational maturity, fused with the same calibrated Bayesian priors).
2. **Agent liveness** (new, only runs if `agent_endpoint_url` is given): a real GET of
   `{agent_endpoint_url}/.well-known/agent-card.json`, and a real MCP `initialize` handshake at
   `{agent_endpoint_url}/mcp` -- not just an HTTP 200 check. Also verifies the agent-card's own declared `url`
   is bound to `domain` (catches an agent card hosted somewhere unrelated to the entity it claims to represent).

Verdicts, most-trusted first: `VERIFIED_LIVE_AGENT`, `VERIFIED_LIVE_DOMAIN_ONLY` (no `agent_endpoint_url`
given), `DOMAIN_VERIFIED_AGENT_UNREACHABLE`, `AGENT_DOMAIN_MISMATCH`, `LIKELY_HALLUCINATED_AGENT`,
`UNVERIFIED_AGENT`. Full semantics in the endpoint's own docstring / OpenAPI description.

## Why $0.35 (vs $0.01 for the sibling `url-metadata-api`)

Real cost per call is meaningfully higher: paid WHOIS lookup (~$0.002/call via Whoxy) plus 5-6 real outbound
checks (WHOIS, CT, Wayback, DNS, agent-card fetch, MCP handshake) instead of one fetch. $0.35 is the midpoint
of the $0.30-0.50 range for identity-verification-class services in the x402 ecosystem.

## Relationship to `live-entity-verification`

`live-entity-verification` (Railway, `live-entity-verification-production.up.railway.app`, free, no x402,
`asset_registry.status='active'` since 2026-08-20) is a **separate, still-live asset** -- this candidate reuses
its domain-verification code (ported into `main.py` here, not imported cross-service) but does not replace or
modify it. Don't touch that Railway service as part of work on this one without checking both.

## Deploy target: Cloud Run, not Railway

Same pipeline as candidate #4 (`url-metadata-api`) -- see `skills/infra-deploy-ops`.

```bash
# 1. First deploy -- PUBLIC_DOMAIN not known yet, every real request 421s until step 2.
./scripts/deploy_cloud_run.sh agent-verification-api manual_assets/agent-verification-api

# 2. Grab the printed *.run.app URL, then (only if it differs from env-vars.deploy.yaml's guess):
gcloud run services update agent-verification-api --region us-central1 --project nexus-505016 \
    --update-env-vars PUBLIC_DOMAIN=<the-real-domain>
```

No numpy/scipy dependency (removed after the first deploy attempt failed Cloud Buildpacks' Python-3.14
scipy source build, which needs a Fortran compiler not present in the build image -- `_fuse_signals_naive_bayes`/
`_compute_evidence_quality` use plain `math.log`/`math.exp`/a small `_clip` helper instead; the one `expit`
import from the original engine was actually unused dead code, dropped).

## Known limitations (left unfixed on purpose -- CLAUDE.md SS3, no gate without evidence it's needed)

- **MCP tool calls are not charged.** Same in-process-call pattern (and same reason) as `url-metadata-api`:
  the MCP tool calls the shared verification function directly, not via HTTP re-entry into the ASGI app.
- **No per-caller rate limiting.** Fine for a 7-day disposable measurement; add if it survives.
- **SSRF guard on `agent_endpoint_url`**: IP-range based pre-connect check (rejects private/loopback/
  link-local/reserved, including cloud metadata's `169.254.169.254`). The agent-card fetch uses
  `follow_redirects=False`. The MCP handshake uses a custom `httpx_client_factory` that also disables
  redirects (the MCP client library's own default factory hardcodes `follow_redirects=True` with no
  opt-out via the public `streamablehttp_client` signature -- found in this candidate's pre-deploy security
  review: a malicious server could otherwise pass the pre-connect check, then 307-redirect the actual MCP
  request to an internal target). Neither guard defends against DNS rebinding between the check and the
  actual connect (accepted risk, same as candidate #4).
- **`name_matches_card` is informational only**, not verdict-gating -- self-reported agent names vary in
  formatting often enough that a hard mismatch gate would produce false negatives on real agents.

## Pre-deploy quality gate (2026-08-22, from design not retroactive)

4 parallel review lenses ran against `main.py` before the first deploy. Real findings, all fixed before
shipping:

- **Security (critical)**: the MCP-handshake SSRF guard was bypassed by the `mcp` library's hardcoded
  `follow_redirects=True` default -- fixed via a custom `httpx_client_factory`.
- **Functional (critical)**: the ported DNS-maturity engine silently dropped 2 of 6 scoring components
  (DKIM, cross-resolver propagation consistency) despite the module docstring claiming an unchanged port --
  restored, and parallelized (was sequential, up to ~48s worst-case per call).
- **Functional**: `_classify_agent_verdict`'s reachability check used OR between agent-card-present and
  MCP-handshake-reachable, letting a dead MCP server with a stale-but-present agent-card pass as
  `VERIFIED_LIVE_AGENT` -- the exact "vaporware" case this asset exists to catch. Fixed to require the
  handshake specifically for the top verdict.
- **Code quality**: dead function, unused `signal_mask` threading, a dropped explanatory comment -- all
  cleaned up.
- **Buyer experience**: the REST response was undocumented in OpenAPI (`response_model` added), the 6-value
  verdict enum had no semantic explanation anywhere reachable pre-payment (added to the endpoint docstring),
  and the fact that a 400/422 is still charged (ASGI middleware settles before FastAPI validation runs) was
  underdisclosed (added to `agent-card.json`'s `protocol_note` and the endpoint docstring).

## Measurement (candidate #3, 7-day window)

7-day window from first real deploy (2026-08-22 -> decision point 2026-08-29). Source of truth:
`traffic_events`/`revenue_events`/`mcp_call_events` tables (`asset_name = 'agent-verification-api'`), not
Cloud Run logs. First real call already confirmed same-session: real x402 payment settled on-chain, real
`revenue_events` row (`amount_eur=0.35`, `pricing_model=x402`), verified against the live `url-metadata-api`
Cloud Run service as the test agent (agent-card fetched, real MCP handshake succeeded, domain-binding
confirmed). Day 7: if zero real traffic (filtering crawlers), pause/delete the Cloud Run service
(`gcloud run services delete agent-verification-api --region us-central1 --project nexus-505016`).
