"""
agent-verification-api -- NEXUS candidate #3 (manual build, no FORGE).

Confirms that an AI agent/service is who it claims to be: fuses the
Bayesian domain-existence engine already live on `live-entity-verification`
(Railway, free, ported here unchanged -- see core/live_entity_verification_api.py
in output/live_entity_verification/) with two agent-specific signals that
domain checks alone can't give: does a real .well-known/agent-card.json
exist and is it bound to the claimed domain, and does a real MCP server
actually answer an `initialize` handshake at the claimed endpoint. A
domain can be perfectly real (registered, indexed, DNS-mature) while the
"agent" squatting on it is vaporware, or a real agent's identity card can
be hosted on a domain that has nothing to do with the entity it claims to
represent -- this is the gap this asset closes.

Built from manual_assets/url-metadata-api/main.py's structure (MCP + x402
+ FastAPI, one process, Cloud Run target) -- same SSRF-guard convention,
same telemetry helpers, same x402 wiring. See skills/infra-deploy-ops and
skills/x402-payments for the gotchas this inherits (DNS-rebinding
allowlist, x402 does not cover MCP tool calls by default, self-payment
payTo bug, version pins, proxy-headers for correct resource.url scheme).
"""

import asyncio
import base64
import ipaddress
import math
import os
import re
import socket
import sys
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Annotated, Literal, Optional
from urllib.parse import urljoin, urlparse

import dns.resolver
import httpx
from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, HTTPException, status
from fastapi.openapi.utils import get_openapi as _fastapi_get_openapi
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import BaseModel, Field, field_validator

from x402.http import FacilitatorConfig, HTTPFacilitatorClient, PaymentOption
from x402.http.middleware.fastapi import PaymentMiddlewareASGI
from x402.http.types import RouteConfig
from x402.mechanisms.evm.exact import ExactEvmServerScheme
from x402.schemas import Network
from x402.server import x402ResourceServer

_NEXUS_ASSET_NAME = "agent-verification-api"

# ---------------------------------------------------------------
# Supabase telemetry -- ported by hand from manual_assets/url-metadata-api
# (this asset is manual, not FORGE-generated). anon key only, never
# service_role -- RLS on traffic_events/mcp_call_events/revenue_events is
# INSERT-only for anon, the only real protection if this key leaks from
# the deployed runtime.
# ---------------------------------------------------------------
_NEXUS_SUPABASE_URL = os.getenv("SUPABASE_URL")
_NEXUS_SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY")

_nexus_bg_tasks: set = set()


def _nexus_fire_and_forget(coro):
    task = asyncio.create_task(coro)
    _nexus_bg_tasks.add(task)
    task.add_done_callback(_nexus_bg_tasks.discard)
    return task


def _nexus_truncate_ip(raw_ip: Optional[str]) -> Optional[str]:
    if not raw_ip:
        return None
    if ":" in raw_ip and "." not in raw_ip:
        segments = [s for s in raw_ip.split(":") if s]
        head = segments[:4] if len(segments) >= 4 else segments
        return (":".join(head) + "::/64") if head else None
    octets = raw_ip.split(".")
    if len(octets) == 4 and all(o.isdigit() for o in octets):
        return f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
    return None


async def _nexus_supabase_insert(table: str, payload: dict) -> None:
    if not _NEXUS_SUPABASE_URL or not _NEXUS_SUPABASE_ANON_KEY:
        return
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            await client.post(
                f"{_NEXUS_SUPABASE_URL}/rest/v1/{table}",
                json=payload,
                headers={
                    "apikey": _NEXUS_SUPABASE_ANON_KEY,
                    "Authorization": f"Bearer {_NEXUS_SUPABASE_ANON_KEY}",
                    "Content-Type": "application/json",
                    "Prefer": "return=minimal",
                },
            )
    except Exception as e:
        print(f"[WARN] Supabase insert to {table!r} failed: {e}", file=sys.stderr)


async def _nexus_log_mcp_call_event(tool_id: str, success: bool, latency_ms: int) -> None:
    await _nexus_supabase_insert("mcp_call_events", {
        "tool_id": tool_id,
        "asset_name": _NEXUS_ASSET_NAME,
        "success": success,
        "latency_ms": latency_ms,
        "agent_framework": "mcp",
        "price_charged": 0,  # MCP path is free today -- see README "Known limitations"
    })


# ---------------------------------------------------------------
# SSRF guard -- both the agent-card fetch and the MCP handshake connect
# to a caller-supplied URL server-side. Resolve the hostname BEFORE
# connecting and reject private/loopback/link-local/reserved ranges.
# Ported verbatim from manual_assets/url-metadata-api/main.py.
# ---------------------------------------------------------------
def _nexus_validate_public_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(400, "agent_endpoint_url must be http(s)")
    if not parsed.hostname:
        raise HTTPException(400, "agent_endpoint_url has no hostname")
    try:
        addrs = socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror:
        raise HTTPException(400, f"Could not resolve host: {parsed.hostname}")
    for family, _, _, _, sockaddr in addrs:
        ip = ipaddress.ip_address(sockaddr[0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            raise HTTPException(400, "agent_endpoint_url resolves to a non-public address")


# =================================================================
# Domain-existence engine -- ported unchanged from
# output/live_entity_verification/core/live_entity_verification_api.py
# (live on Railway as the free `live-entity-verification` asset since
# 2026-08-20). Do not re-tune the priors here without re-tuning them
# there too -- they're calibrated against the same corpus.
# =================================================================

_PRIOR_WHOIS_PRESENT = (42.0, 3.0)
_PRIOR_WHOIS_ABSENT = (2.0, 31.0)
_PRIOR_CT_PRESENT = (38.0, 5.0)
_PRIOR_CT_ABSENT = (5.0, 28.0)
_PRIOR_WAYBACK_PRESENT = (33.0, 6.0)
_PRIOR_WAYBACK_ABSENT = (7.0, 24.0)
_PRIOR_DNS_MATURE = (22.0, 8.0)
_PRIOR_WEAK_NEUTRAL = (12.0, 12.0)
_PRIOR_WHOIS_YOUNG = (7.0, 15.0)

_MIN_POSITIVE_SIGNALS = 2

_DOMAIN_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)


def _validate_domain(domain: str) -> str:
    domain = domain.strip().lower()
    if not _DOMAIN_RE.match(domain):
        raise ValueError(f"Domain '{domain}' is not a valid FQDN")
    return domain


def _beta_mean(alpha: float, beta: float) -> float:
    return alpha / (alpha + beta)


def _clip(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def _fuse_signals_naive_bayes(signal_weights: list, uniform_prior: float = 0.5) -> float:
    if not signal_weights:
        return uniform_prior
    log_real = math.log(uniform_prior)
    log_fake = math.log(1.0 - uniform_prior)
    for w in signal_weights:
        w = _clip(w, 1e-9, 1.0 - 1e-9)
        log_real += math.log(w)
        log_fake += math.log(1.0 - w)
    max_log = max(log_real, log_fake)
    real_exp = math.exp(log_real - max_log)
    fake_exp = math.exp(log_fake - max_log)
    return real_exp / (real_exp + fake_exp)


def _compute_evidence_quality(signals_evaluated: dict, posterior: float) -> float:
    coverage = len(signals_evaluated) / 4.0
    p = _clip(posterior, 1e-9, 1.0 - 1e-9)
    entropy_norm = 1.0 - (-(p * math.log(p) + (1 - p) * math.log(1 - p)) / math.log(2))
    polarization = abs(posterior - 0.5) * 2.0
    quality = 0.35 * coverage + 0.40 * polarization + 0.25 * entropy_norm
    return _clip(quality, 0.0, 1.0)


def _classify_failure_mode(posterior: float, evidence_quality: float,
                            confidence_threshold: float, signals_present: list,
                            whois_absent: bool, all_signals: list) -> str:
    positive_count = sum(1 for s in signals_present if s in all_signals)
    return (
        'signals_missing' if len(all_signals) == 0
        else 'insufficient_corroboration' if evidence_quality < confidence_threshold
        else 'verified_live' if (posterior >= 0.70 and positive_count >= _MIN_POSITIVE_SIGNALS)
        else 'likely_hallucinated' if (posterior <= 0.30 and whois_absent)
        else 'obscured_or_new_entity' if (0.30 < posterior < 0.70)
        else 'insufficient_corroboration'
    )


_WHOXY_API_URL = 'https://api.whoxy.com/'
_RDAP_API_URL = 'https://rdap.org/domain/'


async def _fetch_whois_whoxy(domain: str, api_key: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(_WHOXY_API_URL, params={'key': api_key, 'whois': domain})
            resp.raise_for_status()
            data = resp.json()
    except httpx.TimeoutException:
        return {'error_code': 'whois_timeout', 'present': False}
    except httpx.HTTPStatusError as exc:
        return {'error_code': f'whois_http_{exc.response.status_code}', 'present': False}
    except Exception as exc:
        return {'error_code': f'whois_error:{type(exc).__name__}', 'present': False}

    if data.get('status') != 1:
        return {'error_code': 'whoxy_no_coverage', 'present': False}
    if data.get('domain_registered') != 'yes':
        return {'error_code': 'whois_no_record', 'present': False, 'whois_source': 'whoxy'}

    creation = data.get('create_date')
    age_days = None
    if creation:
        try:
            created_dt = datetime.fromisoformat(creation)
            created_dt = created_dt.replace(tzinfo=timezone.utc) if created_dt.tzinfo is None else created_dt
            age_days = (datetime.now(timezone.utc) - created_dt).days
        except Exception:
            pass

    return {
        'present': True,
        'creation_date': creation,
        'age_days': age_days,
        'whois_source': 'whoxy',
    }


async def _fetch_whois_rdap(domain: str) -> dict:
    request_url = f'{_RDAP_API_URL}{domain}'
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            resp = await client.get(request_url)
    except Exception as exc:
        return {'error_code': f'rdap_error:{type(exc).__name__}', 'present': False}

    redirected_to_registry = str(resp.url) != request_url

    if resp.status_code == 404:
        if redirected_to_registry:
            return {'error_code': 'whois_no_record', 'present': False, 'whois_source': 'rdap'}
        return {'error_code': 'rdap_no_coverage', 'present': False}
    if resp.status_code != 200:
        return {'error_code': f'rdap_http_{resp.status_code}', 'present': False}

    try:
        data = resp.json()
    except Exception as exc:
        return {'error_code': f'rdap_parse_error:{type(exc).__name__}', 'present': False}

    registration_dates = [
        ev.get('eventDate') for ev in (data.get('events') or [])
        if ev.get('eventAction') == 'registration'
    ]
    creation = registration_dates[-1] if registration_dates else None
    age_days = None
    if creation:
        try:
            created_dt = datetime.fromisoformat(creation.replace('Z', '+00:00'))
            created_dt = created_dt.replace(tzinfo=timezone.utc) if created_dt.tzinfo is None else created_dt
            age_days = (datetime.now(timezone.utc) - created_dt).days
        except Exception:
            pass

    return {
        'present': True,
        'creation_date': creation,
        'age_days': age_days,
        'whois_source': 'rdap',
    }


async def _fetch_whois(domain: str) -> dict:
    api_key = os.getenv('WHOXY_API_KEY')
    if api_key:
        whoxy_result = await _fetch_whois_whoxy(domain, api_key)
        if whoxy_result.get('present') or whoxy_result.get('error_code') == 'whois_no_record':
            return whoxy_result

    rdap_result = await _fetch_whois_rdap(domain)
    return rdap_result


async def _fetch_ct_presence(domain: str) -> dict:
    url = 'https://crt.sh/'
    params = {'q': domain, 'output': 'json'}
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            records = resp.json()
        except httpx.TimeoutException:
            return {'error_code': 'ct_timeout', 'present': False}
        except httpx.HTTPStatusError as exc:
            return {'error_code': f'ct_http_{exc.response.status_code}', 'present': False}
        except Exception as exc:
            return {'error_code': f'ct_error:{type(exc).__name__}', 'present': False}

    if not records:
        return {'present': False, 'certificate_count': 0, 'earliest_issuance': None}

    records = records[:100]
    dates = []
    for r in records:
        not_before = r.get('not_before') or r.get('entry_timestamp')
        if not_before:
            try:
                dates.append(datetime.fromisoformat(not_before.replace('Z', '+00:00')))
            except Exception:
                pass
    dates.sort()
    return {
        'present': len(records) > 0,
        'certificate_count': len(records),
        'earliest_issuance': dates[0].isoformat() if dates else None,
    }


async def _fetch_wayback_density(domain: str) -> dict:
    now = datetime.now(timezone.utc)
    from_dt = now.replace(year=now.year - 5)
    url = 'http://web.archive.org/cdx/search/cdx'
    params = {
        'url': domain, 'output': 'json', 'fl': 'timestamp', 'collapse': 'timestamp:6',
        'from': from_dt.strftime('%Y%m%d'), 'to': now.strftime('%Y%m%d'),
        'limit': 1000, 'statuscode': 200,
    }
    async with httpx.AsyncClient(timeout=35.0) as client:
        try:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            raw = resp.json()
        except httpx.TimeoutException:
            return {'error_code': 'wayback_timeout', 'present': False}
        except httpx.HTTPStatusError as exc:
            return {'error_code': f'wayback_http_{exc.response.status_code}', 'present': False}
        except Exception as exc:
            return {'error_code': f'wayback_error:{type(exc).__name__}', 'present': False}

    if not raw or len(raw) <= 1:
        return {'present': False, 'total_snapshots': 0, 'first_snapshot_date': None, 'last_snapshot_date': None}

    timestamps = []
    for row in raw[1:]:
        try:
            timestamps.append(datetime.strptime(row[0][:8], '%Y%m%d').replace(tzinfo=timezone.utc))
        except Exception:
            pass
    if not timestamps:
        return {'present': False, 'total_snapshots': 0, 'first_snapshot_date': None, 'last_snapshot_date': None}

    timestamps.sort()
    return {
        'present': True,
        'total_snapshots': len(timestamps),
        'first_snapshot_date': timestamps[0].date().isoformat(),
        'last_snapshot_date': timestamps[-1].date().isoformat(),
    }


async def _audit_dns_maturity(domain: str) -> dict:
    resolvers = ['8.8.8.8', '1.1.1.1']
    loop = asyncio.get_event_loop()

    def _resolve(resolver_ip: str, qname: str, rdtype: str) -> list:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = [resolver_ip]
        r.timeout = 5.0
        r.lifetime = 5.0
        try:
            return [str(a) for a in r.resolve(qname, rdtype)]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except dns.exception.DNSException:
            return []

    async def _aresolve(resolver_ip: str, qname: str, rdtype: str) -> list:
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, _resolve, resolver_ip, qname, rdtype), timeout=6.0
            )
        except asyncio.TimeoutError:
            return []

    # All per-resolver lookups run concurrently -- sequential (resolver x
    # record-type) would be up to 2 * 4 * 6s = 48s worst-case per call on
    # a $0.35 paid endpoint (same latency issue as the DKIM loop above).
    mx_lists, txt_lists, dmarc_lists, ns_lists = await asyncio.gather(
        asyncio.gather(*(_aresolve(r, domain, 'MX') for r in resolvers)),
        asyncio.gather(*(_aresolve(r, domain, 'TXT') for r in resolvers)),
        asyncio.gather(*(_aresolve(r, f'_dmarc.{domain}', 'TXT') for r in resolvers)),
        asyncio.gather(*(_aresolve(r, domain, 'NS') for r in resolvers)),
    )
    mx = [a for sub in mx_lists for a in sub]
    spf = [t for sub in txt_lists for t in sub if 'v=spf1' in t.lower()]
    dmarc = [t for sub in dmarc_lists for t in sub if 'v=dmarc1' in t.lower()]
    ns_per_resolver = [set(sub) for sub in ns_lists]

    has_mx, has_spf, has_dmarc = len(mx) > 0, len(spf) > 0, len(dmarc) > 0
    ns = set().union(*ns_per_resolver) if ns_per_resolver else set()
    ns_count = len(ns)

    # DKIM: checked against the primary resolver only for the common
    # selectors, same scope as the original engine -- run concurrently
    # (the original's sequential for-loop meant a domain with none of the
    # 7 selectors configured paid up to 7 * 6s = 42s serially; a real
    # cost on a $0.35 paid call, not just the free Railway asset).
    _DKIM_SELECTORS = ['google', 'default', 'mail', 'k1', 'smtp', 'selector1', 'selector2']
    dkim_results = await asyncio.gather(*(
        _aresolve(resolvers[0], f'{selector}._domainkey.{domain}', 'TXT') for selector in _DKIM_SELECTORS
    ))
    has_dkim = any(dkim_results)

    # Propagation consistency: do the first two resolvers agree on NS?
    propagation_consistent = True
    if len(ns_per_resolver) >= 2:
        propagation_consistent = bool(ns_per_resolver[0] & ns_per_resolver[1])

    score_components = {
        'has_mx': (0.25, has_mx), 'has_spf': (0.20, has_spf), 'has_dmarc': (0.20, has_dmarc),
        'has_dkim': (0.15, has_dkim), 'ns_count_adequate': (0.12, ns_count >= 2),
        'propagation_consistent': (0.08, propagation_consistent),
    }
    maturity_score = sum(w for w, v in score_components.values() if v)
    is_mature = maturity_score >= 0.45

    return {'present': ns_count > 0, 'is_mature': is_mature, 'maturity_score': round(maturity_score, 4)}


async def _run_domain_verification(domain: str, min_confidence_threshold: float,
                                    signal_mask: Optional[list]) -> dict:
    """Cross-signal Bayesian corroboration of domain existence. Direct
    port of POST /verify-entity-existence-cross-signal's body from the
    live `live-entity-verification` Railway asset -- see module docstring."""
    active_signals = list(signal_mask) if signal_mask else ['whois', 'ct', 'wayback', 'dns']

    tasks = {}
    if 'whois' in active_signals:
        tasks['whois'] = _fetch_whois(domain)
    if 'ct' in active_signals:
        tasks['ct'] = _fetch_ct_presence(domain)
    if 'wayback' in active_signals:
        tasks['wayback'] = _fetch_wayback_density(domain)
    if 'dns' in active_signals:
        tasks['dns'] = _audit_dns_maturity(domain)

    gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)
    results = {}
    for key, result in zip(tasks.keys(), gathered):
        results[key] = ({'error_code': f'{key}_exception:{type(result).__name__}', 'present': False}
                         if isinstance(result, Exception) else result)

    signals_evaluated: dict = {}
    signals_missing: list = []
    positive_signals: list = []
    whois_absent = True

    if 'whois' in results:
        w = results['whois']
        if w.get('error_code') == 'whois_no_record':
            whois_absent = True
            signals_evaluated['whois'] = _beta_mean(*_PRIOR_WHOIS_ABSENT)
        elif 'error_code' in w and not w.get('present', False):
            signals_missing.append('whois')
        else:
            whois_present = w.get('present', False)
            whois_absent = not whois_present
            age_days = w.get('age_days')
            if not whois_present:
                tier = 'negative'
            elif age_days is not None and age_days < 90:
                tier = 'young'
            elif age_days is not None and age_days > 730:
                tier = 'strong'
            else:
                tier = 'weak'
            weight = (
                _beta_mean(*_PRIOR_WHOIS_PRESENT) if tier == 'strong' else
                _beta_mean(*_PRIOR_WHOIS_YOUNG) if tier == 'young' else
                _beta_mean(*_PRIOR_WHOIS_ABSENT) if tier == 'negative' else
                _beta_mean(*_PRIOR_WEAK_NEUTRAL)
            )
            signals_evaluated['whois'] = weight
            if tier == 'strong':
                positive_signals.append('whois')

    if 'ct' in results:
        c = results['ct']
        if 'error_code' in c and not c.get('present', False):
            signals_missing.append('ct')
        else:
            cert_count = c.get('certificate_count', 0) or 0
            earliest = c.get('earliest_issuance')
            ct_span_days = None
            if earliest:
                try:
                    earliest_dt = datetime.fromisoformat(earliest.replace('Z', '+00:00'))
                    if earliest_dt.tzinfo is None:
                        earliest_dt = earliest_dt.replace(tzinfo=timezone.utc)
                    ct_span_days = (datetime.now(timezone.utc) - earliest_dt).days
                except Exception:
                    ct_span_days = None
            tier = ('negative' if cert_count <= 0 else
                    'strong' if (ct_span_days is not None and ct_span_days >= 365) else 'weak')
            weight = (
                _beta_mean(*_PRIOR_CT_PRESENT) if tier == 'strong' else
                _beta_mean(*_PRIOR_CT_ABSENT) if tier == 'negative' else
                _beta_mean(*_PRIOR_WEAK_NEUTRAL)
            )
            signals_evaluated['ct'] = weight
            if tier == 'strong':
                positive_signals.append('ct')

    if 'wayback' in results:
        wb = results['wayback']
        if 'error_code' in wb and not wb.get('present', False):
            signals_missing.append('wayback')
        else:
            snapshot_count = wb.get('total_snapshots', 0) or 0
            first, last = wb.get('first_snapshot_date'), wb.get('last_snapshot_date')
            wb_span_days = None
            if first and last:
                try:
                    wb_span_days = (datetime.fromisoformat(last) - datetime.fromisoformat(first)).days
                except Exception:
                    wb_span_days = None
            tier = ('negative' if snapshot_count <= 0 else
                    'strong' if (snapshot_count >= 5 and (wb_span_days or 0) >= 180) else 'weak')
            weight = (
                _beta_mean(*_PRIOR_WAYBACK_PRESENT) if tier == 'strong' else
                _beta_mean(*_PRIOR_WAYBACK_ABSENT) if tier == 'negative' else
                _beta_mean(*_PRIOR_WEAK_NEUTRAL)
            )
            signals_evaluated['wayback'] = weight
            if tier == 'strong':
                positive_signals.append('wayback')

    if 'dns' in results:
        d = results['dns']
        if 'error_code' in d and not d.get('present', False):
            signals_missing.append('dns')
        else:
            dns_mature = d.get('is_mature', False)
            weight = _beta_mean(*_PRIOR_DNS_MATURE) if dns_mature else _beta_mean(*_PRIOR_WEAK_NEUTRAL)
            signals_evaluated['dns'] = weight
            if dns_mature:
                positive_signals.append('dns')

    posterior_real = _fuse_signals_naive_bayes(list(signals_evaluated.values()))
    evidence_quality = _compute_evidence_quality(signals_evaluated, posterior_real)

    failure_mode = _classify_failure_mode(
        posterior=posterior_real, evidence_quality=evidence_quality,
        confidence_threshold=min_confidence_threshold, signals_present=positive_signals,
        whois_absent=whois_absent, all_signals=list(signals_evaluated.keys()),
    )
    # Per-spec: DNS alone is never sufficient for VERIFIED_LIVE.
    if failure_mode == 'verified_live' and positive_signals == ['dns']:
        failure_mode = 'insufficient_corroboration'

    verdict = ('VERIFIED_LIVE' if failure_mode == 'verified_live' else
               'LIKELY_HALLUCINATED' if failure_mode == 'likely_hallucinated' else 'UNVERIFIED')

    return {
        'verdict': verdict,
        'hallucination_probability': round(1.0 - posterior_real, 4),
        'evidence_quality_score': round(evidence_quality, 4),
        'failure_mode_classification': failure_mode,
        'positive_signals': positive_signals,
        'signals_evaluated': list(signals_evaluated.keys()),
        'signals_missing': signals_missing,
        'posterior_probability_real': round(posterior_real, 4),
    }


# =================================================================
# Agent-specific signals (new for this asset) -- neither domain WHOIS
# nor DNS maturity says anything about whether a *live agent process*
# actually exists at a claimed endpoint, or whether its identity card
# actually points back at the domain being verified.
# =================================================================

async def _fetch_agent_card(agent_endpoint_url: str) -> dict:
    """GETs .well-known/agent-card.json (A2A spec) relative to the
    caller-supplied base URL. present=False with an error_code is
    missing evidence, not negative evidence -- same missing-vs-absent
    discipline as the domain fetchers above (an agent without a card is
    not proof of hallucination, just an unverifiable claim)."""
    _nexus_validate_public_url(agent_endpoint_url)
    url = urljoin(agent_endpoint_url.rstrip('/') + '/', '.well-known/agent-card.json')
    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=False) as client:
            resp = await client.get(url, headers={'User-Agent': 'agent-verification-api/1.0'})
    except httpx.TimeoutException:
        return {'present': False, 'error_code': 'agent_card_timeout'}
    except httpx.HTTPError as exc:
        return {'present': False, 'error_code': f'agent_card_error:{type(exc).__name__}'}

    if resp.status_code != 200:
        return {'present': False, 'error_code': f'agent_card_http_{resp.status_code}'}
    try:
        data = resp.json()
    except Exception:
        return {'present': False, 'error_code': 'agent_card_invalid_json'}
    if not isinstance(data, dict):
        return {'present': False, 'error_code': 'agent_card_invalid_schema'}

    skills = data.get('skills')
    provider = data.get('provider') or {}
    return {
        'present': True,
        'name': data.get('name'),
        'url': data.get('url'),
        'skill_count': len(skills) if isinstance(skills, list) else 0,
        'provider_organization': provider.get('organization') if isinstance(provider, dict) else None,
    }


def _nexus_no_redirect_mcp_http_client(headers=None, timeout=None, auth=None) -> httpx.AsyncClient:
    """httpx_client_factory override for streamablehttp_client. The
    library's own default factory (mcp.shared._httpx_utils.create_mcp_http_client)
    hardcodes follow_redirects=True with no opt-out via streamablehttp_client's
    public signature -- that made _nexus_validate_public_url()'s pre-connect
    SSRF check a no-op against a malicious server that passes the check, then
    307/308-redirects the actual MCP request to a private/link-local target
    (e.g. Cloud Run's own 169.254.169.254 metadata endpoint). A 30s default
    timeout is also too loose for a caller-supplied endpoint we don't trust
    to respond promptly -- the outer asyncio.timeout(10.0) below already
    bounds total handshake time, but a tighter per-request timeout here
    fails faster on a hung/slow target. Same posture as _fetch_agent_card's
    follow_redirects=False (found in security review, 2026-08-22)."""
    kwargs: dict = {"follow_redirects": False, "timeout": timeout or httpx.Timeout(10.0)}
    if headers is not None:
        kwargs["headers"] = headers
    if auth is not None:
        kwargs["auth"] = auth
    return httpx.AsyncClient(**kwargs)


async def _mcp_handshake_check(agent_endpoint_url: str) -> dict:
    """Real MCP `initialize` handshake (streamable HTTP transport, same
    client used to live-verify `ws` -- see logs/_fase2_ws_live_mcp_verify.py)
    against {base}/mcp. Confirms a live, protocol-compliant MCP server
    answers -- not just that some HTTP endpoint returns 200. Redirects are
    NOT followed (see _nexus_no_redirect_mcp_http_client) -- an endpoint
    that requires a redirect to reach its real MCP path is reported as
    unreachable (missing evidence, not negative evidence), same tradeoff
    _fetch_agent_card already makes. Does not defend against DNS rebinding
    between the pre-connect check and the client's own connect (same
    accepted risk as url-metadata-api's SSRF guard)."""
    # Trailing slash built in on purpose: FastAPI's app.mount("/mcp", ...)
    # convention (used by this asset's own MCP mount below, and by every
    # other MCP asset in this codebase) 307-redirects a bare "/mcp" to
    # "/mcp/" -- with follow_redirects=False that redirect would otherwise
    # get reported as unreachable for the common case. A server that
    # instead requires the bare no-slash path is reported as unreachable
    # (missing evidence, not negative) -- same tradeoff as not following
    # redirects at all.
    mcp_url = urljoin(agent_endpoint_url.rstrip('/') + '/', 'mcp/')
    _nexus_validate_public_url(mcp_url)
    try:
        async with asyncio.timeout(10.0):
            async with streamablehttp_client(
                mcp_url, httpx_client_factory=_nexus_no_redirect_mcp_http_client
            ) as (read, write, _):
                async with ClientSession(read, write) as session:
                    init_result = await session.initialize()
                    server_info = getattr(init_result, 'serverInfo', None)
                    tools_result = await session.list_tools()
        return {
            'reachable': True,
            'server_name': getattr(server_info, 'name', None) if server_info else None,
            'server_version': getattr(server_info, 'version', None) if server_info else None,
            'tool_count': len(tools_result.tools) if tools_result else 0,
        }
    except (asyncio.TimeoutError, TimeoutError):
        return {'reachable': False, 'error_code': 'mcp_timeout'}
    except Exception as exc:
        return {'reachable': False, 'error_code': f'mcp_error:{type(exc).__name__}'}


def _domain_matches(claimed_domain: str, actual_url: Optional[str]) -> bool:
    if not actual_url:
        return False
    host = (urlparse(actual_url).hostname or '').lower()
    return host == claimed_domain or host.endswith('.' + claimed_domain)


def _classify_agent_verdict(domain_verdict: str, agent_checked: bool, agent_lens: dict) -> str:
    if domain_verdict == 'LIKELY_HALLUCINATED':
        return 'LIKELY_HALLUCINATED_AGENT'
    if not agent_checked:
        return 'VERIFIED_LIVE_DOMAIN_ONLY' if domain_verdict == 'VERIFIED_LIVE' else 'UNVERIFIED_AGENT'

    card = agent_lens.get('agent_card', {})
    handshake = agent_lens.get('mcp_handshake', {})
    card_present = bool(card.get('present'))
    mcp_live = bool(handshake.get('reachable'))
    any_signal = card_present or mcp_live

    if card_present and agent_lens.get('domain_bound') is False:
        return 'AGENT_DOMAIN_MISMATCH'
    if not any_signal:
        return 'DOMAIN_VERIFIED_AGENT_UNREACHABLE' if domain_verdict == 'VERIFIED_LIVE' else 'UNVERIFIED_AGENT'
    if domain_verdict == 'VERIFIED_LIVE' and agent_lens.get('domain_bound') and mcp_live:
        return 'VERIFIED_LIVE_AGENT'
    if domain_verdict == 'VERIFIED_LIVE' and not mcp_live:
        # Domain is real and the agent-card corroborates identity, but
        # the live process itself didn't answer the MCP handshake -- the
        # actual liveness proof this asset exists to give (see module
        # docstring), not just a static card being present. Found in
        # functional review 2026-08-22: an OR here let a dead MCP server
        # with a stale-but-present agent-card pass as VERIFIED_LIVE_AGENT.
        return 'DOMAIN_VERIFIED_AGENT_UNREACHABLE'
    return 'UNVERIFIED_AGENT'


# ---------------------------------------------------------------
# MCP server (Streamable HTTP)
# ---------------------------------------------------------------
_public_domain = os.getenv("PUBLIC_DOMAIN", "*")
if _public_domain == "*":
    print(
        "[WARN] PUBLIC_DOMAIN is unset -- every real request will get 421'd once "
        "deployed publicly (fails closed). Set it to the real Cloud Run domain and "
        "redeploy.", file=sys.stderr,
    )

mcp = FastMCP(
    "agent-verification-api",
    stateless_http=True,
    host="0.0.0.0",
    streamable_http_path="/",
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=["localhost:*", "127.0.0.1:*", _public_domain, _public_domain + ":*"],
        allowed_origins=["http://localhost:*", "http://127.0.0.1:*", "https://" + _public_domain],
    ),
)


async def _verify_agent_identity_core(domain: str, entity_name: str,
                                       agent_endpoint_url: Optional[str],
                                       claimed_agent_name: Optional[str],
                                       min_confidence_threshold: float) -> dict:
    # signal_mask isn't exposed on the public request (this asset always
    # evaluates all 4 domain signals) -- _run_domain_verification keeps
    # the parameter because it's the direct port of the live engine's
    # own signature, but every caller here passes None.
    domain_result = await _run_domain_verification(domain, min_confidence_threshold, None)

    agent_lens: dict = {"checked": False}
    if agent_endpoint_url:
        agent_lens["checked"] = True
        card_signal, handshake_signal = await asyncio.gather(
            _fetch_agent_card(agent_endpoint_url),
            _mcp_handshake_check(agent_endpoint_url),
        )
        agent_lens["agent_card"] = card_signal
        agent_lens["mcp_handshake"] = handshake_signal
        agent_lens["domain_bound"] = (
            _domain_matches(domain, card_signal.get("url")) if card_signal.get("present") else None
        )
        if claimed_agent_name and card_signal.get("present"):
            # Informational only -- deliberately NOT gating the verdict.
            # Self-reported names vary in formatting (legal-entity suffixes,
            # casing) often enough that a hard mismatch gate would produce
            # false negatives on real agents; domain_bound is the actual
            # spoofing check above.
            agent_lens["name_matches_card"] = (
                claimed_agent_name.strip().lower() == (card_signal.get("name") or "").strip().lower()
            )

    verdict = _classify_agent_verdict(domain_result["verdict"], agent_lens["checked"], agent_lens)

    return {
        "domain": domain,
        "entity_name": entity_name,
        "agent_endpoint_url": agent_endpoint_url,
        "verdict": verdict,
        "domain_verification": domain_result,
        "agent_verification": agent_lens,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }


@mcp.tool()
async def verify_agent_identity(domain: str, entity_name: str,
                                 agent_endpoint_url: Optional[str] = None,
                                 claimed_agent_name: Optional[str] = None,
                                 ctx: Context = None) -> dict:
    """Confirms an AI agent/service is who it claims to be. Fuses
    cross-signal domain verification (WHOIS/CT/Wayback/DNS) with a real
    .well-known/agent-card.json fetch and a real MCP `initialize`
    handshake against agent_endpoint_url (if given), and checks that the
    agent card's own declared url is bound to `domain`. Returns
    VERIFIED_LIVE_AGENT, AGENT_DOMAIN_MISMATCH, LIKELY_HALLUCINATED_AGENT,
    DOMAIN_VERIFIED_AGENT_UNREACHABLE, VERIFIED_LIVE_DOMAIN_ONLY (no
    agent_endpoint_url given), or UNVERIFIED_AGENT.
    """
    start = time.monotonic()
    success = False
    try:
        domain = _validate_domain(domain)
        result = await _verify_agent_identity_core(
            domain, entity_name, agent_endpoint_url, claimed_agent_name, 0.65
        )
        success = True
        return result
    finally:
        latency_ms = int((time.monotonic() - start) * 1000)
        _nexus_fire_and_forget(_nexus_log_mcp_call_event("verify_agent_identity", success, latency_ms))


# ---------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    async with mcp.session_manager.run():
        yield


app = FastAPI(
    title="Agent Verification API",
    description=(
        "Confirms an AI agent/service is who it claims to be: fuses cross-signal "
        "domain-existence verification (WHOIS/CT/Wayback/DNS) with a real agent-card "
        "fetch and a real MCP handshake against the claimed endpoint."
    ),
    version="1.0.0",
    contact={"email": "dasaanrod@gmail.com"},
    lifespan=lifespan,
)


@app.middleware("http")
async def _nexus_traffic_log(request, call_next):
    response = await call_next(request)
    ip = request.client.host if request.client else None
    _nexus_fire_and_forget(_nexus_supabase_insert("traffic_events", {
        "asset_name": _NEXUS_ASSET_NAME,
        "ip_range": _nexus_truncate_ip(ip),
        "method": request.method,
        "path": request.url.path,
        "status": response.status_code,
    }))
    return response


# --- x402: pay-per-call in USDC, Base Sepolia testnet -- same wallet,
#     facilitator and self-payment-bug fix as manual_assets/url-metadata-api
#     (skills/x402-payments). $0.35: mid-point of the $0.30-0.50 range the
#     brief specified for identity-verification-class services -- above
#     url-metadata-api's $0.01 because this call does real WHOIS spend
#     (~$0.002/lookup via Whoxy) plus 5-6 real outbound network calls
#     (WHOIS, CT, Wayback, DNS x2, agent-card, MCP handshake) instead of one. ---
_X402_EVM_ADDRESS = os.getenv("X402_WALLET_ADDRESS", "0xYOUR_WALLET_ADDRESS_HERE")
_X402_NETWORK: Network = "eip155:84532"  # Base Sepolia testnet
_X402_PRICE = os.getenv("X402_PRICE", "$0.35")

if not _X402_PRICE or not _X402_PRICE.startswith("$"):
    print(
        f"[WARN] X402_PRICE ({_X402_PRICE!r}) doesn't look like a price string "
        "(expected something like '$0.35'). Falling back to '$0.35' so the "
        "server can still boot -- fix X402_PRICE before deploying.",
        file=sys.stderr,
    )
    _X402_PRICE = "$0.35"

_looks_like_evm_address = (
    _X402_EVM_ADDRESS.startswith("0x")
    and len(_X402_EVM_ADDRESS) == 42
    and all(c in "0123456789abcdefABCDEF" for c in _X402_EVM_ADDRESS[2:])
)
if not _looks_like_evm_address:
    print(
        f"[WARN] X402_WALLET_ADDRESS ({_X402_EVM_ADDRESS!r}) doesn't look like a "
        "real EVM address (expected '0x' + 40 hex chars). The server will still "
        "boot and issue 402 challenges, but payments will have nowhere real to "
        "settle. See README.md.",
        file=sys.stderr,
    )

_x402_facilitator = HTTPFacilitatorClient(FacilitatorConfig(url="https://x402.org/facilitator"))
_x402_server = x402ResourceServer(_x402_facilitator)
_x402_server.register(_X402_NETWORK, ExactEvmServerScheme())


async def _nexus_log_x402_revenue_event(ctx) -> None:
    try:
        result = getattr(ctx, "result", None)
        requirements = getattr(ctx, "requirements", None)
        if result is None or requirements is None or not getattr(result, "success", False):
            return
        raw_amount = getattr(requirements, "amount", None)
        amount_eur = int(raw_amount) / 1_000_000 if raw_amount is not None else None
        await _nexus_supabase_insert("revenue_events", {
            "asset_name": _NEXUS_ASSET_NAME,
            "amount_eur": amount_eur,
            "pricing_model": "x402",
            "stripe_event_id": None,
            "customer_id": getattr(result, "payer", None),
        })
    except Exception:
        pass


_x402_server.on_after_settle(_nexus_log_x402_revenue_event)

_X402_ROUTES: dict[str, RouteConfig] = {
    "POST /verify-agent-identity": RouteConfig(
        accepts=[PaymentOption(scheme="exact", pay_to=_X402_EVM_ADDRESS, price=_X402_PRICE, network=_X402_NETWORK)],
        mime_type="application/json",
        description="Confirm an AI agent/service is who it claims to be (domain + agent-card + MCP handshake)",
    ),
}
app.add_middleware(PaymentMiddlewareASGI, routes=_X402_ROUTES, server=_x402_server)


class VerifyAgentIdentityRequest(BaseModel):
    domain: Annotated[str, Field(..., min_length=3, max_length=253,
        description="Claimed operating domain of the entity/agent, e.g. 'acme-corp.com'.")]
    entity_name: Annotated[str, Field(..., min_length=1, max_length=200,
        description="Human-readable entity name the domain is supposed to represent.")]
    agent_endpoint_url: Annotated[Optional[str], Field(None,
        description="Base URL of the agent's live service, e.g. 'https://acme-corp.com'. "
                     "When given, fetches {base}/.well-known/agent-card.json and performs a real "
                     "MCP initialize handshake at {base}/mcp. Must resolve to a public IP.")]
    claimed_agent_name: Annotated[Optional[str], Field(None, max_length=200,
        description="Name the caller expects the agent to self-report in its agent-card, if known.")]
    min_confidence_threshold: Annotated[float, Field(0.65, ge=0.0, le=1.0,
        description="Minimum domain evidence_quality_score for a decisive domain verdict.")]

    @field_validator('domain')
    @classmethod
    def _validate_domain_field(cls, v: str) -> str:
        return _validate_domain(v)


_AgentVerdict = Literal[
    "VERIFIED_LIVE_AGENT", "AGENT_DOMAIN_MISMATCH", "LIKELY_HALLUCINATED_AGENT",
    "DOMAIN_VERIFIED_AGENT_UNREACHABLE", "VERIFIED_LIVE_DOMAIN_ONLY", "UNVERIFIED_AGENT",
]


class VerifyAgentIdentityResponse(BaseModel):
    domain: str
    entity_name: str
    agent_endpoint_url: Optional[str] = None
    verdict: _AgentVerdict
    domain_verification: dict = Field(..., description="Cross-signal domain-existence result: "
        "verdict/hallucination_probability/evidence_quality_score/signals_evaluated/signals_missing/etc.")
    agent_verification: dict = Field(..., description="checked=false if agent_endpoint_url wasn't given. "
        "Otherwise: agent_card (present/name/url/...), mcp_handshake (reachable/server_name/...), "
        "domain_bound (True/False/None), name_matches_card (informational, not verdict-gating).")
    evaluated_at: str


@app.post(
    "/verify-agent-identity",
    response_model=VerifyAgentIdentityResponse,
    responses={
        400: {"description": "invalid domain, or agent_endpoint_url has no hostname / doesn't resolve / resolves to a non-public address -- still charged, see below"},
    },
)
async def verify_agent_identity_endpoint(payload: VerifyAgentIdentityRequest) -> dict:
    """Fuses cross-signal domain verification with agent-card + MCP handshake evidence.

    `verdict` meanings, most-trusted first:
    - VERIFIED_LIVE_AGENT: domain is real, agent-card is bound to that domain, and a real
      live MCP server answered the handshake at agent_endpoint_url.
    - VERIFIED_LIVE_DOMAIN_ONLY: domain is real; no agent_endpoint_url was given, so no
      agent-specific check ran.
    - DOMAIN_VERIFIED_AGENT_UNREACHABLE: domain is real, but agent_endpoint_url gave no
      corroborating evidence (no agent-card AND no live MCP response) -- or an agent-card
      was found but the MCP process itself didn't answer. The domain is real; whatever is
      (or isn't) running at that endpoint right now is not confirmed live.
    - AGENT_DOMAIN_MISMATCH: an agent-card WAS found at agent_endpoint_url, but its own
      declared `url` field does not match `domain` -- possible spoofing/typosquat.
    - LIKELY_HALLUCINATED_AGENT: the domain itself fails cross-signal verification
      (no WHOIS/CT/Wayback/DNS corroboration) -- the entity is probably not real,
      independent of anything agent-specific.
    - UNVERIFIED_AGENT: neither a confident real nor fake domain verdict, and/or no
      agent-specific corroboration -- genuinely inconclusive, not a negative result.

    Payment (x402) is settled by PaymentMiddlewareASGI BEFORE this handler runs -- a call
    that returns a non-VERIFIED verdict (LIKELY_HALLUCINATED_AGENT, UNVERIFIED_AGENT, etc.)
    has already been charged, same as VERIFIED_LIVE_AGENT: the verdict itself is the paid
    product, not a guarantee of a positive result. This includes a 400 (invalid domain /
    agent_endpoint_url rejected by the SSRF guard) or a 422 (malformed request body): the
    payment challenge is issued and settled by ASGI middleware ahead of FastAPI's own
    request validation, so a well-formed payment attached to an otherwise-invalid request
    is still charged."""
    return await _verify_agent_identity_core(
        payload.domain, payload.entity_name, payload.agent_endpoint_url,
        payload.claimed_agent_name, payload.min_confidence_threshold,
    )


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


_FAVICON_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
)


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    from fastapi.responses import Response
    return Response(content=_FAVICON_PNG, media_type="image/png")


# --- 402index.io domain claim verification (POST /api/v1/claim, 2026-08-22
#     -- token persisted in memory agent_verification_api_402index_claim_2026_08_22) ---
_NEXUS_402INDEX_VERIFY_HASH = "568c28c2a01a12ce5177c4a9f5be47e0ca1e8989ba0ccff91d89c16e2b729eff"


@app.get("/.well-known/402index-verify.txt", include_in_schema=False)
async def _nexus_402index_verify():
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(content=_NEXUS_402INDEX_VERIFY_HASH)


@app.get("/.well-known/agent-card.json", include_in_schema=False)
async def agent_card() -> dict:
    base = f"https://{_public_domain}" if _public_domain != "*" else "https://agent-verification-api.example"
    return {
        "name": "Agent Verification API",
        "description": "Confirms an AI agent/service is who it claims to be: cross-signal domain "
                        "verification fused with a real agent-card fetch and a real MCP handshake.",
        "url": base,
        "version": "1.0.0",
        "documentationUrl": f"{base}/docs",
        "provider": {"organization": "nexus-mcp-infra", "url": "https://github.com/nexus-mcp-infra"},
        "capabilities": {"streaming": False, "pushNotifications": False, "stateTransitionHistory": False},
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "additionalInterfaces": [{"url": f"{base}/mcp", "transport": "MCP"}],
        "skills": [
            {
                "id": "nexus_agent_verification_api_verify_agent_identity",
                "name": "Verify Agent Identity",
                "description": "Confirm an AI agent/service is who it claims to be, fusing domain "
                                "existence verification with agent-card and MCP-handshake evidence.",
                "tags": ["agent-identity", "verification", "anti-hallucination", "trust"],
            },
        ],
        "metadata": {
            "protocol_note": (
                "This service implements the Model Context Protocol (MCP) at /mcp, not A2A's own "
                "task methods. POST /verify-agent-identity is charged "
                f"{_X402_PRICE} via x402 (Base Sepolia TESTNET, not real funds) -- higher than a "
                "simple metadata-extraction call because each request does real paid WHOIS spend "
                "plus 5-6 real outbound checks (WHOIS, Certificate Transparency, Wayback Machine, "
                "DNS, agent-card fetch, MCP handshake), not one. The MCP tool is currently free -- "
                "see README. Payment settles BEFORE verification runs, at the ASGI middleware layer "
                "ahead of request validation: a call is charged even if it returns a non-VERIFIED "
                "verdict, and even if it 400s (invalid domain / agent_endpoint_url rejected by the "
                "SSRF guard) or 422s (malformed body)."
            ),
        },
    }


_NEXUS_X402_OPENAPI_OPERATIONS = [("post", "/verify-agent-identity")]


def _nexus_openapi_with_payment_info():
    if app.openapi_schema:
        return app.openapi_schema
    schema = _fastapi_get_openapi(title=app.title, version=app.version, description=app.description, routes=app.routes)
    for method, path in _NEXUS_X402_OPENAPI_OPERATIONS:
        op = schema.get("paths", {}).get(path, {}).get(method)
        if op is None:
            continue
        op["x-payment-info"] = {
            "price": {"mode": "fixed", "currency": "USD", "amount": _X402_PRICE.lstrip("$")},
            "protocols": [{"x402": {}}],
        }
        op.setdefault("responses", {})["402"] = {"description": "Payment Required"}
    schema.setdefault("info", {})["contact"] = {"email": "dasaanrod@gmail.com"}
    app.openapi_schema = schema
    return app.openapi_schema


app.openapi = _nexus_openapi_with_payment_info

app.mount("/mcp", mcp.streamable_http_app())
