"""NIST NVD API 2.0 CVE/CVSS enrichment service.

References:
- SECREF/53_NVD_API_docs_web.md: Endpoint, query params, JSON response schema.
- SECREF/53b_NVD_start_here_web.md: Rate limits (50 req/30s with key, 5 req/30s unauth) and apiKey header.
- SECREF/50b_FIRST_CVSS_v3.1_web.md: CVSS v3.1 scoring and base severity metrics.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from cipher_lens.adapters.base import Finding

logger = logging.getLogger(__name__)

NVD_CVE_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_TIMEOUT_SECONDS = 5.0

# In-memory cache for product:version -> CVE enrichment payload to honor NIST rate limits
_NVD_LOOKUP_CACHE: dict[str, dict[str, Any] | None] = {}


def clear_nvd_cache() -> None:
    """Clear in-memory NVD lookup cache (useful for test isolation)."""
    _NVD_LOOKUP_CACHE.clear()


def fetch_nvd_cve_for_product(
    product: str,
    version: str,
    api_key: str | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    opener: Callable[..., Any] = urlopen,
) -> dict[str, Any] | None:
    """Query NVD API 2.0 for a verified product and version string.

    Gated strictly to non-empty scanner-captured product and version strings.
    Returns parsed dictionary containing cve, cvss, severity, cwe or None if not found/failed.
    """
    clean_product = product.strip()
    clean_version = version.strip()
    if not clean_product or not clean_version:
        return None

    cache_key = f"{clean_product.lower()}:{clean_version.lower()}"
    if cache_key in _NVD_LOOKUP_CACHE:
        return _NVD_LOOKUP_CACHE[cache_key]

    # Without an API key, do not fire live network calls to NVD to maintain zero-cost operation
    if not api_key or not api_key.strip():
        return None

    query_params = {
        "keywordSearch": f"{clean_product} {clean_version}",
        "resultsPerPage": 1,
    }
    url = f"{NVD_CVE_API_BASE_URL}?{urlencode(query_params)}"
    headers = {
        "User-Agent": "Cipher-Lens-Assessment-Platform/1.0",
        "apiKey": api_key.strip(),
    }
    req = Request(url, headers=headers)

    try:
        with opener(req, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
        logger.warning("NVD API 2.0 lookup failed for %s %s: %s", clean_product, clean_version, exc)
        _NVD_LOOKUP_CACHE[cache_key] = None
        return None

    vulnerabilities = payload.get("vulnerabilities", [])
    if not vulnerabilities:
        _NVD_LOOKUP_CACHE[cache_key] = None
        return None

    top_cve_entry = vulnerabilities[0].get("cve", {})
    cve_id = top_cve_entry.get("id")
    if not cve_id:
        _NVD_LOOKUP_CACHE[cache_key] = None
        return None

    metrics = top_cve_entry.get("metrics", {})
    cvss_score: float | None = None
    severity: str | None = None

    # Deterministic precedence: CVSS v3.1 -> CVSS v3.0 -> CVSS v2.0
    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(metric_key, [])
        if metric_list and isinstance(metric_list, list):
            cvss_data = metric_list[0].get("cvssData", {})
            if "baseScore" in cvss_data:
                try:
                    cvss_score = float(cvss_data["baseScore"])
                    raw_sev = cvss_data.get("baseSeverity") or metric_list[0].get("baseSeverity")
                    if raw_sev:
                        severity = str(raw_sev).title()
                    break
                except (ValueError, TypeError):
                    continue

    cwe_id: str | None = None
    for weakness in top_cve_entry.get("weaknesses", []):
        for desc in weakness.get("description", []):
            val = desc.get("value", "")
            if val.upper().startswith("CWE-") and val.upper() != "CWE-OTHER":
                cwe_id = val.upper()
                break
        if cwe_id:
            break

    result = {
        "cve": cve_id,
        "cvss": cvss_score,
        "severity": severity,
        "cwe": cwe_id,
    }
    _NVD_LOOKUP_CACHE[cache_key] = result
    return result


def enrich_finding_with_nvd(
    finding: Finding,
    api_key: str | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    opener: Callable[..., Any] = urlopen,
) -> Finding:
    """Enrich a finding with NVD CVE/CVSS data at Result Ingestion time.

    Rules:
    1. If finding already has a CVE (from Tier 1 native tool output), return unchanged.
    2. If finding has no verified product or version from scanner output, never fire NVD lookup.
    3. If api_key is None or empty, return unchanged with cve=None.
    4. If lookup fails or times out, return unchanged with cve=None without erroring.
    """
    # Tier 1 priority: native tool CVE is retained and prioritized without network call
    if finding.cve:
        return finding

    # Gate strictly to scanner-captured product and version strings
    if not finding.product or not finding.version:
        return finding

    # If NVD_API_KEY is not configured, remain in zero-cost mode
    if not api_key:
        return finding

    enriched_data = fetch_nvd_cve_for_product(
        product=finding.product,
        version=finding.version,
        api_key=api_key,
        timeout=timeout,
        opener=opener,
    )
    if not enriched_data:
        return finding

    updates: dict[str, Any] = {}
    if enriched_data.get("cve"):
        updates["cve"] = enriched_data["cve"]
    if enriched_data.get("cvss") is not None and finding.cvss is None:
        updates["cvss"] = enriched_data["cvss"]
    if enriched_data.get("severity"):
        if finding.severity is None or finding.severity.strip().lower() in {"info", "informational", "none"}:
            updates["severity"] = enriched_data["severity"]
    if enriched_data.get("cwe") and finding.cwe is None:
        updates["cwe"] = enriched_data["cwe"]

    if not updates:
        return finding

    return finding.model_copy(update=updates)

