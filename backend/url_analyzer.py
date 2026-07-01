import base64
import asyncio
import os
import re
from urllib.parse import urlparse

import httpx
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY")
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"
MAX_URLS_TO_ANALYZE = 50
MAX_VIRUSTOTAL_LOOKUPS = 4

# Servicios de acortamiento para resolver
URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
    'short.link', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'is.gd',
    'tiny.cc', 'shorte.st', 'adf.ly', 'bc.vc', 'lnkd.in'
}

SUSPICIOUS_PATH_TERMS = {
    "account", "auth", "billing", "confirm", "login", "password",
    "secure", "signin", "unlock", "update", "verify", "wallet"
}

RISK_SCORE = {
    "http_sin_tls": 5,
    "url_acortada": 10,
    "redireccion_en_params": 15,
    "ip_directa": 35,
    "multiples_subdominios": 10,
    "numeros_en_dominio": 10,
    "tld_sospechoso": 15,
    "usuario_en_url": 35,
    "puerto_no_estandar": 10,
    "dominio_punycode": 35,
    "dominio_muy_largo": 10,
    "path_sospechoso": 10,
    "vt_sospechoso": 45,
    "vt_malicioso": 90,
}

def _unique_flags(flags: list[str]) -> list[str]:
    """Devuelve flags sin duplicados conservando el orden."""
    seen = set()
    result = []
    for flag in flags:
        if flag not in seen:
            seen.add(flag)
            result.append(flag)
    return result


def _base_domain(domain: str) -> str:
    hostname = domain.split(":")[0].lower().removeprefix("www.")
    parts = hostname.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname


def _risk_from_flags(flags: list[str]) -> str:
    score = 0
    normalized_flags = []

    for flag in flags:
        normalized = flag.split(":", 1)[0]
        normalized_flags.append(normalized)
        score += RISK_SCORE.get(normalized, 0)

    if "vt_malicioso" in normalized_flags or score >= 60:
        return "high"
    elif score >= 25:
        return "medium"
    else:
        return "low"


def enrich_local_url_analysis(url_data: dict) -> dict:
    """Completa el análisis local sin depender de servicios externos."""
    url = url_data.get("url", "")
    flags = list(url_data.get("flags") or [])

    try:
        parsed = urlparse(url)
    except Exception:
        return {
            "url": url,
            "resolved_url": None,
            "domain": url_data.get("domain", ""),
            "risk": "unknown",
            "flags": _unique_flags(flags),
            "virustotal": None,
        }

    domain = (url_data.get("domain") or parsed.netloc or "").lower()
    hostname = (parsed.hostname or "").lower()

    if parsed.scheme == "http":
        flags.append("http_sin_tls")

    if parsed.username or parsed.password:
        flags.append("usuario_en_url")

    try:
        port = parsed.port
    except ValueError:
        port = None
        flags.append("puerto_no_estandar")

    if port and port not in (80, 443):
        flags.append("puerto_no_estandar")

    if "xn--" in hostname:
        flags.append("dominio_punycode")

    if len(hostname) > 60:
        flags.append("dominio_muy_largo")

    path_terms = {term for term in re.split(r"[^a-z0-9]+", parsed.path.lower()) if term}
    if path_terms & SUSPICIOUS_PATH_TERMS:
        flags.append("path_sospechoso")

    flags = _unique_flags(flags)
    risk = _risk_from_flags(flags)

    return {
        "url": url,
        "resolved_url": url_data.get("resolved_url"),
        "domain": domain,
        "risk": risk,
        "flags": flags,
        "virustotal": url_data.get("virustotal"),
    }


async def resolve_url(url: str, client: httpx.AsyncClient) -> str:
    """Resuelve URLs acortadas siguiendo redirecciones."""
    try:
        res = await client.head(
            url,
            follow_redirects=True,
            timeout=5,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        final_url = str(res.url)
        return final_url if final_url != url else url
    except Exception:
        return url


async def check_url_virustotal(url: str, client: httpx.AsyncClient) -> dict:
    """Consulta VirusTotal para una URL."""
    if not VIRUSTOTAL_KEY:
        return {"status": "skipped", "reason": "missing_api_key"}

    try:
        # VirusTotal requiere la URL en base64 sin padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

        res = await client.get(
            f"{VIRUSTOTAL_URL}/{url_id}",
            headers={"x-apikey": VIRUSTOTAL_KEY},
            timeout=10,
        )

        if res.status_code == 404:
            return {"status": "not_found"}

        res.raise_for_status()
        attrs = res.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        return {
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }
    except httpx.HTTPStatusError as e:
        return {"error": f"VirusTotal error {e.response.status_code}"}
    except Exception as e:
        return {"error": f"VirusTotal no disponible: {str(e)}"}


async def analyze_url(url_data: dict, client: httpx.AsyncClient, check_virustotal: bool = False) -> dict:
    """Analiza una URL: resuelve acortadores y consulta VirusTotal si es sospechosa."""
    local = enrich_local_url_analysis(url_data)
    url = local["url"]
    risk = local["risk"]
    flags = list(local["flags"])
    domain = local["domain"]

    resolved_url = url

    # Resuelve si es acortador
    base_domain = _base_domain(domain) if domain else ""
    if base_domain in URL_SHORTENERS or "url_acortada" in flags:
        resolved_url = await resolve_url(url, client)
        if resolved_url != url:
            flags.append("resuelta")

    # Consulta VirusTotal solo si riesgo medio o alto
    vt_result = None
    if check_virustotal and risk in ("medium", "high"):
        vt_result = await check_url_virustotal(resolved_url, client)

        # Actualiza el riesgo según VirusTotal
        if vt_result and not vt_result.get("error") and vt_result.get("status") != "not_found":
            malicious = vt_result.get("malicious", 0)
            if malicious > 3:
                risk = "high"
                flags.append("vt_malicioso")
            elif malicious > 0:
                risk = "medium"
                flags.append("vt_sospechoso")

    flags = _unique_flags(flags)
    risk = _risk_from_flags(flags)

    return {
        "url":          url,
        "resolved_url": resolved_url if resolved_url != url else None,
        "domain":       domain,
        "risk":         risk,
        "flags":        flags,
        "virustotal":   vt_result,
    }


async def analyze_all_urls(urls: list[dict]) -> list[dict]:
    """Analiza todas las URLs con un límite de concurrencia para respetar la cuota de VirusTotal."""
    if not urls:
        return []

    urls_to_analyze = urls[:MAX_URLS_TO_ANALYZE]
    enriched_urls = [enrich_local_url_analysis(url_data) for url_data in urls_to_analyze]

    async with httpx.AsyncClient() as client:
        vt_slots = MAX_VIRUSTOTAL_LOOKUPS if VIRUSTOTAL_KEY else 0
        tasks = []

        for url_data in enriched_urls:
            should_check_vt = vt_slots > 0 and url_data["risk"] in ("medium", "high")
            if should_check_vt:
                vt_slots -= 1
            tasks.append(analyze_url(url_data, client, check_virustotal=should_check_vt))

        return await asyncio.gather(*tasks)
