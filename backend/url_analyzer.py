import httpx
import asyncio
import os
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY")
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"

# Servicios de acortamiento para resolver
URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
    'short.link', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'is.gd',
    'tiny.cc', 'shorte.st', 'adf.ly', 'bc.vc', 'lnkd.in'
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
    try:
        import base64
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


async def analyze_url(url_data: dict, client: httpx.AsyncClient) -> dict:
    """Analiza una URL: resuelve acortadores y consulta VirusTotal si es sospechosa."""
    url    = url_data["url"]
    risk   = url_data["risk"]
    flags  = url_data["flags"]
    domain = url_data["domain"]

    resolved_url = url

    # Resuelve si es acortador
    base_domain = ".".join(domain.split(".")[-2:]) if domain else ""
    if base_domain in URL_SHORTENERS or "url_acortada" in flags:
        resolved_url = await resolve_url(url, client)
        if resolved_url != url:
            flags = flags + ["resuelta"]

    # Consulta VirusTotal solo si riesgo medio o alto
    vt_result = None
    if risk in ("medium", "high"):
        vt_result = await check_url_virustotal(resolved_url, client)

        # Actualiza el riesgo según VirusTotal
        if vt_result and not vt_result.get("error") and vt_result.get("status") != "not_found":
            malicious = vt_result.get("malicious", 0)
            if malicious > 3:
                risk = "high"
                flags = list(set(flags + ["vt_malicioso"]))
            elif malicious > 0:
                risk = "medium"
                flags = list(set(flags + ["vt_sospechoso"]))

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

    # Limita a 10 URLs para no saturar
    urls_to_analyze = urls[:10]

    async with httpx.AsyncClient() as client:
        # VirusTotal permite 4 req/min en el plan gratuito
        # Procesamos en lotes de 4 con pausa entre lotes
        results = []
        batch_size = 4

        for i in range(0, len(urls_to_analyze), batch_size):
            batch = urls_to_analyze[i:i + batch_size]
            batch_results = await asyncio.gather(*[
                analyze_url(url_data, client) for url_data in batch
            ])
            results.extend(batch_results)

            # Pausa entre lotes si quedan más URLs
            if i + batch_size < len(urls_to_analyze):
                await asyncio.sleep(15)

    return results