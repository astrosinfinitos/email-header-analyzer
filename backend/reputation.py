import httpx
import os
import asyncio
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_KEY  = os.getenv("ABUSEIPDB_KEY")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY")

ABUSEIPDB_URL  = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses"


def is_private(ip: str) -> bool:
    """Detecta IPs privadas o de loopback."""
    if not ip:
        return True
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("127."):
        return True
    if ip == "::1":
        return True
    # Rango privado real: 172.16.0.0 – 172.31.255.255
    try:
        second_octet = int(ip.split(".")[1])
        if ip.startswith("172.") and 16 <= second_octet <= 31:
            return True
    except (IndexError, ValueError):
        pass
    return False


async def check_abuseipdb(ip: str, client: httpx.AsyncClient) -> dict:
    try:
        res = await client.get(
            ABUSEIPDB_URL,
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=8,
        )
        res.raise_for_status()
        data = res.json().get("data", {})
        return {
            "score":       data.get("abuseConfidenceScore", 0),
            "reports":     data.get("totalReports", 0),
            "country":     data.get("countryCode", "—"),
            "isp":         data.get("isp", "—"),
            "is_tor":      data.get("isTor", False),
            "last_report": data.get("lastReportedAt", None),
        }
    except httpx.HTTPStatusError as e:
        return {"error": f"AbuseIPDB error {e.response.status_code}"}
    except Exception as e:
        return {"error": f"AbuseIPDB no disponible: {str(e)}"}


async def check_virustotal(ip: str, client: httpx.AsyncClient) -> dict:
    try:
        res = await client.get(
            f"{VIRUSTOTAL_URL}/{ip}",
            headers={"x-apikey": VIRUSTOTAL_KEY},
            timeout=8,
        )
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


async def check_all_ips(ips: list[str]) -> list[dict]:
    # Filtra privadas y duplicadas
    public_ips = list({ip for ip in ips if not is_private(ip)})

    print(f"[reputation] IPs públicas a consultar: {public_ips}")

    if not public_ips:
        return []

    async with httpx.AsyncClient() as client:
        tasks = [
            asyncio.gather(
                check_abuseipdb(ip, client),
                check_virustotal(ip, client),
            )
            for ip in public_ips
        ]
        results = await asyncio.gather(*tasks)

    output = [
        {"ip": ip, "abuseipdb": abuse, "virustotal": vt}
        for ip, (abuse, vt) in zip(public_ips, results)
    ]

    print(f"[reputation] Resultados: {output}")
    return output