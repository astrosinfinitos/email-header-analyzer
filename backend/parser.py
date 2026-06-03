import email
from email import policy
import re
from urllib.parse import urlparse, parse_qs


# Regex para extraer URLs
URL_REGEX = re.compile(
    r'https?://[^\s<>"\')\]]+',
    re.IGNORECASE
)

# Servicios de acortamiento conocidos
URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
    'short.link', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'is.gd',
    'tiny.cc', 'shorte.st', 'adf.ly', 'bc.vc', 'lnkd.in'
}


def parse_header(raw: str) -> dict:
    print(f"[parser] Raw recibido: {len(raw)} chars")
    print(f"[parser] Primeros 200 chars: {repr(raw[:200])}")
    msg = email.message_from_string(raw, policy=email.policy.compat32)

    print(f"[parser] is_multipart: {msg.is_multipart()}")
    print(f"[parser] content_type: {msg.get_content_type()}")
    print(f"[parser] transfer_encoding: {msg.get('Content-Transfer-Encoding', 'none')}")

    result = {
        "from":       msg.get("From", ""),
        "to":         msg.get("To", ""),
        "subject":    msg.get("Subject", ""),
        "date":       msg.get("Date", ""),
        "message_id": msg.get("Message-ID", ""),
        "mailer":     msg.get("X-Mailer", msg.get("User-Agent", "")),
        "spam_score": msg.get("X-Spam-Status", ""),
    }

    # Autenticación
    auth = msg.get("Authentication-Results", "")
    result["auth"] = {
        "spf":   _extract_auth(auth, "spf"),
        "dkim":  _extract_auth(auth, "dkim"),
        "dmarc": _extract_auth(auth, "dmarc"),
    }

    # Hops en orden cronológico
    received = msg.get_all("Received") or []
    result["hops"] = [_parse_received(r) for r in reversed(received)]

    # Cuerpo y URLs
    body = _extract_body(msg)
    print(f"[parser] Cuerpo extraído: {len(body)} chars")
    result["urls"] = _extract_urls(body) if body else []
    print(f"[parser] URLs encontradas: {len(result['urls'])}")

    return result


def _extract_auth(auth_str: str, protocol: str) -> str:
    m = re.search(rf"{protocol}=(\S+)", auth_str, re.IGNORECASE)
    return m.group(1).rstrip(";") if m else "none"


def _parse_received(received: str) -> dict:
    ip_match = re.search(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", received)
    return {
        "raw": received.strip(),
        "ip":  ip_match.group(1) if ip_match else None,
    }

def _extract_body(msg) -> str:
    body = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition  = str(part.get("Content-Disposition", ""))
            if "attachment" in disposition:
                continue
            if content_type in ("text/plain", "text/html"):
                try:
                    raw_bytes = part.get_payload(decode=True)
                    if raw_bytes:
                        charset = part.get_content_charset() or "utf-8"
                        content = raw_bytes.decode(charset, errors="replace")
                    else:
                        content = part.get_payload(decode=False) or ""
                    if content_type == "text/plain" or not body:
                        body += content
                except Exception as e:
                    print(f"[parser] Error: {e}")
    else:
        try:
            raw_bytes = msg.get_payload(decode=True)
            if raw_bytes:
                charset = msg.get_content_charset() or "utf-8"
                body = raw_bytes.decode(charset, errors="replace")
            else:
                # Sin encoding — el payload ya es texto plano
                body = msg.get_payload(decode=False) or ""
                print(f"[parser] Payload texto plano: {len(body)} chars")
        except Exception as e:
            print(f"[parser] Error: {e}")

    return body


def _extract_urls(body: str) -> list[dict]:
    """Extrae URLs únicas del cuerpo y las clasifica."""
    raw_urls = URL_REGEX.findall(body)

    seen = set()
    urls = []
    for url in raw_urls:
        url = url.rstrip('.,;:!?"\')>')
        if url not in seen:
            seen.add(url)
            urls.append(_classify_url(url))

    return urls


def _classify_url(url: str) -> dict:
    """Clasifica una URL con análisis básico."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        params = parse_qs(parsed.query)
    except Exception:
        return {"url": url, "domain": "", "risk": "unknown", "flags": []}

    flags = []

    base_domain = ".".join(domain.split(".")[-2:])
    if base_domain in URL_SHORTENERS:
        flags.append("url_acortada")

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain.split(":")[0]):
        flags.append("ip_directa")

    suspicious_params = {"url", "redirect", "next", "goto", "return", "redir", "link"}
    for param in params:
        if param.lower() in suspicious_params:
            flags.append(f"redireccion_en_params:{param}")

    if re.search(r"\d{4,}", domain):
        flags.append("numeros_en_dominio")

    if domain.count(".") >= 3:
        flags.append("multiples_subdominios")

    suspicious_tlds = {".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf"}
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            flags.append("tld_sospechoso")
            break

    if len(flags) >= 2:
        risk = "high"
    elif len(flags) == 1:
        risk = "medium"
    else:
        risk = "low"

    return {
        "url":    url,
        "domain": domain,
        "risk":   risk,
        "flags":  flags,
    }