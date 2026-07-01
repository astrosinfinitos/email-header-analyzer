import email
from email import policy
from html import unescape
import re
from urllib.parse import urlparse, parse_qs


# Regex para extraer URLs
URL_REGEX = re.compile(
    r'https?://[^\s<>"\')\]]+',
    re.IGNORECASE
)

HTML_URL_ATTR_REGEX = re.compile(
    r"""(?:href|src|action)\s*=\s*["']([^"']+)["']""",
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
    parts = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition  = str(part.get("Content-Disposition", ""))
            if "attachment" in disposition:
                continue
            if content_type in ("text/plain", "text/html"):
                content = _decode_part(part)
                if content:
                    parts.append(content)
    else:
        content = _decode_part(msg)
        if content:
            parts.append(content)
            print(f"[parser] Payload texto: {len(content)} chars")

    return "\n".join(parts)


def _decode_part(part) -> str:
    try:
        raw_bytes = part.get_payload(decode=True)
        if raw_bytes:
            charset = part.get_content_charset() or "utf-8"
            return raw_bytes.decode(charset, errors="replace")
        return part.get_payload(decode=False) or ""
    except Exception as e:
        print(f"[parser] Error: {e}")
        return ""


def _extract_urls(body: str) -> list[dict]:
    """Extrae URLs únicas del cuerpo, incluyendo enlaces embebidos en HTML."""
    decoded_body = unescape(body)
    raw_urls = URL_REGEX.findall(decoded_body)
    raw_urls.extend(_extract_html_attr_urls(decoded_body))

    seen = set()
    urls = []
    for url in raw_urls:
        url = _clean_url(url)
        if not url:
            continue

        dedupe_key = _dedupe_url_key(url)
        if dedupe_key not in seen:
            seen.add(dedupe_key)
            urls.append(_classify_url(url))

    return urls


def _extract_html_attr_urls(body: str) -> list[str]:
    urls = []
    for match in HTML_URL_ATTR_REGEX.finditer(body):
        url = unescape(match.group(1).strip())
        if url.lower().startswith(("http://", "https://")):
            urls.append(url)
    return urls


def _clean_url(url: str) -> str:
    url = unescape(url).strip()
    url = url.rstrip('.,;:!?"\')>]}')
    if not url.lower().startswith(("http://", "https://")):
        return ""
    return url


def _dedupe_url_key(url: str) -> str:
    try:
        parsed = urlparse(url)
    except Exception:
        return url.strip().lower()

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    if scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    elif scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]

    return parsed._replace(scheme=scheme, netloc=netloc, fragment="").geturl()


def _classify_url(url: str) -> dict:
    """Clasifica una URL con análisis básico."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        hostname = (parsed.hostname or "").lower()
        params = parse_qs(parsed.query)
    except Exception:
        return {"url": url, "domain": "", "risk": "unknown", "flags": []}

    flags = []

    base_domain = ".".join(hostname.split(".")[-2:])
    if base_domain in URL_SHORTENERS:
        flags.append("url_acortada")

    is_direct_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname))
    if is_direct_ip:
        flags.append("ip_directa")

    suspicious_params = {"url", "redirect", "next", "goto", "return", "redir", "link"}
    for param in params:
        if param.lower() in suspicious_params:
            flags.append(f"redireccion_en_params:{param}")

    if re.search(r"\d{4,}", hostname):
        flags.append("numeros_en_dominio")

    if not is_direct_ip and hostname.count(".") >= 3:
        flags.append("multiples_subdominios")

    suspicious_tlds = {".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf"}
    for tld in suspicious_tlds:
        if hostname.endswith(tld):
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
