import uuid
from datetime import datetime


def determine_criticality(data: dict) -> str:
    auth  = data.get("auth", {})
    spf   = (auth.get("spf",   "none")).lower()
    dkim  = (auth.get("dkim",  "none")).lower()
    dmarc = (auth.get("dmarc", "none")).lower()

    fails    = [spf, dkim, dmarc].count("fail")
    nones    = [spf, dkim, dmarc].count("none")

    reputation   = data.get("reputation", [])
    high_abuse   = any(r.get("abuseipdb", {}).get("score", 0) > 50 for r in reputation)
    vt_malicious = any(r.get("virustotal", {}).get("malicious", 0) > 3 for r in reputation)
    urls          = data.get("urls", [])
    high_urls     = sum(1 for u in urls if u.get("risk") == "high")
    malicious_urls = any("vt_malicioso" in (u.get("flags") or []) for u in urls)

    severe_url_signal = malicious_urls or high_urls >= 2 or (high_urls > 0 and fails >= 1)

    if fails >= 2 or high_abuse or vt_malicious or severe_url_signal:
        return "CRÍTICA"
    elif fails == 1 or nones >= 2 or high_urls > 0:
        return "ALTA"
    elif nones == 1:
        return "MEDIA"
    else:
        return "BAJA"


def determine_threat_type(data: dict, criticality: str) -> str:
    auth  = data.get("auth", {})
    spf   = (auth.get("spf",   "none")).lower()
    dkim  = (auth.get("dkim",  "none")).lower()
    dmarc = (auth.get("dmarc", "none")).lower()

    reputation   = data.get("reputation", [])
    high_abuse   = any(r.get("abuseipdb", {}).get("score", 0) > 25 for r in reputation)
    vt_malicious = any(r.get("virustotal", {}).get("malicious", 0) > 0 for r in reputation)
    urls          = data.get("urls", [])
    high_urls     = any(u.get("risk") == "high" for u in urls)
    malicious_urls = any("vt_malicioso" in (u.get("flags") or []) for u in urls)

    if criticality == "BAJA":
        return "Legítimo"
    if vt_malicious or high_urls or malicious_urls:
        return "Malware / Phishing"
    if high_abuse and (spf == "fail" or dkim == "fail"):
        return "Phishing"
    if spf == "fail" or dkim == "fail":
        return "Spoofing"
    if dkim == "none" and dmarc == "none":
        return "Spam / Correo no autenticado"
    return "Indeterminado"


def build_iocs(data: dict) -> list[str]:
    iocs = []
    for r in data.get("reputation", []):
        abuse = r.get("abuseipdb", {})
        vt    = r.get("virustotal", {})
        iocs.append(
            f"IP {r['ip']} — AbuseIPDB: {abuse.get('score', 0)}% "
            f"({abuse.get('reports', 0)} reportes), "
            f"ISP: {abuse.get('isp', '—')}, "
            f"País: {abuse.get('country', '—')}, "
            f"TOR: {'Sí' if abuse.get('is_tor') else 'No'}, "
            f"VirusTotal: {vt.get('malicious', 0)} motores maliciosos"
        )
    for url in data.get("urls", []):
        if url.get("risk") != "high" and "vt_malicioso" not in (url.get("flags") or []):
            continue

        vt = url.get("virustotal") or {}
        flags = ", ".join(url.get("flags", [])) or "sin flags"
        resolved = f", resuelta: {url['resolved_url']}" if url.get("resolved_url") else ""
        vt_text = ""
        if vt and vt.get("status") not in ("not_found", "skipped"):
            vt_text = f", VirusTotal: {vt.get('malicious', 0)} motores maliciosos"

        iocs.append(
            f"URL {url.get('url', '—')} — Riesgo: {url.get('risk', 'unknown').upper()}, "
            f"Dominio: {url.get('domain', '—')}, Flags: {flags}{resolved}{vt_text}"
        )
    return iocs


def build_recommendations(criticality: str, threat_type: str, data: dict | None = None) -> list[str]:
    base = [
        "Revisar y validar el contenido del reporte antes de su uso oficial.",
        "Actualizar los datos de identificación según los procedimientos internos.",
    ]
    risky_urls = any(
        u.get("risk") == "high" or "vt_malicioso" in (u.get("flags") or [])
        for u in (data or {}).get("urls", [])
    )

    if criticality in ("CRÍTICA", "ALTA"):
        recs = base + [
            "Poner en cuarentena el correo inmediatamente.",
            "Bloquear las IPs identificadas en el firewall perimetral.",
            "Notificar al usuario afectado y al equipo de seguridad.",
            "Reportar las IPs maliciosas en AbuseIPDB.",
            "Revisar si otros usuarios han recibido correos similares.",
            "Iniciar proceso de respuesta a incidentes según el playbook.",
        ]
        if risky_urls:
            recs.insert(3, "Bloquear o revisar los dominios y URLs sospechosas identificadas.")
        return recs
    elif criticality == "MEDIA":
        recs = base + [
            "Marcar el correo como sospechoso y notificar al usuario.",
            "Monitorizar actividad adicional desde las IPs identificadas.",
            "Verificar si el dominio remitente es legítimo.",
        ]
        if risky_urls:
            recs.append("Validar manualmente los enlaces detectados antes de permitir su acceso.")
        return recs
    else:
        return base + [
            "No se requieren acciones de contención.",
            "Archivar el análisis como referencia.",
        ]


def generate_report(data: dict) -> dict:
    ticket      = f"INC-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"
    criticality = determine_criticality(data)
    threat_type = determine_threat_type(data, criticality)
    iocs        = build_iocs(data)
    recs        = build_recommendations(criticality, threat_type, data)

    auth  = data.get("auth", {})
    hops  = data.get("hops", [])
    urls  = data.get("urls", [])

    additional = [
        f"SPF: {auth.get('spf', 'none').upper()}",
        f"DKIM: {auth.get('dkim', 'none').upper()}",
        f"DMARC: {auth.get('dmarc', 'none').upper()}",
        f"Número de hops: {len(hops)}",
        f"Enlaces detectados: {len(urls)}",
    ]
    high_urls = sum(1 for u in urls if u.get("risk") == "high")
    medium_urls = sum(1 for u in urls if u.get("risk") == "medium")
    if high_urls or medium_urls:
        additional.append(f"Enlaces de riesgo: {high_urls} alto(s), {medium_urls} medio(s)")
    if data.get("spam_score"):
        additional.append(f"Spam score: {data['spam_score']}")

    content = f"""TICKET: {ticket}
FECHA Y HORA: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}
CRITICIDAD: {criticality}
TIPO DE AMENAZA: {threat_type}

DESCRIPCIÓN:
Análisis forense del correo electrónico recibido por {data.get('to', '—')} con asunto "{data.get('subject', '—')}". \
El remitente identificado es {data.get('from', '—')}. \
{"Se han detectado fallos en los mecanismos de autenticación del correo." if criticality != "BAJA" else "Los mecanismos de autenticación del correo han superado todas las verificaciones."} \
{"Se han identificado IPs o enlaces con señales de riesgo." if iocs else "No se han identificado indicadores de compromiso relevantes."}

INDICADORES DE COMPROMISO:
{chr(10).join(f"- {ioc}" for ioc in iocs) if iocs else "- No se han identificado indicadores de compromiso."}

ELEMENTOS ADICIONALES:
{chr(10).join(f"- {a}" for a in additional)}

RECOMENDACIONES:
{chr(10).join(f"- {r}" for r in recs)}

DISCLAIMER:
Este reporte ha sido generado automáticamente como punto de partida para el análisis. \
El analista responsable debe revisar, validar y adaptar el contenido antes de su uso oficial. \
Los datos de identificación (ticket, fechas, destinatarios) deben ser verificados y actualizados \
según los procedimientos internos de la organización."""

    return {
        "ticket":      ticket,
        "criticality": criticality,
        "content":     content,
    }
