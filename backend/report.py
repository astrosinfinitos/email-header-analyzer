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

    if fails >= 2 or high_abuse or vt_malicious:
        return "CRÍTICA"
    elif fails == 1 or nones >= 2:
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

    if criticality == "BAJA":
        return "Legítimo"
    if vt_malicious:
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
    return iocs


def build_recommendations(criticality: str, threat_type: str) -> list[str]:
    base = [
        "Revisar y validar el contenido del reporte antes de su uso oficial.",
        "Actualizar los datos de identificación según los procedimientos internos.",
    ]

    if criticality in ("CRÍTICA", "ALTA"):
        return base + [
            "Poner en cuarentena el correo inmediatamente.",
            "Bloquear las IPs identificadas en el firewall perimetral.",
            "Notificar al usuario afectado y al equipo de seguridad.",
            "Reportar las IPs maliciosas en AbuseIPDB.",
            "Revisar si otros usuarios han recibido correos similares.",
            "Iniciar proceso de respuesta a incidentes según el playbook.",
        ]
    elif criticality == "MEDIA":
        return base + [
            "Marcar el correo como sospechoso y notificar al usuario.",
            "Monitorizar actividad adicional desde las IPs identificadas.",
            "Verificar si el dominio remitente es legítimo.",
        ]
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
    recs        = build_recommendations(criticality, threat_type)

    auth  = data.get("auth", {})
    hops  = data.get("hops", [])

    additional = [
        f"SPF: {auth.get('spf', 'none').upper()}",
        f"DKIM: {auth.get('dkim', 'none').upper()}",
        f"DMARC: {auth.get('dmarc', 'none').upper()}",
        f"Número de hops: {len(hops)}",
    ]
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
{"Se han identificado IPs con reputación negativa en la ruta de entrega." if iocs else "No se han identificado IPs con reputación negativa."}

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