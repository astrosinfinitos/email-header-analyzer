import email
from email import policy
import re


def parse_header(raw: str) -> dict:
    msg = email.message_from_string(raw, policy=policy.default)

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

    # Hops en orden cronológico (Received: viene en orden inverso)
    received = msg.get_all("Received") or []
    result["hops"] = [_parse_received(r) for r in reversed(received)]

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