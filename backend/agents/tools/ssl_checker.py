"""SSL/TLS configuration analysis — protocol versions, cert expiry, cipher strength."""

import ssl
import socket
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
_WEAK_CIPHERS_SUBSTR = ("RC4", "DES", "3DES", "EXPORT", "NULL", "anon", "MD5")


def check_ssl_tls(host: str, port: int = 443) -> dict:
    """
    Connects to host:port and inspects the TLS handshake.
    Returns cert details, negotiated protocol/cipher, and a list of issues.
    """
    results: dict = {
        "host": host,
        "port": port,
        "reachable": False,
        "protocol": None,
        "cipher": None,
        "cert_subject": None,
        "cert_issuer": None,
        "cert_expiry": None,
        "cert_days_remaining": None,
        "cert_expired": False,
        "cert_expiring_soon": False,
        "san": [],
        "issues": [],
    }

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we want to inspect even invalid certs

    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                results["reachable"] = True
                results["protocol"] = ssock.version()
                cipher_name, _, bits = ssock.cipher()
                results["cipher"] = {"name": cipher_name, "bits": bits}

                cert = ssock.getpeercert()
                if cert:
                    # Subject
                    subj = dict(x[0] for x in cert.get("subject", []))
                    results["cert_subject"] = subj.get("commonName")

                    # Issuer
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    results["cert_issuer"] = issuer.get("organizationName")

                    # Expiry
                    not_after = cert.get("notAfter")
                    if not_after:
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                            tzinfo=timezone.utc
                        )
                        results["cert_expiry"] = expiry.isoformat()
                        days_left = (expiry - datetime.now(timezone.utc)).days
                        results["cert_days_remaining"] = days_left
                        if days_left < 0:
                            results["cert_expired"] = True
                            results["issues"].append(
                                f"Certificate expired {abs(days_left)} days ago"
                            )
                        elif days_left < 30:
                            results["cert_expiring_soon"] = True
                            results["issues"].append(
                                f"Certificate expires in {days_left} days — renew urgently"
                            )
                        elif days_left < 90:
                            results["issues"].append(
                                f"Certificate expires in {days_left} days — schedule renewal"
                            )

                    # SANs
                    results["san"] = [
                        v for _, v in cert.get("subjectAltName", []) if _ == "DNS"
                    ]

    except ssl.SSLError as e:
        results["issues"].append(f"SSL handshake error: {e}")
        return results
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        results["issues"].append(f"Could not connect to {host}:{port} — {e}")
        return results
    except Exception as e:
        results["issues"].append(f"Unexpected error: {e}")
        return results

    # ── Protocol version checks ───────────────────────────────────────────────
    proto = results.get("protocol") or ""
    if proto in _WEAK_PROTOCOLS:
        results["issues"].append(
            f"Negotiated {proto} — this protocol is obsolete and has known attacks (POODLE, BEAST, etc.)"
        )

    # ── Cipher strength ────────────────────────────────────────────────────────
    cipher_name = (results.get("cipher") or {}).get("name", "")
    bits = (results.get("cipher") or {}).get("bits") or 0
    if any(w in cipher_name for w in _WEAK_CIPHERS_SUBSTR):
        results["issues"].append(f"Weak cipher negotiated: {cipher_name}")
    if bits and bits < 128:
        results["issues"].append(f"Short key length: {bits} bits — minimum acceptable is 128")

    return results
