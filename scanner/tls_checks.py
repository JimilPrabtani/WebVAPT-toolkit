"""
scanner/tls_checks.py
─────────────────────
TLS/SSL security checks.

Inspects the target's TLS configuration for:
  1. Certificate expiry (within 30 days = HIGH, expired = CRITICAL)
  2. Weak protocol versions (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
  3. Self-signed or untrusted certificate
  4. Certificate hostname mismatch

Uses only the Python standard library (ssl + socket) — no sslyze dependency.
sslyze integration can be added as a P2 enhancement for full cipher analysis.

References:
  - OWASP A02:2021 (Cryptographic Failures)
  - CWE-295 (Improper Certificate Validation)
  - CWE-326 (Inadequate Encryption Strength)
  - NIST SP 800-52 Rev 2
"""

import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime, timezone
from scanner.models import Finding


def _get_cert_info(hostname: str, port: int = 443, timeout: int = 10) -> dict | None:
    """
    Connect to the host and retrieve certificate metadata.
    Returns a dict with expiry, subject, issuer, protocol, or None on failure.
    """
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert      = ssock.getpeercert()
                protocol  = ssock.version()
                not_after = cert.get("notAfter", "")
                subject   = dict(x[0] for x in cert.get("subject", []))
                issuer    = dict(x[0] for x in cert.get("issuer", []))
                return {
                    "not_after": not_after,
                    "subject":   subject,
                    "issuer":    issuer,
                    "protocol":  protocol,
                }
    except ssl.SSLCertVerificationError as e:
        return {"ssl_error": str(e), "error_type": "verification"}
    except ssl.SSLError as e:
        return {"ssl_error": str(e), "error_type": "ssl"}
    except Exception:
        return None


def check_tls(url: str) -> list[Finding]:
    """Run all TLS checks for the given URL. Only runs on HTTPS targets."""
    findings = []
    parsed   = urlparse(url)

    if parsed.scheme != "https":
        return []   # HTTP targets handled by check_https() in misc_checks.py

    hostname = parsed.hostname
    port     = parsed.port or 443

    info = _get_cert_info(hostname, port)
    if info is None:
        return []   # Could not connect — skip

    # ── Certificate verification error ────────────────────────────────────
    if "ssl_error" in info:
        err = info["ssl_error"]
        is_self_signed = "self-signed" in err.lower() or "self signed" in err.lower()
        findings.append(Finding(
            vuln_type  = "TLS: Certificate Verification Failed",
            severity   = "HIGH",
            url        = url,
            detail     = (
                f"{'Self-signed certificate detected' if is_self_signed else 'TLS certificate verification failed'}. "
                "Browsers will show a trust warning. Attackers performing MITM attacks can present "
                "fake certificates without detection by users who click through warnings."
            ),
            evidence   = f"SSL error: {err[:200]}",
            remediation= (
                "Obtain a certificate from a trusted CA (Let's Encrypt is free). "
                "Self-signed certs are acceptable only in isolated internal environments "
                "with explicit trust configuration on all clients."
            ),
        ))
        return findings   # Can't check expiry/protocol if cert is untrusted

    # ── Certificate expiry ────────────────────────────────────────────────
    not_after_str = info.get("not_after", "")
    if not_after_str:
        try:
            expiry = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            now        = datetime.now(tz=timezone.utc)
            days_left  = (expiry - now).days

            if days_left < 0:
                findings.append(Finding(
                    vuln_type  = "TLS: Certificate Expired",
                    severity   = "CRITICAL",
                    url        = url,
                    detail     = (
                        f"The TLS certificate expired {abs(days_left)} day(s) ago "
                        f"(expiry: {expiry.date()}). Browsers block access to sites with expired "
                        "certificates. Service is effectively down for cautious users."
                    ),
                    evidence   = f"Not After: {not_after_str}  |  Days since expiry: {abs(days_left)}",
                    remediation= "Renew the certificate immediately. Use certbot --renew for Let's Encrypt.",
                ))
            elif days_left <= 30:
                findings.append(Finding(
                    vuln_type  = "TLS: Certificate Expiring Soon",
                    severity   = "HIGH",
                    url        = url,
                    detail     = (
                        f"TLS certificate expires in {days_left} day(s) ({expiry.date()}). "
                        "Failure to renew will cause browser trust errors and service disruption."
                    ),
                    evidence   = f"Not After: {not_after_str}  |  Days remaining: {days_left}",
                    remediation= (
                        "Renew the certificate now. Set up automated renewal "
                        "(certbot renew --deploy-hook) to avoid future expiry."
                    ),
                ))
        except ValueError:
            pass   # Unparseable date format — skip

    # ── Weak protocol version ─────────────────────────────────────────────
    protocol = info.get("protocol", "")
    weak_protocols = {"TLSv1": "TLS 1.0", "TLSv1.1": "TLS 1.1",
                      "SSLv2": "SSL 2.0", "SSLv3": "SSL 3.0"}
    if protocol in weak_protocols:
        findings.append(Finding(
            vuln_type  = f"TLS: Weak Protocol ({weak_protocols[protocol]})",
            severity   = "HIGH",
            url        = url,
            detail     = (
                f"The server negotiated {weak_protocols[protocol]}, which is deprecated and vulnerable. "
                "TLS 1.0 is susceptible to BEAST; TLS 1.1 lacks modern cipher support. "
                "PCI-DSS 3.2 requires disabling both. NIST SP 800-52 Rev 2 mandates TLS 1.2+ only."
            ),
            evidence   = f"Negotiated protocol: {protocol}",
            remediation= (
                "Disable TLS 1.0 and TLS 1.1 at the server level. "
                "Nginx: ssl_protocols TLSv1.2 TLSv1.3;  "
                "Apache: SSLProtocol -All +TLSv1.2 +TLSv1.3"
            ),
        ))

    return findings


def run_all_tls_checks(url: str, response) -> list[Finding]:
    return check_tls(url)
