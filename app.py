"""
app.py — WebPenTest AI Toolkit Dashboard
Fixed: lag, history view results, remediation rendering, XSS escaping, polling timeout
"""

import os
import html as html_module
import streamlit as st
import requests as req
import json
import time
from dotenv import load_dotenv

load_dotenv()

# Forward the API key to the backend when it is configured.
_API_KEY: str = os.getenv("API_KEY", "")
_AUTH_HEADERS: dict = {"X-API-Key": _API_KEY} if _API_KEY else {}

st.set_page_config(
    page_title="WebPenTest AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

API_BASE = "http://localhost:8000/api/v1"

# ── CSS ───────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

*, *::before, *::after { box-sizing: border-box; }
.stApp { background: #080d14; font-family: 'Syne', sans-serif; }
#MainMenu, footer, header { visibility: hidden; }
.block-container { padding: 2rem 2.5rem 4rem; max-width: 1400px; }

section[data-testid="stSidebar"] {
    background: #0b1018 !important;
    border-right: 1px solid #1a2535;
}
section[data-testid="stSidebar"] .block-container { padding: 1.5rem 1rem; }

h1,h2,h3,h4 { font-family: 'Syne', sans-serif !important; }

.hero-title {
    font-family: 'Syne', sans-serif;
    font-size: 2.8rem;
    font-weight: 800;
    background: linear-gradient(135deg, #ffffff 0%, #94b4d4 60%, #4a90d9 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    line-height: 1.1;
    margin-bottom: 0.25rem;
}
.hero-sub {
    color: #4a6280;
    font-size: 0.85rem;
    font-family: 'JetBrains Mono', monospace;
    letter-spacing: 0.05em;
    margin-bottom: 1.5rem;
}
.scan-box {
    background: #0d1520;
    border: 1px solid #1e3050;
    border-radius: 16px;
    padding: 1.75rem;
    margin-bottom: 1.5rem;
    position: relative;
    overflow: hidden;
}
.scan-box::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, #1e3050, #4a90d9, #1e3050);
}
.metric-card {
    background: #0d1520;
    border: 1px solid #1e3050;
    border-radius: 12px;
    padding: 1.1rem 1.25rem;
    text-align: center;
}
.metric-value {
    font-family: 'Syne', sans-serif;
    font-size: 2.2rem;
    font-weight: 800;
    color: #ffffff;
    line-height: 1;
    margin-bottom: 0.2rem;
}
.metric-label {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.65rem;
    color: #4a6280;
    letter-spacing: 0.1em;
    text-transform: uppercase;
}
.section-title {
    font-family: 'Syne', sans-serif;
    font-size: 0.65rem;
    font-weight: 600;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    color: #4a6280;
    margin-bottom: 0.6rem;
    margin-top: 1rem;
    padding-bottom: 0.4rem;
    border-bottom: 1px solid #1a2535;
}
.exec-box {
    background: #0a1520;
    border: 1px solid #1e3050;
    border-radius: 10px;
    padding: 1.25rem;
    font-size: 0.875rem;
    color: #8aaac8;
    line-height: 1.8;
    margin-bottom: 1rem;
}
.progress-bar-bg {
    background: #1a2535;
    border-radius: 4px;
    height: 5px;
    overflow: hidden;
    margin-top: 0.3rem;
}
.finding-history-card {
    background: #0a1018;
    border: 1px solid #1a2535;
    border-radius: 10px;
    padding: 1rem 1.25rem;
    margin-bottom: 0.5rem;
    border-left: 3px solid;
}
.sidebar-logo {
    font-family: 'Syne', sans-serif;
    font-size: 1rem;
    font-weight: 800;
    color: #ffffff;
    margin-bottom: 0.1rem;
}
.sidebar-sub {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.6rem;
    color: #4a6280;
    letter-spacing: 0.08em;
    margin-bottom: 1rem;
}

/* Streamlit widget overrides */
.stTextInput > div > div > input {
    background: #0d1520 !important;
    border: 1px solid #1e3050 !important;
    border-radius: 10px !important;
    color: #e8f0f8 !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.9rem !important;
    padding: 0.7rem 1rem !important;
}
.stTextInput > div > div > input:focus {
    border-color: #4a90d9 !important;
    box-shadow: 0 0 0 3px rgba(74,144,217,0.15) !important;
}
.stButton > button {
    background: linear-gradient(135deg, #1e4080, #4a90d9) !important;
    color: white !important;
    border: none !important;
    border-radius: 10px !important;
    font-family: 'Syne', sans-serif !important;
    font-weight: 700 !important;
    font-size: 0.9rem !important;
    padding: 0.6rem 1.5rem !important;
    width: 100% !important;
    transition: opacity 0.2s !important;
}
.stButton > button:hover { opacity: 0.85 !important; }
.stCheckbox > label { color: #6a8aaa !important; }
div[data-testid="stExpander"] {
    background: #0a1018 !important;
    border: 1px solid #1a2535 !important;
    border-radius: 10px !important;
    margin-bottom: 0.5rem !important;
}
div[data-testid="stExpander"] summary { color: #c8d8e8 !important; font-family: 'Syne', sans-serif !important; font-weight: 600 !important; }
div[data-testid="stTab"] button { font-family: 'Syne', sans-serif !important; font-weight: 600 !important; }
</style>
""", unsafe_allow_html=True)

# ── Severity config ───────────────────────────────────────────────────────
SEV = {
    "CRITICAL": {"color": "#ff3c5a", "bg": "rgba(255,60,90,0.12)",   "icon": "🔴"},
    "HIGH":     {"color": "#ff8c42", "bg": "rgba(255,140,66,0.12)",  "icon": "🟠"},
    "MEDIUM":   {"color": "#ffd166", "bg": "rgba(255,209,102,0.12)", "icon": "🟡"},
    "LOW":      {"color": "#06d6a0", "bg": "rgba(6,214,160,0.12)",   "icon": "🟢"},
    "INFO":     {"color": "#4a90d9", "bg": "rgba(74,144,217,0.12)",  "icon": "🔵"},
}

# ── CWE / OWASP / MITRE ATT&CK education lookup ──────────────────────────
# Maps vuln_type prefix → reference identifiers shown as badges in the UI.
VULN_EDUCATION: dict[str, dict] = {
    "SQL Injection (Error-Based)": {
        "cwe": "CWE-89", "owasp": "A03:2021",
        "mitre": "T1190", "mitre_name": "Exploit Public-Facing Application",
        "cwe_url":   "https://cwe.mitre.org/data/definitions/89.html",
        "owasp_url": "https://owasp.org/Top10/A03_2021-Injection/",
        "mitre_url": "https://attack.mitre.org/techniques/T1190/",
    },
    "SQL Injection (Boolean-Based Blind)": {
        "cwe": "CWE-89", "owasp": "A03:2021", "mitre": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "cwe_url":   "https://cwe.mitre.org/data/definitions/89.html",
        "owasp_url": "https://owasp.org/Top10/A03_2021-Injection/",
        "mitre_url": "https://attack.mitre.org/techniques/T1190/",
    },
    "Cross-Site Scripting (Reflected XSS)": {
        "cwe": "CWE-79", "owasp": "A03:2021", "mitre": "T1059.007",
        "mitre_name": "JavaScript",
        "cwe_url":   "https://cwe.mitre.org/data/definitions/79.html",
        "owasp_url": "https://owasp.org/Top10/A03_2021-Injection/",
        "mitre_url": "https://attack.mitre.org/techniques/T1059/007/",
    },
    "Cross-Site Scripting (DOM-based Indicator)": {
        "cwe": "CWE-79", "owasp": "A03:2021", "mitre": "T1059.007",
        "mitre_name": "JavaScript",
        "cwe_url":   "https://cwe.mitre.org/data/definitions/79.html",
        "owasp_url": "https://owasp.org/Top10/A03_2021-Injection/",
        "mitre_url": "https://attack.mitre.org/techniques/T1059/007/",
    },
    "Server-Side Template Injection (SSTI)": {
        "cwe": "CWE-94", "owasp": "A03:2021", "mitre": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "cwe_url":   "https://cwe.mitre.org/data/definitions/94.html",
        "owasp_url": "https://owasp.org/Top10/A03_2021-Injection/",
        "mitre_url": "https://attack.mitre.org/techniques/T1190/",
    },
    "Open Redirect": {
        "cwe": "CWE-601", "owasp": "A01:2021", "mitre": "T1566",
        "mitre_name": "Phishing",
        "cwe_url":   "https://cwe.mitre.org/data/definitions/601.html",
        "owasp_url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        "mitre_url": "https://attack.mitre.org/techniques/T1566/",
    },
    "CORS Misconfiguration: Wildcard Origin": {
        "cwe": "CWE-942", "owasp": "A05:2021", "mitre": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "cwe_url":   "https://cwe.mitre.org/data/definitions/942.html",
        "owasp_url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        "mitre_url": "https://attack.mitre.org/techniques/T1190/",
    },
    "TLS: Certificate Expired": {
        "cwe": "CWE-295", "owasp": "A02:2021", "mitre": "T1557",
        "mitre_name": "Adversary-in-the-Middle",
        "cwe_url":   "https://cwe.mitre.org/data/definitions/295.html",
        "owasp_url": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        "mitre_url": "https://attack.mitre.org/techniques/T1557/",
    },
    "TLS: Weak Protocol": {
        "cwe": "CWE-326", "owasp": "A02:2021", "mitre": "T1557",
        "mitre_name": "Adversary-in-the-Middle",
        "cwe_url":   "https://cwe.mitre.org/data/definitions/326.html",
        "owasp_url": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        "mitre_url": "https://attack.mitre.org/techniques/T1557/",
    },
    "Insecure Transport: No HTTPS": {
        "cwe": "CWE-319", "owasp": "A02:2021", "mitre": "T1040",
        "mitre_name": "Network Sniffing",
        "cwe_url":   "https://cwe.mitre.org/data/definitions/319.html",
        "owasp_url": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        "mitre_url": "https://attack.mitre.org/techniques/T1040/",
    },
    "Directory Listing Enabled": {
        "cwe": "CWE-548", "owasp": "A05:2021", "mitre": "T1083",
        "mitre_name": "File and Directory Discovery",
        "cwe_url":   "https://cwe.mitre.org/data/definitions/548.html",
        "owasp_url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        "mitre_url": "https://attack.mitre.org/techniques/T1083/",
    },
    "Secret Exposure": {
        "cwe": "CWE-312", "owasp": "A02:2021", "mitre": "T1552",
        "mitre_name": "Unsecured Credentials",
        "cwe_url":   "https://cwe.mitre.org/data/definitions/312.html",
        "owasp_url": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        "mitre_url": "https://attack.mitre.org/techniques/T1552/",
    },
}


def _get_education(vuln_type: str) -> dict:
    """Match vuln_type to education data by prefix. Returns empty dict if no match."""
    for key, data in VULN_EDUCATION.items():
        if vuln_type.startswith(key) or key in vuln_type:
            return data
    return {}


def render_education_badges(vuln_type: str):
    """Render CWE / OWASP / MITRE ATT&CK reference badges for a finding."""
    edu = _get_education(vuln_type)
    if not edu:
        return

    badge_html = '<div style="display:flex;gap:0.4rem;flex-wrap:wrap;margin-top:0.5rem;">'

    if edu.get("cwe"):
        badge_html += (
            f'<a href="{edu.get("cwe_url","#")}" target="_blank" style="text-decoration:none;">'
            f'<span style="font-family:JetBrains Mono,monospace;font-size:0.6rem;padding:0.15rem 0.5rem;'
            f'border-radius:3px;background:rgba(255,140,66,0.15);color:#ff8c42;'
            f'border:1px solid rgba(255,140,66,0.3);">{edu["cwe"]}</span></a>'
        )
    if edu.get("owasp"):
        badge_html += (
            f'<a href="{edu.get("owasp_url","#")}" target="_blank" style="text-decoration:none;">'
            f'<span style="font-family:JetBrains Mono,monospace;font-size:0.6rem;padding:0.15rem 0.5rem;'
            f'border-radius:3px;background:rgba(74,144,217,0.15);color:#4a90d9;'
            f'border:1px solid rgba(74,144,217,0.3);">OWASP {edu["owasp"]}</span></a>'
        )
    if edu.get("mitre"):
        badge_html += (
            f'<a href="{edu.get("mitre_url","#")}" target="_blank" style="text-decoration:none;">'
            f'<span style="font-family:JetBrains Mono,monospace;font-size:0.6rem;padding:0.15rem 0.5rem;'
            f'border-radius:3px;background:rgba(255,60,90,0.12);color:#ff3c5a;'
            f'border:1px solid rgba(255,60,90,0.3);">'
            f'MITRE {edu["mitre"]} · {edu.get("mitre_name","")}</span></a>'
        )

    badge_html += "</div>"
    st.markdown(badge_html, unsafe_allow_html=True)

# ── Cached API calls — FIX 1: stops lag by caching sidebar data ───────────
@st.cache_data(ttl=15)   # refresh every 15 seconds, not on every rerun
def fetch_stats():
    try:
        r = req.get(f"{API_BASE}/stats", headers=_AUTH_HEADERS, timeout=5)
        return r.json() if r.status_code == 200 else {}
    except Exception:
        return {}

@st.cache_data(ttl=10)
def fetch_history(limit=8):
    try:
        r = req.get(f"{API_BASE}/history?limit={limit}", headers=_AUTH_HEADERS, timeout=5)
        return r.json() if r.status_code == 200 else {}
    except Exception:
        return {}

def api_post(endpoint, data):
    try:
        r = req.post(f"{API_BASE}{endpoint}", json=data, headers=_AUTH_HEADERS, timeout=10)
        return r.json()
    except Exception as e:
        st.error(f"API error: {e} — Is `uvicorn main:app --reload` running?")
        return None

def api_get(endpoint):
    try:
        r = req.get(f"{API_BASE}{endpoint}", headers=_AUTH_HEADERS, timeout=10)
        return r.json() if r.status_code == 200 else None
    except Exception:
        return None

def api_delete(endpoint) -> bool:
    """DELETE request — returns True on success (200/204)."""
    try:
        r = req.delete(f"{API_BASE}{endpoint}", headers=_AUTH_HEADERS, timeout=10)
        return r.status_code in (200, 204)
    except Exception:
        return False

# ── FIX 3: robust remediation parser ─────────────────────────────────────
def parse_remediation(text: str) -> dict:
    """
    Parse AI remediation text into sections regardless of
    how newlines were stored (real \n or escaped \\n).
    Returns dict of section_name -> content.
    """
    if not text:
        return {}

    # Normalise escaped newlines that SQLite sometimes stores
    text = text.replace("\\n", "\n").strip()

    SECTION_KEYS = [
        "WHY IT MATTERS",
        "ATTACK SCENARIO",
        "HOW TO FIX",
        "SECURE CODE EXAMPLE",
        "REFERENCES",
    ]

    sections = {}
    current_key   = None
    current_lines = []

    for line in text.split("\n"):
        stripped = line.strip()
        matched  = False
        for key in SECTION_KEYS:
            if stripped.startswith(key):
                if current_key:
                    sections[current_key] = "\n".join(current_lines).strip()
                current_key   = key
                current_lines = []
                matched       = True
                break
        if not matched and current_key:
            current_lines.append(line)

    if current_key:
        sections[current_key] = "\n".join(current_lines).strip()

    return sections


# ── Finding card ──────────────────────────────────────────────────────────
def render_finding_card(f: dict):
    sev     = f.get("severity", "INFO")
    cfg     = SEV.get(sev, SEV["INFO"])
    cvss    = f.get("cvss_score")
    ai      = f.get("ai_verified")
    vuln    = f.get("vuln_type", "Unknown Finding")
    url     = f.get("url", "")
    detail  = f.get("detail", "")
    evidence= f.get("evidence", "")
    raw_rem = f.get("remediation", "")

    # Escape all attacker-controlled strings before injecting into raw HTML.
    # Evidence and detail come from scanned-site HTTP responses — a malicious
    # target could embed HTML/JS tokens in headers, error messages, or cookies.
    url_safe     = html_module.escape(url)
    detail_safe  = html_module.escape(detail)

    # Header line for expander
    cvss_str = f" · CVSS {cvss:.1f}" if cvss else ""
    ai_str   = " · ✦ AI" if ai == 1 else ""
    label    = f"{cfg['icon']} {vuln}{cvss_str}{ai_str}"

    # Auto-expand critical findings
    with st.expander(label, expanded=(sev == "CRITICAL")):

        # Severity pill + URL
        st.markdown(f"""
        <div style="margin-bottom:0.75rem;">
            <span style="padding:0.2rem 0.7rem; border-radius:4px; font-family:'JetBrains Mono',monospace;
                         font-size:0.7rem; background:{cfg['bg']}; color:{cfg['color']};
                         border:1px solid {cfg['color']}44;">{sev}</span>
            {"<span style='margin-left:0.5rem;padding:0.2rem 0.6rem;border-radius:4px;font-family:JetBrains Mono,monospace;font-size:0.65rem;background:rgba(74,144,217,0.12);color:#4a90d9;border:1px solid rgba(74,144,217,0.3);'>✦ AI Verified</span>" if ai==1 else ""}
        </div>
        <div style="font-family:'JetBrains Mono',monospace; font-size:0.72rem;
                    color:#4a6280; word-break:break-all; margin-bottom:0.75rem;">
            🔗 {url_safe}
        </div>
        """, unsafe_allow_html=True)

        # Education badges (CWE / OWASP / MITRE ATT&CK)
        render_education_badges(vuln)

        # What was found
        if detail:
            st.markdown('<div class="section-title">What Was Found</div>', unsafe_allow_html=True)
            st.markdown(f'<div style="font-size:0.875rem;color:#8aaac8;line-height:1.7;">{detail_safe}</div>', unsafe_allow_html=True)

        # Evidence — rendered via st.code (safe, no HTML injection path)
        if evidence:
            st.markdown('<div class="section-title">Evidence</div>', unsafe_allow_html=True)
            st.code(evidence, language=None)

        # Remediation — FIX 3: properly parsed sections
        if raw_rem:
            st.markdown('<div class="section-title">Remediation</div>', unsafe_allow_html=True)

            sections = parse_remediation(raw_rem)

            if sections:
                # AI-enriched: render each section properly
                for sec_name, sec_body in sections.items():
                    if not sec_body.strip():
                        continue

                    st.markdown(f"""
                    <div style="font-family:'JetBrains Mono',monospace; font-size:0.62rem;
                                letter-spacing:0.1em; color:#2a5080; text-transform:uppercase;
                                margin-top:0.75rem; margin-bottom:0.3rem;">{sec_name}</div>
                    """, unsafe_allow_html=True)

                    if sec_name == "SECURE CODE EXAMPLE":
                        # Clean code fences before rendering
                        code = sec_body
                        for fence in ["```python","```nginx","```apache","```javascript","```bash","```"]:
                            code = code.replace(fence, "")
                        st.code(code.strip())

                    elif sec_name == "HOW TO FIX":
                        # Render numbered steps
                        for line in sec_body.split("\n"):
                            line = line.strip()
                            if line:
                                st.markdown(f'<div style="font-size:0.875rem;color:#6a8aaa;line-height:1.7;margin-bottom:0.3rem;">{line}</div>', unsafe_allow_html=True)

                    elif sec_name == "REFERENCES":
                        for line in sec_body.split("\n"):
                            line = line.strip().lstrip("- ")
                            if line:
                                st.markdown(f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.72rem;color:#4a6280;">'
                                            f'<a href="{line}" target="_blank" style="color:#4a90d9;">{line}</a></div>',
                                            unsafe_allow_html=True)
                    else:
                        st.markdown(f'<div style="font-size:0.875rem;color:#6a8aaa;line-height:1.8;">{sec_body}</div>',
                                    unsafe_allow_html=True)
            else:
                # Plain text remediation (heuristic, no AI)
                st.markdown(f'<div style="font-size:0.875rem;color:#6a8aaa;line-height:1.7;">{raw_rem}</div>',
                            unsafe_allow_html=True)


# ── Risk score gauge ──────────────────────────────────────────────────────
def render_risk_gauge(score, overall_risk):
    if score is None:
        return
    RISK_COLORS = {"CRITICAL":"#ff3c5a","HIGH":"#ff8c42","MEDIUM":"#ffd166","LOW":"#06d6a0"}
    color = RISK_COLORS.get(overall_risk, "#4a6280")
    st.markdown(f"""
    <div style="text-align:center; padding:1.25rem 0 1rem;">
        <div style="font-family:'JetBrains Mono',monospace; font-size:0.6rem;
                    letter-spacing:0.15em; text-transform:uppercase; color:#4a6280; margin-bottom:0.4rem;">
            Risk Score
        </div>
        <div style="font-family:'Syne',sans-serif; font-size:4rem; font-weight:800;
                    color:{color}; line-height:1;">{score}</div>
        <div style="font-family:'Syne',sans-serif; font-size:0.75rem; font-weight:700;
                    color:{color}; letter-spacing:0.12em; margin-bottom:0.6rem;">{overall_risk or ''}</div>
        <div style="background:#1a2535; border-radius:6px; height:8px; overflow:hidden; margin:0 1rem;">
            <div style="background:{color}; height:100%; width:{score}%;
                        border-radius:6px; box-shadow:0 0 10px {color}66;"></div>
        </div>
    </div>
    """, unsafe_allow_html=True)


# ── Severity bars ─────────────────────────────────────────────────────────
def render_severity_bars(summary_json):
    if not summary_json:
        return
    by_sev = summary_json.get("by_severity", {})
    total  = max(summary_json.get("total_findings", 1), 1)
    st.markdown('<div class="section-title">Breakdown</div>', unsafe_allow_html=True)
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
        count = by_sev.get(sev, 0)
        cfg   = SEV[sev]
        pct   = (count / total) * 100 if count else 0
        st.markdown(f"""
        <div style="margin-bottom:0.5rem;">
            <div style="display:flex;justify-content:space-between;margin-bottom:0.15rem;">
                <span style="font-family:'JetBrains Mono',monospace;font-size:0.68rem;color:{cfg['color']};">
                    {cfg['icon']} {sev}
                </span>
                <span style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;
                             color:#ffffff;font-weight:600;">{count}</span>
            </div>
            <div class="progress-bar-bg">
                <div style="background:{cfg['color']};height:100%;width:{pct}%;
                            border-radius:4px;box-shadow:0 0 5px {cfg['color']}66;"></div>
            </div>
        </div>
        """, unsafe_allow_html=True)


# ── Executive summary ─────────────────────────────────────────────────────
def render_exec_summary(exec_summary):
    if not exec_summary:
        return
    text = exec_summary.get("executive_summary","")
    if text:
        st.markdown('<div class="section-title">AI Executive Summary</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="exec-box">{text}</div>', unsafe_allow_html=True)

    col1, col2 = st.columns(2)
    with col1:
        risks = exec_summary.get("key_risks",[])
        if risks:
            st.markdown('<div class="section-title">Key Risks</div>', unsafe_allow_html=True)
            for r in risks:
                st.markdown(f'<div style="font-size:0.875rem;color:#8aaac8;line-height:1.7;margin-bottom:0.4rem;">▸ {r}</div>', unsafe_allow_html=True)
    with col2:
        actions = exec_summary.get("immediate_actions",[])
        if actions:
            st.markdown('<div class="section-title">Immediate Actions</div>', unsafe_allow_html=True)
            for i,a in enumerate(actions,1):
                st.markdown(f"""
                <div style="display:flex;gap:0.6rem;margin-bottom:0.4rem;align-items:flex-start;">
                    <span style="font-family:'JetBrains Mono',monospace;font-size:0.65rem;color:#4a90d9;
                                 background:rgba(74,144,217,0.12);padding:0.1rem 0.35rem;
                                 border-radius:3px;flex-shrink:0;">0{i}</span>
                    <span style="font-size:0.875rem;color:#8aaac8;line-height:1.6;">{a}</span>
                </div>
                """, unsafe_allow_html=True)


# ── Full results renderer ─────────────────────────────────────────────────
def render_results(results: dict):
    if not results:
        return

    findings     = results.get("findings", [])
    summary_json = results.get("summary_json") or {}
    exec_summary = results.get("exec_summary") or {}
    total        = results.get("total_findings", 0)
    pages        = results.get("pages_crawled", 0)
    duration     = results.get("duration_secs") or 0
    risk_score   = results.get("risk_score")
    overall_risk = results.get("overall_risk")
    target       = results.get("target_url","")
    by_sev       = summary_json.get("by_severity", {})

    st.divider()

    # Target info
    st.markdown(f"""
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.7rem;color:#4a6280;margin-bottom:1rem;">
        🎯 {target} &nbsp;·&nbsp; {pages} page(s) &nbsp;·&nbsp; {duration:.0f}s
    </div>""", unsafe_allow_html=True)

    # Metric cards
    c1,c2,c3,c4 = st.columns(4)
    cards = [
        (total, "Total Findings", "#ffffff"),
        (by_sev.get("CRITICAL",0), "Critical", "#ff3c5a" if by_sev.get("CRITICAL",0) else "#2a4060"),
        (by_sev.get("HIGH",0),     "High",     "#ff8c42" if by_sev.get("HIGH",0)     else "#2a4060"),
        (by_sev.get("MEDIUM",0),   "Medium",   "#ffd166" if by_sev.get("MEDIUM",0)   else "#2a4060"),
    ]
    for col, (val, label, color) in zip([c1,c2,c3,c4], cards):
        with col:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-value" style="color:{color};">{val}</div>
                <div class="metric-label">{label}</div>
            </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Risk gauge + breakdown | Executive summary
    col_left, col_right = st.columns([1,2])
    with col_left:
        render_risk_gauge(risk_score, overall_risk)
        render_severity_bars(summary_json)
    with col_right:
        render_exec_summary(exec_summary)

    st.divider()

    # Findings section
    if not findings:
        st.success("🎉 No vulnerabilities found!")
        return

    st.markdown(f"""
    <div style="font-family:'Syne',sans-serif;font-weight:700;font-size:1.05rem;
                color:#e8f0f8;margin-bottom:0.2rem;">Detailed Findings</div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.7rem;
                color:#4a6280;margin-bottom:1rem;">
        {total} finding(s) sorted by severity · Click to expand each finding
    </div>""", unsafe_allow_html=True)

    # Filters
    fc1, fc2 = st.columns([3,2])
    with fc1:
        filter_sev = st.multiselect(
            "Severity filter",
            ["CRITICAL","HIGH","MEDIUM","LOW","INFO"],
            default=["CRITICAL","HIGH","MEDIUM","LOW","INFO"],
            label_visibility="collapsed",
        )
    with fc2:
        ai_only = st.checkbox("AI-verified findings only", value=False)

    filtered = [
        f for f in findings
        if f.get("severity") in filter_sev
        and (not ai_only or f.get("ai_verified") == 1)
    ]

    st.markdown(f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.68rem;color:#4a6280;margin-bottom:0.75rem;">Showing {len(filtered)} of {total}</div>', unsafe_allow_html=True)

    for f in filtered:
        render_finding_card(f)

    # Optional export — downloads are secondary, viewing inline is primary
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown('<div class="section-title">Export Report (Optional)</div>', unsafe_allow_html=True)
    d1, d2, _ = st.columns([1,1,2])
    with d1:
        st.download_button(
            "⬇ JSON Report",
            data=json.dumps(results, indent=2, default=str),
            file_name=f"scan_{results.get('id','x')[:8]}.json",
            mime="application/json",
            use_container_width=True,
        )
    with d2:
        st.download_button(
            "⬇ TXT Report",
            data=build_text_report(results),
            file_name=f"scan_{results.get('id','x')[:8]}.txt",
            mime="text/plain",
            use_container_width=True,
        )


# ── Text report ───────────────────────────────────────────────────────────
def build_text_report(results: dict) -> str:
    lines = ["="*60,"  WebPenTest AI Toolkit — Security Report","="*60]
    lines += [
        f"  Target   : {results.get('target_url')}",
        f"  Scanned  : {results.get('started_at','')[:16]}",
        f"  Risk     : {results.get('overall_risk','N/A')} ({results.get('risk_score','?')}/100)",
        f"  Findings : {results.get('total_findings',0)}","",
    ]
    es = results.get("exec_summary") or {}
    if es.get("executive_summary"):
        lines += ["EXECUTIVE SUMMARY","-"*40, es["executive_summary"],""]
        if es.get("immediate_actions"):
            lines.append("IMMEDIATE ACTIONS:")
            for i,a in enumerate(es["immediate_actions"],1):
                lines.append(f"  {i}. {a}")
            lines.append("")

    lines += ["FINDINGS","-"*40]
    for f in results.get("findings",[]):
        lines += [
            f"\n[{f.get('severity')}] {f.get('vuln_type')}",
            f"  URL      : {f.get('url')}",
            f"  CVSS     : {f.get('cvss_score','N/A')}",
            f"  Detail   : {f.get('detail','')}",
            f"  Evidence : {f.get('evidence','')}",
        ]
        rem = f.get("remediation","")
        if rem:
            sections = parse_remediation(rem)
            if sections:
                for k,v in sections.items():
                    lines.append(f"\n  {k}:")
                    for ln in v.split("\n"):
                        if ln.strip():
                            lines.append(f"    {ln.strip()}")
            else:
                lines.append(f"  Fix: {rem[:400]}")
        lines.append("")

    lines += ["="*60,"  Authorized security testing only."]
    return "\n".join(lines)


# ── Sidebar ───────────────────────────────────────────────────────────────
def render_sidebar():
    with st.sidebar:
        st.markdown('<div class="sidebar-logo">🛡️ WebPenTest AI</div>', unsafe_allow_html=True)
        st.markdown('<div class="sidebar-sub">v1.3 · Authorized Testing Only</div>', unsafe_allow_html=True)
        st.divider()

        # FIX 1: cached — won't re-fetch on every interaction
        stats = fetch_stats()
        if stats:
            st.markdown('<div style="font-family:JetBrains Mono,monospace;font-size:0.6rem;letter-spacing:0.12em;text-transform:uppercase;color:#2a4060;margin-bottom:0.5rem;">Overview</div>', unsafe_allow_html=True)
            c1,c2 = st.columns(2)
            with c1:
                st.metric("Scans",    stats.get("total_scans",0))
                st.metric("Critical", stats.get("critical_findings",0))
            with c2:
                st.metric("Findings", stats.get("total_findings",0))
                st.metric("High",     stats.get("high_findings",0))

        st.divider()

        history = fetch_history(8)
        if history and history.get("scans"):
            st.markdown('<div style="font-family:JetBrains Mono,monospace;font-size:0.6rem;letter-spacing:0.12em;text-transform:uppercase;color:#2a4060;margin-bottom:0.5rem;">Recent Scans</div>', unsafe_allow_html=True)
            for scan in history["scans"]:
                url    = scan.get("target_url","").replace("https://","").replace("http://","")[:30]
                risk   = scan.get("overall_risk","")
                score  = scan.get("risk_score","?")
                status = scan.get("status","")
                cfg    = SEV.get(risk, {"color":"#4a6280","icon":"⚪"})
                icon   = "✅" if status=="complete" else "⏳" if status=="running" else "❌"
                st.markdown(f"""
                <div style="background:#0d1520;border:1px solid #1a2535;border-radius:7px;
                            padding:0.5rem 0.7rem;margin-bottom:0.35rem;">
                    <div style="font-family:'JetBrains Mono',monospace;font-size:0.68rem;color:#6a8aaa;
                                white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">
                        {icon} {url}
                    </div>
                    <div style="font-size:0.62rem;color:{cfg['color']};margin-top:0.1rem;">
                        {cfg['icon']} {risk or 'N/A'} · {score}/100
                    </div>
                </div>""", unsafe_allow_html=True)

        st.divider()
        st.markdown('<div style="font-family:JetBrains Mono,monospace;font-size:0.58rem;color:#2a4060;line-height:1.8;">⚠️ Authorized testing only.<br>Get written permission first.</div>', unsafe_allow_html=True)


# ── Polling ───────────────────────────────────────────────────────────────
MAX_POLL_SECONDS = 300   # 5-minute hard cap — no infinite loops

def poll_until_complete(scan_id: str, status_ph, progress_ph):
    messages = [
        "🔍 Crawling site pages...",
        "🔎 Checking security headers...",
        "💉 Testing for SQL injection...",
        "⚡ Testing for XSS vulnerabilities...",
        "📂 Scanning for exposed files...",
        "🤖 Running AI analysis...",
        "📝 Generating report...",
    ]
    idx = 0; elapsed = 0
    while elapsed < MAX_POLL_SECONDS:
        status = api_get(f"/scan/{scan_id}/status")
        if not status:
            time.sleep(3); elapsed += 3; continue

        if status["status"] == "complete":
            progress_ph.progress(1.0)
            status_ph.success("✅ Scan complete!")
            return api_get(f"/scan/{scan_id}")

        if status["status"] == "failed":
            status_ph.error(f"❌ {status.get('error','Scan failed')}")
            return None

        progress_ph.progress(min(0.9, elapsed / MAX_POLL_SECONDS))
        status_ph.info(messages[idx % len(messages)])
        idx += 1; time.sleep(4); elapsed += 4

    status_ph.error(f"⏱ Scan timed out after {MAX_POLL_SECONDS}s. Check History tab for results.")
    return None


# ── Main app ──────────────────────────────────────────────────────────────
def main():
    render_sidebar()

    st.markdown("""
    <div class="hero-title">Web Application<br>Security Scanner</div>
    <div class="hero-sub">// ai-powered · owasp top 10 · real-time analysis</div>
    """, unsafe_allow_html=True)

    tab_scan, tab_history, tab_about = st.tabs(["🔍 New Scan", "📋 History", "ℹ️ How It Works"])

    # ── session state bootstrap ────────────────────────────────────────────
    if "active_tab" not in st.session_state:
        st.session_state["active_tab"] = "scan"
    if "history_view_id" not in st.session_state:
        st.session_state["history_view_id"] = None
    if "confirm_delete_id" not in st.session_state:
        st.session_state["confirm_delete_id"] = None

    # ════════════════════════════════════════════════════════════════════
    with tab_scan:
        st.markdown('<div class="scan-box">', unsafe_allow_html=True)
        st.markdown("""
        <div style="font-family:'Syne',sans-serif;font-size:1.05rem;font-weight:700;
                    color:#e8f0f8;margin-bottom:0.2rem;">Start a Security Scan</div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;
                    color:#4a6280;margin-bottom:1.1rem;">
            Enter any website URL. Our AI crawls it, finds vulnerabilities,
            and generates a full report with remediation steps.
        </div>""", unsafe_allow_html=True)

        ci, cb = st.columns([4,1])
        with ci:
            target_url = st.text_input("URL", placeholder="https://example.com",
                                       label_visibility="collapsed")
        with cb:
            clicked = st.button("⚡ Scan", use_container_width=True)

        ca, cc = st.columns(2)
        with ca:
            enable_ai = st.checkbox("✦ AI Analysis", value=True,
                                    help="AI verifies findings and writes fix instructions.")
        with cc:
            max_pages = st.slider("Pages to crawl", 1, 50, 20)

        st.markdown('</div>', unsafe_allow_html=True)

        if clicked:
            if not target_url:
                st.warning("⚠️ Enter a target URL first.")
            else:
                url = target_url.strip()
                if not url.startswith(("http://","https://")):
                    url = "https://" + url

                resp = api_post("/scan", {"target_url":url,"enable_ai":enable_ai,"max_pages":max_pages})
                if resp and "scan_id" in resp:
                    scan_id = resp["scan_id"]
                    st.info(f"🚀 Scan started · `{scan_id[:8]}...`")
                    s_ph = st.empty(); p_ph = st.empty()
                    results = poll_until_complete(scan_id, s_ph, p_ph)
                    if results:
                        st.session_state["last_results"] = results
                        st.session_state["active_tab"]   = "scan"
                        fetch_stats.clear()   # refresh sidebar stats
                        fetch_history.clear()
                        st.rerun()

        # Show results if they belong to this tab
        if st.session_state.get("last_results") and st.session_state.get("active_tab") == "scan":
            render_results(st.session_state["last_results"])

    # ════════════════════════════════════════════════════════════════════
    with tab_history:
        # ── if a scan is open, show its full results inline ───────────────
        if st.session_state["history_view_id"]:
            view_id = st.session_state["history_view_id"]

            # Back button — clears the view
            if st.button("← Back to History", key="back_btn"):
                st.session_state["history_view_id"] = None
                st.session_state["last_results"]    = None
                st.session_state["active_tab"]      = "history"
                st.rerun()

            # Load + render
            if st.session_state.get("last_results") and \
               st.session_state["last_results"].get("id") == view_id:
                full = st.session_state["last_results"]
            else:
                full = api_get(f"/scan/{view_id}")
                if full:
                    st.session_state["last_results"] = full

            if full:
                render_results(full)
            else:
                st.error("Could not load scan results. The scan may have been deleted.")
                st.session_state["history_view_id"] = None

        else:
            # ── History list view ─────────────────────────────────────────
            history = api_get("/history?limit=50")

            if not history or not history.get("scans"):
                st.info("No scans yet. Run your first scan above.")
            else:
                scans = history["scans"]

                # Header row
                col_hdr, col_refresh = st.columns([4, 1])
                with col_hdr:
                    st.markdown(
                        f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.7rem;'
                        f'color:#4a6280;margin-bottom:1rem;">'
                        f'{len(scans)} scan(s) in history</div>',
                        unsafe_allow_html=True,
                    )
                with col_refresh:
                    if st.button("↺ Refresh", key="refresh_history", use_container_width=True):
                        fetch_history.clear()
                        st.rerun()

                for scan in scans:
                    scan_id  = scan.get("id", "")
                    url      = scan.get("target_url", "")
                    risk     = scan.get("overall_risk", "")
                    score    = scan.get("risk_score", "?")
                    total    = scan.get("total_findings", 0)
                    status   = scan.get("status", "")
                    started  = scan.get("started_at", "")[:16].replace("T", " ")
                    duration = scan.get("duration_secs") or 0
                    cfg      = SEV.get(risk, {"color": "#4a6280", "icon": "⚪"})
                    s_color  = "#06d6a0" if status == "complete" else "#ffd166" if status == "running" else "#ff3c5a"
                    s_icon   = "✓" if status == "complete" else "●" if status == "running" else "✗"
                    by_sev   = (scan.get("summary_json") or {}).get("by_severity", {})

                    st.markdown(f"""
                    <div class="finding-history-card" style="border-left-color:{cfg['color']};">
                        <div style="display:flex;justify-content:space-between;align-items:center;">
                            <div style="flex:1;min-width:0;">
                                <div style="font-family:'Syne',sans-serif;font-weight:700;
                                            color:#e8f0f8;font-size:0.9rem;margin-bottom:0.2rem;
                                            white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">
                                    {html_module.escape(url)}
                                </div>
                                <div style="font-family:'JetBrains Mono',monospace;font-size:0.68rem;color:#4a6280;">
                                    <span style="color:{s_color};">{s_icon} {status.upper()}</span>
                                    &nbsp;·&nbsp; {started}
                                    &nbsp;·&nbsp; {duration:.0f}s
                                    &nbsp;·&nbsp; {total} finding(s)
                                </div>
                            </div>
                            <div style="text-align:right;flex-shrink:0;margin-left:1rem;">
                                <div style="font-family:'Syne',sans-serif;font-size:1.6rem;
                                            font-weight:800;color:{cfg['color']};line-height:1;">{score}</div>
                                <div style="font-family:'JetBrains Mono',monospace;font-size:0.62rem;
                                            color:{cfg['color']};">{risk or 'N/A'}</div>
                            </div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

                    # ── action buttons row ────────────────────────────────
                    b1, b2, b3, _ = st.columns([1, 1, 1, 3])

                    with b1:
                        if st.button("📄 View", key=f"view_{scan_id}",
                                     use_container_width=True,
                                     disabled=(status != "complete")):
                            st.session_state["history_view_id"] = scan_id
                            st.session_state["active_tab"]      = "history"
                            st.session_state["last_results"]    = None  # force fresh load
                            st.session_state["confirm_delete_id"] = None
                            st.rerun()

                    with b2:
                        # Download JSON without navigating away
                        if status == "complete":
                            full_for_dl = api_get(f"/scan/{scan_id}")
                            if full_for_dl:
                                st.download_button(
                                    "⬇ JSON",
                                    data=json.dumps(full_for_dl, indent=2, default=str),
                                    file_name=f"scan_{scan_id[:8]}.json",
                                    mime="application/json",
                                    key=f"dl_{scan_id}",
                                    use_container_width=True,
                                )
                        else:
                            st.button("⬇ JSON", key=f"dl_{scan_id}",
                                      disabled=True, use_container_width=True)

                    with b3:
                        # Two-step delete: first click shows confirm, second click deletes
                        if st.session_state["confirm_delete_id"] == scan_id:
                            if st.button("⚠️ Confirm Delete", key=f"del_confirm_{scan_id}",
                                         use_container_width=True):
                                ok = api_delete(f"/scan/{scan_id}")
                                st.session_state["confirm_delete_id"] = None
                                fetch_history.clear()
                                fetch_stats.clear()
                                if ok:
                                    st.success(f"Scan `{scan_id[:8]}...` deleted.")
                                else:
                                    st.error("Delete failed. Try again.")
                                st.rerun()
                        else:
                            if st.button("🗑 Delete", key=f"del_{scan_id}",
                                         use_container_width=True):
                                st.session_state["confirm_delete_id"] = scan_id
                                st.rerun()

                    st.markdown("<div style='margin-bottom:0.5rem;'></div>",
                                unsafe_allow_html=True)

    # ════════════════════════════════════════════════════════════════════
    with tab_about:
        st.markdown('<div style="max-width:680px;">', unsafe_allow_html=True)
        st.markdown("""
        <div style="font-family:'Syne',sans-serif;font-size:1.2rem;font-weight:800;
                    color:#e8f0f8;margin-bottom:0.5rem;">How WebPenTest AI Works</div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;
                    color:#4a6280;margin-bottom:1.5rem;">4-stage automated security pipeline</div>
        """, unsafe_allow_html=True)

        for num,title,color,desc in [
            ("01","Crawl",   "#4a90d9", "Discovers all pages by following links within the same domain. Builds a complete map of the attack surface before any testing."),
            ("02","Scan",    "#06d6a0", "Runs 30+ checks across every page: security headers, SQL injection, XSS, open redirects, 25 sensitive file paths, CORS, cookies, and more."),
            ("03","AI",      "#ffd166", "Sends HIGH/CRITICAL findings to the configured AI provider. AI verifies each finding, assigns a CVSS score, writes an attack scenario, and generates fix instructions with code."),
            ("04","Report",  "#ff8c42", "Structured output sorted by severity. Every finding shows what was found, why it matters, and exactly how to fix it. Export as JSON or TXT."),
        ]:
            st.markdown(f"""
            <div style="display:flex;gap:1rem;margin-bottom:1rem;align-items:flex-start;">
                <div style="font-family:'Syne',sans-serif;font-size:1.3rem;font-weight:800;
                            color:{color};opacity:0.35;flex-shrink:0;">{num}</div>
                <div>
                    <div style="font-family:'Syne',sans-serif;font-weight:700;color:#e8f0f8;
                                font-size:0.95rem;margin-bottom:0.2rem;">{title}</div>
                    <div style="font-size:0.85rem;color:#6a8aaa;line-height:1.7;">{desc}</div>
                </div>
            </div>""", unsafe_allow_html=True)

        st.markdown('<div style="font-family:\'Syne\',sans-serif;font-weight:700;color:#e8f0f8;font-size:0.95rem;margin:1.5rem 0 0.75rem;">What We Check</div>', unsafe_allow_html=True)
        for name, detail in [
            ("Security Headers",     "CSP · HSTS · X-Frame-Options · X-Content-Type-Options · Referrer-Policy · Permissions-Policy"),
            ("SQL Injection",         "Error-based · Boolean-blind · Form surface detection"),
            ("Cross-Site Scripting",  "Reflected XSS · DOM-based sinks · Form input surfaces"),
            ("CORS",                  "Wildcard origins · Credentials + wildcard combinations"),
            ("Sensitive Files",       "25+ paths: .env · wp-config.php · .git · backups · admin panels"),
            ("Cookies",               "Missing HttpOnly · Secure · SameSite flags"),
            ("Transport Security",    "HTTPS enforcement · Mixed content"),
            ("Information Disclosure","Server version headers · Directory listing"),
            ("Open Redirect",         "URL parameter redirect hijacking"),
        ]:
            st.markdown(f"""
            <div style="display:flex;gap:0.6rem;margin-bottom:0.4rem;padding:0.55rem 0.7rem;
                        background:#0a1018;border-radius:7px;border:1px solid #1a2535;">
                <span style="color:#4a90d9;flex-shrink:0;">▸</span>
                <div>
                    <span style="font-family:'Syne',sans-serif;font-weight:700;color:#c8d8e8;
                                 font-size:0.85rem;">{name}</span>
                    <span style="font-family:'JetBrains Mono',monospace;font-size:0.68rem;
                                 color:#4a6280;margin-left:0.4rem;">{detail}</span>
                </div>
            </div>""", unsafe_allow_html=True)

        st.markdown('</div>', unsafe_allow_html=True)


main()