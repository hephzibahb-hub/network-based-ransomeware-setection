"""
SENTINEL — Email Alert Router
Sends a formatted threat-alert email to the admin when ransomware is detected.
Endpoint: POST /send-alert
"""

import smtplib
import socket
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

from fastapi import APIRouter
from pydantic import BaseModel

try:
    from app.api.smtp_config import SMTP_HOST, SMTP_PORT, SMTP_EMAIL, SMTP_PASSWORD
except ImportError:
    SMTP_HOST = "smtp.gmail.com"
    SMTP_PORT = 587
    SMTP_EMAIL = ""
    SMTP_PASSWORD = ""

alert_router = APIRouter()


# ------------------------------------------------------------------
# Request schema
# ------------------------------------------------------------------
class AlertRequest(BaseModel):
    admin_email: str
    filename: str
    verdict: str
    dominant_family: str
    malware_ratio: float
    total_rows: int
    benign_rows: int
    malicious_rows: int
    confidence_tier: str
    explanation: str
    model_used: str = "Random Forest"


# ------------------------------------------------------------------
# POST /send-alert
# ------------------------------------------------------------------
@alert_router.post("/send-alert")
def send_alert(req: AlertRequest):
    """Send a threat-alert email to the admin address."""

    if not SMTP_EMAIL or not SMTP_PASSWORD:
        return {
            "error": (
                "SMTP credentials not configured. "
                "Open app/api/smtp_config.py and fill in SMTP_EMAIL and SMTP_PASSWORD."
            )
        }

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"🚨 SENTINEL THREAT ALERT — {req.dominant_family} Detected"
    msg["From"]    = f"SENTINEL Security <{SMTP_EMAIL}>"
    msg["To"]      = req.admin_email

    msg.attach(MIMEText(_build_plain(req), "plain"))
    msg.attach(MIMEText(_build_html(req),  "html"))

    try:
        _smtp_send(SMTP_HOST, SMTP_PORT, SMTP_EMAIL, SMTP_PASSWORD, req.admin_email, msg)
        return {"success": True, "message": f"Alert sent to {req.admin_email}"}

    except smtplib.SMTPAuthenticationError:
        return {"error": "SMTP authentication failed. Check your Gmail App Password in smtp_config.py."}
    except (OSError, socket.timeout) as e:
        return {
            "error": str(e),
            "hint": (
                "[WinError 10060] Port 587 and 465 are both unreachable. "
                "Your network (college/work Wi-Fi or firewall) is blocking outbound SMTP. "
                "Try switching to a mobile hotspot, or disable Windows Firewall temporarily. "
                "Run: Test-NetConnection -ComputerName smtp.gmail.com -Port 587  in PowerShell to confirm."
            )
        }
    except Exception as e:
        return {"error": str(e)}


# ------------------------------------------------------------------
# SMTP send helper — tries port 587 (STARTTLS), falls back to 465 (SSL)
# ------------------------------------------------------------------
def _smtp_send(host, port, email, password, recipient, msg):
    """
    Attempt delivery via STARTTLS (port 587).
    If the connection is refused or times out (WinError 10060),
    automatically retry via SSL on port 465.
    """
    try:
        with smtplib.SMTP(host, port, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(email, password)
            server.sendmail(email, recipient, msg.as_string())
        return  # success on port 587
    except (OSError, socket.timeout, smtplib.SMTPException) as primary_err:
        # Port 587 failed — try port 465 (SSL)
        try:
            with smtplib.SMTP_SSL(host, 465, timeout=10) as server:
                server.login(email, password)
                server.sendmail(email, recipient, msg.as_string())
            return  # success on port 465
        except (OSError, socket.timeout):
            raise primary_err   # re-raise original error for caller to handle


# ------------------------------------------------------------------
# GET /alert-status  — lets the frontend check if SMTP is configured
# ------------------------------------------------------------------
@alert_router.get("/alert-status")
def alert_status():
    configured = bool(SMTP_EMAIL and SMTP_PASSWORD)
    return {
        "configured": configured,
        "sender": SMTP_EMAIL if configured else None
    }


# ------------------------------------------------------------------
# Email body builders
# ------------------------------------------------------------------
def _build_plain(r: AlertRequest) -> str:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "═" * 54,
        "  SENTINEL — RANSOMWARE THREAT ALERT",
        "═" * 54,
        f"  Timestamp   : {ts}",
        f"  File        : {r.filename}",
        f"  Verdict     : {r.verdict}",
        f"  Family      : {r.dominant_family}",
        f"  Ratio       : {r.malware_ratio * 100:.1f}% malicious",
        f"  Confidence  : {r.confidence_tier}",
        f"  Model       : {r.model_used}",
        "─" * 54,
        f"  Total Flows     : {r.total_rows}",
        f"  Benign Flows    : {r.benign_rows}",
        f"  Malicious Flows : {r.malicious_rows}",
        "─" * 54,
        f"  {r.explanation}",
        "═" * 54,
        "  Investigate immediately and isolate affected systems.",
        "═" * 54,
        "  Sent by SENTINEL Threat Intelligence Platform",
    ]
    return "\n".join(lines)


def _build_html(r: AlertRequest) -> str:
    ts      = datetime.now().strftime("%d %b %Y, %H:%M:%S")
    ratio   = f"{r.malware_ratio * 100:.1f}%"
    bar_pct = min(int(r.malware_ratio * 100), 100)
    bar_col = "#ff3355" if r.malware_ratio >= 0.5 else ("#ffaa00" if r.malware_ratio >= 0.2 else "#00ff9f")
    conf_col = {"High": "#ff3355", "Medium": "#ffaa00", "Low": "#00ff9f"}.get(r.confidence_tier, "#94a3b8")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SENTINEL Threat Alert</title>
</head>
<body style="margin:0;padding:0;background:#0a0f1e;font-family:'Segoe UI',Arial,sans-serif;color:#e2e8f0;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0f1e;padding:32px 16px;">
  <tr><td align="center">
  <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;">

    <!-- Header -->
    <tr>
      <td style="background:linear-gradient(135deg,#1a0a12,#2d0a1a);border:1px solid rgba(255,51,85,0.3);border-radius:16px 16px 0 0;padding:32px 36px;text-align:center;">
        <div style="font-size:42px;margin-bottom:12px;">🚨</div>
        <h1 style="margin:0 0 6px;font-size:24px;font-weight:700;color:#ff3355;letter-spacing:1px;">THREAT DETECTED</h1>
        <p style="margin:0;font-size:13px;color:#94a3b8;font-family:monospace;letter-spacing:1px;">SENTINEL THREAT INTELLIGENCE PLATFORM</p>
      </td>
    </tr>

    <!-- Verdict bar -->
    <tr>
      <td style="background:#ff3355;padding:12px 36px;text-align:center;">
        <span style="font-size:15px;font-weight:700;color:#fff;letter-spacing:1px;">
          ⚠️ &nbsp; {r.dominant_family.upper()} RANSOMWARE ACTIVITY CONFIRMED &nbsp; ⚠️
        </span>
      </td>
    </tr>

    <!-- Body -->
    <tr>
      <td style="background:#0d1120;border:1px solid rgba(255,51,85,0.2);border-top:none;border-radius:0 0 16px 16px;padding:32px 36px;">

        <!-- Meta info -->
        <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:28px;">
          <tr>
            <td style="padding:6px 0;font-size:12px;color:#64748b;font-family:monospace;text-transform:uppercase;letter-spacing:1px;width:140px;">Timestamp</td>
            <td style="padding:6px 0;font-size:13px;color:#e2e8f0;font-family:monospace;">{ts}</td>
          </tr>
          <tr>
            <td style="padding:6px 0;font-size:12px;color:#64748b;font-family:monospace;text-transform:uppercase;letter-spacing:1px;">Analyzed File</td>
            <td style="padding:6px 0;font-size:13px;color:#00d4ff;font-family:monospace;">{r.filename}</td>
          </tr>
          <tr>
            <td style="padding:6px 0;font-size:12px;color:#64748b;font-family:monospace;text-transform:uppercase;letter-spacing:1px;">Model Used</td>
            <td style="padding:6px 0;font-size:13px;color:#e2e8f0;font-family:monospace;">{r.model_used}</td>
          </tr>
        </table>

        <!-- Threat stats -->
        <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:28px;border-collapse:separate;border-spacing:8px;">
          <tr>
            <td style="background:#1a0a12;border:1px solid rgba(255,51,85,0.25);border-radius:10px;padding:16px;text-align:center;width:25%;">
              <div style="font-size:22px;font-weight:700;color:#ff3355;font-family:monospace;">{r.dominant_family}</div>
              <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:1px;margin-top:4px;">Family</div>
            </td>
            <td style="background:#0f1a1f;border:1px solid rgba(0,212,255,0.2);border-radius:10px;padding:16px;text-align:center;width:25%;">
              <div style="font-size:22px;font-weight:700;color:#00d4ff;font-family:monospace;">{r.total_rows:,}</div>
              <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:1px;margin-top:4px;">Total Flows</div>
            </td>
            <td style="background:#1a0a12;border:1px solid rgba(255,51,85,0.2);border-radius:10px;padding:16px;text-align:center;width:25%;">
              <div style="font-size:22px;font-weight:700;color:#ff3355;font-family:monospace;">{r.malicious_rows:,}</div>
              <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:1px;margin-top:4px;">Malicious</div>
            </td>
            <td style="background:#0a1a0f;border:1px solid rgba(0,255,159,0.2);border-radius:10px;padding:16px;text-align:center;width:25%;">
              <div style="font-size:22px;font-weight:700;color:#00ff9f;font-family:monospace;">{r.benign_rows:,}</div>
              <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:1px;margin-top:4px;">Benign</div>
            </td>
          </tr>
        </table>

        <!-- Malware ratio bar -->
        <div style="margin-bottom:28px;">
          <div style="display:flex;justify-content:space-between;margin-bottom:6px;">
            <span style="font-size:11px;color:#64748b;font-family:monospace;text-transform:uppercase;letter-spacing:1px;">Malware Ratio</span>
            <span style="font-size:12px;color:{bar_col};font-family:monospace;font-weight:700;">{ratio}</span>
          </div>
          <div style="background:rgba(255,255,255,0.06);border-radius:100px;height:8px;overflow:hidden;">
            <div style="background:{bar_col};width:{bar_pct}%;height:100%;border-radius:100px;"></div>
          </div>
        </div>

        <!-- Confidence badge -->
        <div style="margin-bottom:24px;display:flex;gap:8px;flex-wrap:wrap;">
          <span style="padding:5px 14px;background:rgba(255,51,85,0.1);border:1px solid rgba(255,51,85,0.3);border-radius:100px;font-size:11px;font-family:monospace;font-weight:700;color:#ff3355;text-transform:uppercase;">
            🚨 {r.verdict}
          </span>
          <span style="padding:5px 14px;background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1);border-radius:100px;font-size:11px;font-family:monospace;color:{conf_col};text-transform:uppercase;">
            {r.confidence_tier} CONFIDENCE
          </span>
        </div>

        <!-- Explanation -->
        <div style="background:rgba(0,0,0,0.3);border-left:3px solid #00d4ff;border-radius:0 8px 8px 0;padding:14px 18px;margin-bottom:28px;">
          <p style="margin:0;font-size:13px;color:#94a3b8;line-height:1.7;">💡 {r.explanation}</p>
        </div>

        <!-- Action recommended -->
        <div style="background:rgba(255,51,85,0.08);border:1px solid rgba(255,51,85,0.25);border-radius:10px;padding:18px 22px;margin-bottom:28px;">
          <p style="margin:0 0 6px;font-size:13px;font-weight:700;color:#ff3355;">⚡ Recommended Actions:</p>
          <ul style="margin:0;padding-left:20px;font-size:12px;color:#94a3b8;line-height:2;">
            <li>Isolate the affected network segment immediately</li>
            <li>Capture full packet data for forensic analysis</li>
            <li>Check affected hosts for encryption activity</li>
            <li>Review firewall rules for {r.dominant_family} C2 IOCs</li>
            <li>Notify the incident response team</li>
          </ul>
        </div>

        <!-- Footer -->
        <p style="margin:0;font-size:11px;color:#334155;text-align:center;font-family:monospace;">
          SENTINEL Threat Intelligence Platform &nbsp;·&nbsp; Auto-generated alert &nbsp;·&nbsp; Do not reply
        </p>

      </td>
    </tr>
  </table>
  </td></tr>
</table>
</body>
</html>"""
