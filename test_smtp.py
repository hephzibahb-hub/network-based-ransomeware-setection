"""
Quick SMTP test script -- run from project root to verify email works.
Tries port 587 (STARTTLS) first, then falls back to port 465 (SSL).

Usage:
    python test_smtp.py                        # sends to yourself
    python test_smtp.py recipient@example.com  # sends to custom address
"""
import sys
import socket
sys.path.insert(0, '.')
# Force UTF-8 output so the script never crashes on Windows terminals
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

from app.api.smtp_config import SMTP_EMAIL, SMTP_PASSWORD, SMTP_HOST, SMTP_PORT
import smtplib
from email.mime.text import MIMEText


def _build_msg(recipient: str) -> MIMEText:
    msg = MIMEText(
        "SENTINEL SMTP test successful!\n\n"
        "If you received this, email alerts are working correctly.\n\n"
        "Port used: see console output.",
        "plain"
    )
    msg["Subject"] = "[SENTINEL] SMTP Test Email"
    msg["From"]    = SMTP_EMAIL
    msg["To"]      = recipient
    return msg


def test_smtp(recipient: str):
    if not SMTP_EMAIL or not SMTP_PASSWORD:
        print("[ERROR] SMTP_EMAIL or SMTP_PASSWORD is empty in smtp_config.py")
        return

    msg = _build_msg(recipient)

    # -- Attempt 1: port 587 STARTTLS --
    print(f"[1/2] Trying {SMTP_HOST}:587 (STARTTLS) ...")
    try:
        with smtplib.SMTP(SMTP_HOST, 587, timeout=10) as s:
            s.ehlo()
            s.starttls()
            s.login(SMTP_EMAIL, SMTP_PASSWORD)
            s.sendmail(SMTP_EMAIL, recipient, msg.as_string())
        print(f"[OK]  Sent via port 587 -> {recipient}  (check inbox + spam)")
        return
    except smtplib.SMTPAuthenticationError:
        print("[ERROR] Auth failed -- regenerate your Gmail App Password in smtp_config.py.")
        return
    except (OSError, socket.timeout) as e:
        print(f"[WARN] Port 587 blocked: {e}")

    # -- Attempt 2: port 465 SSL --
    print(f"[2/2] Falling back to {SMTP_HOST}:465 (SSL) ...")
    try:
        with smtplib.SMTP_SSL(SMTP_HOST, 465, timeout=10) as s:
            s.login(SMTP_EMAIL, SMTP_PASSWORD)
            s.sendmail(SMTP_EMAIL, recipient, msg.as_string())
        print(f"[OK]  Sent via port 465 -> {recipient}  (check inbox + spam)")
        print("[INFO] Update SMTP_PORT = 465 in smtp_config.py to use SSL by default.")
        return
    except smtplib.SMTPAuthenticationError:
        print("[ERROR] Auth failed -- regenerate your Gmail App Password in smtp_config.py.")
        return
    except (OSError, socket.timeout) as e:
        print(f"[ERROR] Port 465 also blocked: {e}")

    # -- Both failed --
    print("\n[FAIL] Both ports are blocked. Most likely causes:")
    print("  1. College/work Wi-Fi blocks outbound SMTP -- try a mobile hotspot.")
    print("  2. Windows Firewall rule blocking port 587/465.")
    print("  3. VPN interference.")
    print("\n  Run in PowerShell to confirm connectivity:")
    print("  Test-NetConnection -ComputerName smtp.gmail.com -Port 587")
    print("  Test-NetConnection -ComputerName smtp.gmail.com -Port 465")


if __name__ == "__main__":
    to = sys.argv[1] if len(sys.argv) > 1 else SMTP_EMAIL
    test_smtp(to)
