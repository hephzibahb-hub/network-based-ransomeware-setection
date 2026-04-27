"""
SENTINEL — SMTP Alert Configuration
======================================
Edit the two values below with your Gmail credentials.

HOW TO GET A GMAIL APP PASSWORD (required — normal password won't work):
  1. Go to your Google Account → Security
  2. Enable 2-Step Verification (if not already on)
  3. Go to Security → App Passwords
  4. Select app: "Mail", device: "Windows Computer" → Generate
  5. Copy the 16-character password and paste it as SMTP_PASSWORD below

NOTE: Never share or commit this file to a public repo.
"""

SMTP_HOST     = "smtp.gmail.com"
SMTP_PORT     = 587

SMTP_EMAIL    = "reshwinkumar8@gmail.com"   # Sender Gmail address
SMTP_PASSWORD = "eteocuxmlsadftit"            # Gmail App Password
