"""
Built-in phishing simulation template library.
These templates are always available in the community view (no DB row required).
IDs use the "sys-" prefix so the fork endpoint can resolve them here.
"""

_G = "#f6f8fa"  # noqa: unused aliases kept for readability in HTML strings

SYSTEM_TEMPLATES: list[dict] = [
    # ── 1. Google Workspace — Sign-In Alert ──────────────────────────────────
    {
        "id": "sys-google-signin-alert",
        "name": "Google Workspace — Unusual Sign-In Alert",
        "subject": "[Google Security] New sign-in to your Google Account",
        "org_name": "Horus Library",
        "org_id": "00000000-0000-0000-0000-000000000000",
        "is_own": False,
        "created_at": "2024-01-01T00:00:00Z",
        "body_html": """\
<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#f6f8fa;font-family:'Google Sans',Roboto,Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" bgcolor="#f6f8fa">
<tr><td align="center" style="padding:40px 20px;">
<table width="520" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.12);">
<tr><td style="padding:28px 40px 24px;border-bottom:1px solid #e8eaed;">
<svg width="74" height="24" viewBox="0 0 74 24" xmlns="http://www.w3.org/2000/svg">
<path d="M9.24 7.66C8.69 6.1 7.24 5 5.5 5 3.01 5 1 7.01 1 9.5S3.01 14 5.5 14c2.03 0 3.73-1.3 4.3-3.1H5.5V9h5.5c.05.33.08.67.08 1 0 3.04-2.04 5.25-5.08 5.25C2.71 15.25 0 12.54 0 9.5S2.71 3.75 5.5 3.75c1.94 0 3.62 1.01 4.54 2.52L9.24 7.66z" fill="#4285F4"/>
<path d="M22.5 9.5c0 3.04-2.46 5.25-5.5 5.25S11.5 12.54 11.5 9.5 13.96 4.25 17 4.25s5.5 2.21 5.5 5.25zm-2.44 0c0-1.8-1.32-3.02-3.06-3.02S13.94 7.7 13.94 9.5s1.32 3.02 3.06 3.02 3.06-1.22 3.06-3.02z" fill="#EA4335"/>
<path d="M34.5 9.5c0 3.04-2.46 5.25-5.5 5.25S23.5 12.54 23.5 9.5 25.96 4.25 29 4.25s5.5 2.21 5.5 5.25zm-2.44 0c0-1.8-1.32-3.02-3.06-3.02S25.94 7.7 25.94 9.5s1.32 3.02 3.06 3.02 3.06-1.22 3.06-3.02z" fill="#FBBC05"/>
<path d="M45.5 4.75v9.5c0 3.91-2.3 5.5-5.03 5.5-2.56 0-4.1-1.72-4.68-3.12l2.12-.88c.36.86 1.24 1.88 2.56 1.88 1.68 0 2.71-1.03 2.71-2.97v-.73h-.08c-.5.61-1.45 1.14-2.66 1.14-2.53 0-4.84-2.2-4.84-5.03 0-2.85 2.31-5.09 4.84-5.09 1.2 0 2.16.53 2.66 1.12h.08V4.75h2.32zm-2.14 4.8c0-1.78-1.19-3.08-2.7-3.08-1.54 0-2.82 1.3-2.82 3.08 0 1.77 1.28 3.03 2.82 3.03 1.51 0 2.7-1.26 2.7-3.03z" fill="#4285F4"/>
<path d="M49 1v13.5h-2.38V1H49z" fill="#34A853"/>
<path d="M58.11 11.44l1.9 1.27c-.61.9-2.08 2.54-4.63 2.54-3.15 0-5.5-2.44-5.5-5.25 0-3.12 2.37-5.25 5.23-5.25 2.88 0 4.29 2.17 4.75 3.34l.25.63-7.41 3.07c.57 1.11 1.45 1.68 2.68 1.68 1.24 0 2.1-.61 2.73-1.03zm-5.82-2l4.95-2.06c-.27-.69-1.1-1.17-2.07-1.17-1.24 0-2.97 1.1-2.88 3.23z" fill="#EA4335"/>
</svg>
</td></tr>
<tr><td style="padding:32px 40px;">
<h1 style="margin:0 0 8px;font-size:22px;font-weight:400;color:#202124;">Security alert</h1>
<p style="margin:0 0 20px;font-size:14px;color:#5f6368;">{{employee_email}}</p>
<p style="margin:0 0 24px;font-size:14px;line-height:1.6;color:#3c4043;">
We detected a new sign-in to your Google Account from an unrecognised device. If this was you, you can ignore this email. If not, your account may be at risk.
</p>
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f8f9fa;border-radius:6px;margin-bottom:28px;">
<tr><td style="padding:16px 20px;">
<p style="margin:0 0 10px;font-size:11px;color:#5f6368;font-weight:600;text-transform:uppercase;letter-spacing:.6px;">Sign-in details</p>
<table cellpadding="0" cellspacing="0">
<tr><td style="padding:3px 0;font-size:13px;color:#5f6368;width:90px;">Device</td><td style="padding:3px 0;font-size:13px;color:#202124;">Unknown · Windows 11</td></tr>
<tr><td style="padding:3px 0;font-size:13px;color:#5f6368;">Location</td><td style="padding:3px 0;font-size:13px;color:#202124;">Netherlands (IP 185.220.101.47)</td></tr>
<tr><td style="padding:3px 0;font-size:13px;color:#5f6368;">Time</td><td style="padding:3px 0;font-size:13px;color:#202124;">Just now</td></tr>
</table>
</td></tr>
</table>
<table cellpadding="0" cellspacing="0"><tr>
<td style="padding-right:12px;"><a href="{{tracking_url}}" style="display:inline-block;background:#1a73e8;color:#fff;text-decoration:none;font-size:14px;font-weight:500;padding:10px 24px;border-radius:4px;">Check activity</a></td>
<td><a href="{{tracking_url}}" style="display:inline-block;color:#1a73e8;text-decoration:none;font-size:14px;font-weight:500;padding:10px 24px;border-radius:4px;border:1px solid #dadce0;">Change password</a></td>
</tr></table>
</td></tr>
<tr><td style="padding:20px 40px;border-top:1px solid #e8eaed;">
<p style="margin:0;font-size:12px;color:#5f6368;line-height:1.6;">
You received this email to {{employee_email}} because your account had a security event.<br>
Google LLC · 1600 Amphitheatre Parkway · Mountain View, CA 94043
</p>
</td></tr>
</table>
</td></tr>
</table>
</body></html>""",
    },

    # ── 2. Google Drive — Shared File ────────────────────────────────────────
    {
        "id": "sys-google-drive-share",
        "name": "Google Drive — File Shared With You",
        "subject": "{{employee_name}}, someone shared a file with you in Google Drive",
        "org_name": "Horus Library",
        "org_id": "00000000-0000-0000-0000-000000000000",
        "is_own": False,
        "created_at": "2024-01-01T00:00:00Z",
        "body_html": """\
<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f6f8fa;font-family:'Google Sans',Roboto,Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" bgcolor="#f6f8fa">
<tr><td align="center" style="padding:40px 20px;">
<table width="520" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.12);">
<tr><td style="padding:28px 40px;border-bottom:1px solid #e8eaed;">
<span style="font-size:22px;font-weight:700;color:#1a73e8;font-family:Arial;">Google Drive</span>
</td></tr>
<tr><td style="padding:32px 40px;">
<p style="margin:0 0 24px;font-size:15px;line-height:1.6;color:#202124;">
<strong>Sarah Mitchell</strong> has shared a file with you.
</p>
<table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e8eaed;border-radius:8px;overflow:hidden;margin-bottom:28px;">
<tr><td style="padding:20px;background:#f8f9fa;border-bottom:1px solid #e8eaed;" align="center">
<svg width="48" height="64" viewBox="0 0 48 64" xmlns="http://www.w3.org/2000/svg">
<path d="M8 0h24l16 16v48H8V0z" fill="#4285F4" opacity=".15"/><path d="M32 0l16 16H32V0z" fill="#4285F4"/>
<path d="M32 0l16 16H32V0z" fill="rgba(0,0,0,.1)"/>
<rect x="14" y="28" width="20" height="2" rx="1" fill="#4285F4"/>
<rect x="14" y="34" width="20" height="2" rx="1" fill="#4285F4"/>
<rect x="14" y="40" width="14" height="2" rx="1" fill="#4285F4"/>
</svg>
</td></tr>
<tr><td style="padding:16px 20px;">
<p style="margin:0 0 4px;font-size:14px;font-weight:500;color:#202124;">Q4_2024_Financial_Report_CONFIDENTIAL.xlsx</p>
<p style="margin:0;font-size:12px;color:#5f6368;">Shared by sarah.mitchell@company.com · 1 viewer</p>
</td></tr>
</table>
<a href="{{tracking_url}}" style="display:inline-block;background:#1a73e8;color:#fff;text-decoration:none;font-size:14px;font-weight:500;padding:10px 24px;border-radius:4px;">Open in Drive</a>
</td></tr>
<tr><td style="padding:20px 40px;border-top:1px solid #e8eaed;">
<p style="margin:0;font-size:12px;color:#5f6368;">This email was sent to {{employee_email}} · <a href="{{tracking_url}}" style="color:#1a73e8;text-decoration:none;">Unsubscribe</a></p>
</td></tr>
</table>
</td></tr>
</table>
</body></html>""",
    },

    # ── 3. Microsoft 365 — Unusual Sign-In ──────────────────────────────────
    {
        "id": "sys-microsoft-signin",
        "name": "Microsoft 365 — Unusual Sign-In Activity",
        "subject": "Microsoft account security alert — unusual sign-in activity",
        "org_name": "Horus Library",
        "org_id": "00000000-0000-0000-0000-000000000000",
        "is_own": False,
        "created_at": "2024-01-01T00:00:00Z",
        "body_html": """\
<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f3f2f1;font-family:'Segoe UI',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" bgcolor="#f3f2f1">
<tr><td align="center" style="padding:40px 20px;">
<table width="540" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:4px;overflow:hidden;">
<tr><td style="background:#0078d4;padding:20px 32px;">
<span style="font-size:20px;font-weight:600;color:#fff;letter-spacing:-.3px;">Microsoft</span>
</td></tr>
<tr><td style="padding:36px 32px;">
<h1 style="margin:0 0 8px;font-size:24px;font-weight:600;color:#323130;">Review recent activity</h1>
<p style="margin:0 0 8px;font-size:14px;color:#605e5c;">Microsoft account</p>
<p style="margin:0 0 24px;font-size:14px;color:#323130;font-weight:600;">{{employee_email}}</p>
<p style="margin:0 0 24px;font-size:14px;line-height:1.6;color:#323130;">
We noticed some unusual activity on your Microsoft account. Please review it and let us know whether or not it was you.
</p>
<table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #edebe9;border-radius:4px;margin-bottom:28px;">
<tr><td style="background:#f3f2f1;padding:12px 20px;font-size:12px;font-weight:600;color:#605e5c;text-transform:uppercase;letter-spacing:.5px;">Recent sign-in</td></tr>
<tr><td style="padding:16px 20px;">
<table cellpadding="0" cellspacing="0" width="100%">
<tr><td style="font-size:13px;color:#605e5c;padding:3px 0;width:110px;">Country/region</td><td style="font-size:13px;color:#323130;padding:3px 0;font-weight:500;">Romania</td></tr>
<tr><td style="font-size:13px;color:#605e5c;padding:3px 0;">IP address</td><td style="font-size:13px;color:#323130;padding:3px 0;font-weight:500;">82.77.142.11</td></tr>
<tr><td style="font-size:13px;color:#605e5c;padding:3px 0;">Date</td><td style="font-size:13px;color:#323130;padding:3px 0;font-weight:500;">Today, a few minutes ago</td></tr>
<tr><td style="font-size:13px;color:#605e5c;padding:3px 0;">Platform</td><td style="font-size:13px;color:#323130;padding:3px 0;font-weight:500;">Windows 10</td></tr>
<tr><td style="font-size:13px;color:#605e5c;padding:3px 0;">Browser</td><td style="font-size:13px;color:#323130;padding:3px 0;font-weight:500;">Chrome</td></tr>
</table>
</td></tr>
</table>
<table cellpadding="0" cellspacing="0"><tr>
<td style="padding-right:12px;"><a href="{{tracking_url}}" style="display:inline-block;background:#0078d4;color:#fff;text-decoration:none;font-size:14px;font-weight:600;padding:10px 24px;border-radius:2px;">Review recent activity</a></td>
<td><a href="{{tracking_url}}" style="display:inline-block;color:#0078d4;text-decoration:none;font-size:14px;font-weight:600;padding:10px 24px;border-radius:2px;border:1px solid #0078d4;">No, this wasn't me</a></td>
</tr></table>
</td></tr>
<tr><td style="padding:20px 32px;border-top:1px solid #edebe9;background:#faf9f8;">
<p style="margin:0;font-size:11px;color:#605e5c;line-height:1.6;">
Microsoft Corporation · One Microsoft Way · Redmond, WA 98052<br>
This email was sent to {{employee_email}}.
</p>
</td></tr>
</table>
</td></tr>
</table>
</body></html>""",
    },

    # ── 4. WhatsApp Business — Account Verification ──────────────────────────
    {
        "id": "sys-whatsapp-verification",
        "name": "WhatsApp Business — Account Verification Required",
        "subject": "Action required: verify your WhatsApp Business account",
        "org_name": "Horus Library",
        "org_id": "00000000-0000-0000-0000-000000000000",
        "is_own": False,
        "created_at": "2024-01-01T00:00:00Z",
        "body_html": """\
<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f0f2f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" bgcolor="#f0f2f5">
<tr><td align="center" style="padding:40px 20px;">
<table width="520" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.08);">
<tr><td style="background:#25d366;padding:24px 32px;" align="center">
<span style="font-size:26px;font-weight:700;color:#fff;letter-spacing:-.5px;">WhatsApp Business</span>
</td></tr>
<tr><td style="padding:32px;">
<p style="margin:0 0 16px;font-size:14px;color:#3b4a54;">Hi {{employee_name}},</p>
<p style="margin:0 0 24px;font-size:14px;line-height:1.6;color:#3b4a54;">
Your WhatsApp Business account <strong>({{employee_email}})</strong> requires verification to continue operating. Accounts that are not verified within <strong>24 hours</strong> may be temporarily suspended.
</p>
<table width="100%" cellpadding="0" cellspacing="0" style="background:#fff3cd;border-left:4px solid #ffc107;border-radius:4px;margin-bottom:24px;">
<tr><td style="padding:14px 18px;">
<p style="margin:0;font-size:13px;color:#856404;font-weight:600;">⚠ Account verification required</p>
<p style="margin:4px 0 0;font-size:12px;color:#856404;">Without verification, your account will be restricted from sending messages after 24 hours.</p>
</td></tr>
</table>
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f0f2f5;border-radius:6px;margin-bottom:24px;padding:16px;display:block;">
<tr><td style="padding:16px;">
<p style="margin:0 0 8px;font-size:12px;font-weight:600;color:#3b4a54;text-transform:uppercase;letter-spacing:.5px;">Account details</p>
<p style="margin:0;font-size:13px;color:#3b4a54;">Email: <strong>{{employee_email}}</strong></p>
<p style="margin:4px 0 0;font-size:13px;color:#3b4a54;">Status: <span style="color:#e74c3c;font-weight:600;">Unverified</span></p>
</td></tr>
</table>
<a href="{{tracking_url}}" style="display:inline-block;background:#25d366;color:#fff;text-decoration:none;font-size:14px;font-weight:600;padding:12px 32px;border-radius:24px;">Verify my account</a>
<p style="margin:24px 0 0;font-size:12px;color:#667781;">This is an automated security notice. Do not reply to this email.</p>
</td></tr>
<tr><td style="padding:16px 32px;background:#f0f2f5;border-top:1px solid #e9edef;">
<p style="margin:0;font-size:11px;color:#667781;">© 2024 WhatsApp Inc. · 1601 Willow Road · Menlo Park, CA 94025</p>
</td></tr>
</table>
</td></tr>
</table>
</body></html>""",
    },

    # ── 5. Meta Business Suite — Ad Account Restricted ──────────────────────
    {
        "id": "sys-meta-ad-restricted",
        "name": "Meta Business Suite — Ad Account Restricted",
        "subject": "[Action Required] Your Meta ad account has been restricted",
        "org_name": "Horus Library",
        "org_id": "00000000-0000-0000-0000-000000000000",
        "is_own": False,
        "created_at": "2024-01-01T00:00:00Z",
        "body_html": """\
<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f0f2f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" bgcolor="#f0f2f5">
<tr><td align="center" style="padding:40px 20px;">
<table width="540" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.1);">
<tr><td style="padding:24px 32px;border-bottom:1px solid #e4e6e9;">
<span style="font-size:24px;font-weight:800;color:#1877f2;letter-spacing:-.5px;">Meta</span>
<span style="font-size:13px;color:#65676b;margin-left:8px;">Business Suite</span>
</td></tr>
<tr><td style="padding:28px 32px;">
<div style="background:#fff3f3;border-left:4px solid #e02020;border-radius:4px;padding:16px 20px;margin-bottom:24px;">
<p style="margin:0;font-size:14px;font-weight:700;color:#1c1e21;">⚠ Your ad account has been restricted</p>
<p style="margin:6px 0 0;font-size:13px;color:#65676b;">Account: {{employee_email}}</p>
</div>
<p style="margin:0 0 16px;font-size:14px;line-height:1.6;color:#1c1e21;">Hi {{employee_name}},</p>
<p style="margin:0 0 20px;font-size:14px;line-height:1.6;color:#1c1e21;">
We have restricted your Meta ad account due to unusual payment activity. Your active campaigns have been paused and no further charges will be made until the issue is resolved.
</p>
<p style="margin:0 0 20px;font-size:14px;line-height:1.6;color:#1c1e21;">
To restore your account, you must verify your payment method and review our advertising policies. Failure to complete this within <strong>48 hours</strong> may result in permanent account suspension.
</p>
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f0f2f5;border-radius:8px;padding:16px;margin-bottom:28px;">
<tr><td style="padding:4px 0;font-size:13px;color:#65676b;width:130px;">Account ID</td><td style="font-size:13px;color:#1c1e21;font-weight:500;">act_87429301847</td></tr>
<tr><td style="padding:4px 0;font-size:13px;color:#65676b;">Restriction date</td><td style="font-size:13px;color:#1c1e21;font-weight:500;">Today</td></tr>
<tr><td style="padding:4px 0;font-size:13px;color:#65676b;">Reason</td><td style="font-size:13px;color:#e02020;font-weight:500;">Unusual payment activity</td></tr>
</table>
<a href="{{tracking_url}}" style="display:inline-block;background:#1877f2;color:#fff;text-decoration:none;font-size:14px;font-weight:600;padding:12px 28px;border-radius:6px;">Verify account &amp; restore access</a>
</td></tr>
<tr><td style="padding:16px 32px;background:#f0f2f5;border-top:1px solid #e4e6e9;">
<p style="margin:0;font-size:11px;color:#65676b;">Meta Platforms, Inc. · 1 Hacker Way · Menlo Park, CA 94025</p>
</td></tr>
</table>
</td></tr>
</table>
</body></html>""",
    },

    # ── 6. Canva — Design Shared ─────────────────────────────────────────────
    {
        "id": "sys-canva-design-shared",
        "name": "Canva — Design Shared With You",
        "subject": "{{employee_name}}, you have a new design shared on Canva",
        "org_name": "Horus Library",
        "org_id": "00000000-0000-0000-0000-000000000000",
        "is_own": False,
        "created_at": "2024-01-01T00:00:00Z",
        "body_html": """\
<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f8f6ff;font-family:'Circular Std',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" bgcolor="#f8f6ff">
<tr><td align="center" style="padding:40px 20px;">
<table width="520" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 16px rgba(109,70,255,.1);">
<tr><td style="padding:24px 36px;border-bottom:1px solid #ede9fe;">
<span style="font-size:22px;font-weight:800;color:#8b3dff;">Canva</span>
</td></tr>
<tr><td style="padding:32px 36px;">
<p style="margin:0 0 20px;font-size:15px;font-weight:600;color:#2c2c54;">Hey {{employee_name}}! 👋</p>
<p style="margin:0 0 24px;font-size:14px;line-height:1.6;color:#54566e;">
<strong>Alex Torres</strong> has shared a Canva design with you and wants your input.
</p>
<table width="100%" cellpadding="0" cellspacing="0" style="border:2px solid #ede9fe;border-radius:12px;overflow:hidden;margin-bottom:28px;">
<tr><td style="background:linear-gradient(135deg,#8b3dff 0%,#c084fc 100%);height:120px;padding:24px;" align="center">
<span style="font-size:16px;font-weight:700;color:#fff;letter-spacing:-.3px;">Company Brand Guidelines 2025</span>
</td></tr>
<tr><td style="padding:16px 20px;">
<p style="margin:0;font-size:13px;color:#54566e;">Shared by <strong>Alex Torres</strong> · Presentation</p>
<p style="margin:4px 0 0;font-size:12px;color:#9ca3af;">Can view &amp; comment</p>
</td></tr>
</table>
<a href="{{tracking_url}}" style="display:inline-block;background:#8b3dff;color:#fff;text-decoration:none;font-size:14px;font-weight:700;padding:12px 32px;border-radius:8px;">Open design</a>
<p style="margin:24px 0 0;font-size:12px;color:#9ca3af;">
Don't want emails like this? <a href="{{tracking_url}}" style="color:#8b3dff;text-decoration:none;">Manage email settings</a>
</p>
</td></tr>
<tr><td style="padding:16px 36px;background:#f8f6ff;border-top:1px solid #ede9fe;">
<p style="margin:0;font-size:11px;color:#9ca3af;">© 2024 Canva · 110 Kippax St, Surry Hills NSW 2010</p>
</td></tr>
</table>
</td></tr>
</table>
</body></html>""",
    },

    # ── 7. Slack — Unread Messages ───────────────────────────────────────────
    {
        "id": "sys-slack-unread",
        "name": "Slack — Unread Messages & DM Notification",
        "subject": "{{employee_name}}, you have unread messages in Slack",
        "org_name": "Horus Library",
        "org_id": "00000000-0000-0000-0000-000000000000",
        "is_own": False,
        "created_at": "2024-01-01T00:00:00Z",
        "body_html": """\
<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f8f8f8;font-family:'Slack-Lato',Lato,-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" bgcolor="#f8f8f8">
<tr><td align="center" style="padding:40px 20px;">
<table width="520" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:4px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.08);">
<tr><td style="background:#4a154b;padding:20px 32px;" align="center">
<span style="font-size:22px;font-weight:900;color:#fff;letter-spacing:-.5px;">slack</span>
</td></tr>
<tr><td style="padding:32px;">
<p style="margin:0 0 24px;font-size:18px;font-weight:700;color:#1d1c1d;">You have 3 unread messages</p>
<!-- Message 1 -->
<table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:16px;border:1px solid #e8e8e8;border-radius:4px;overflow:hidden;">
<tr><td style="padding:14px 16px;">
<div style="display:flex;align-items:flex-start;">
<div style="width:36px;height:36px;border-radius:4px;background:#e01e5a;display:inline-block;text-align:center;line-height:36px;color:#fff;font-weight:700;font-size:14px;margin-right:12px;vertical-align:top;">JR</div>
<div style="display:inline-block;vertical-align:top;margin-left:12px;">
<p style="margin:0 0 2px;font-size:13px;font-weight:700;color:#1d1c1d;">Jamie Robinson <span style="font-weight:400;color:#616061;font-size:12px;">in #general</span></p>
<p style="margin:0;font-size:13px;color:#1d1c1d;">Hey {{employee_name}}, can you check this contract before EOD?</p>
</div>
</div>
</td></tr>
</table>
<!-- Message 2 -->
<table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:16px;border:1px solid #e8e8e8;border-radius:4px;overflow:hidden;">
<tr><td style="padding:14px 16px;">
<div style="width:36px;height:36px;border-radius:4px;background:#36c5f0;display:inline-block;text-align:center;line-height:36px;color:#fff;font-weight:700;font-size:14px;margin-right:12px;vertical-align:top;">IT</div>
<div style="display:inline-block;vertical-align:top;margin-left:12px;">
<p style="margin:0 0 2px;font-size:13px;font-weight:700;color:#1d1c1d;">IT Security <span style="font-weight:400;color:#616061;font-size:12px;">via DM</span></p>
<p style="margin:0;font-size:13px;color:#1d1c1d;">Your Slack workspace password needs to be updated.</p>
</div>
</div>
</td></tr>
</table>
<table cellpadding="0" cellspacing="0" style="margin-top:24px;"><tr>
<td><a href="{{tracking_url}}" style="display:inline-block;background:#4a154b;color:#fff;text-decoration:none;font-size:14px;font-weight:700;padding:12px 28px;border-radius:4px;">Open Slack</a></td>
</tr></table>
</td></tr>
<tr><td style="padding:16px 32px;background:#f8f8f8;border-top:1px solid #e8e8e8;">
<p style="margin:0;font-size:11px;color:#616061;">Sent to {{employee_email}} · <a href="{{tracking_url}}" style="color:#1264a3;text-decoration:none;">Manage preferences</a><br>
Slack Technologies, LLC · 500 Howard St · San Francisco, CA 94105</p>
</td></tr>
</table>
</td></tr>
</table>
</body></html>""",
    },

    # ── 8. Notion — Workspace Invite ─────────────────────────────────────────
    {
        "id": "sys-notion-invite",
        "name": "Notion — Workspace Invitation",
        "subject": "You've been invited to join a Notion workspace",
        "org_name": "Horus Library",
        "org_id": "00000000-0000-0000-0000-000000000000",
        "is_own": False,
        "created_at": "2024-01-01T00:00:00Z",
        "body_html": """\
<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#fff;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" bgcolor="#fff">
<tr><td align="center" style="padding:40px 20px;">
<table width="480" cellpadding="0" cellspacing="0" style="background:#fff;">
<tr><td style="padding:0 0 28px;" align="center">
<span style="font-size:28px;">📝</span><br>
<span style="font-size:20px;font-weight:700;color:#000;letter-spacing:-.4px;">Notion</span>
</td></tr>
<tr><td style="padding:0 0 20px;">
<p style="margin:0;font-size:16px;line-height:1.6;color:#000;font-weight:400;">
Hi {{employee_name}},
</p>
</td></tr>
<tr><td style="padding:0 0 20px;">
<p style="margin:0;font-size:16px;line-height:1.6;color:#000;">
<strong>David Chen</strong> has invited you to join the <strong>Acme Corp</strong> workspace on Notion.
</p>
</td></tr>
<tr><td style="padding:0 0 32px;">
<table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e9e9e9;border-radius:4px;">
<tr><td style="padding:20px 24px;">
<p style="margin:0 0 4px;font-size:14px;font-weight:600;color:#000;">Acme Corp</p>
<p style="margin:0;font-size:13px;color:#787774;">14 members · Collaborative workspace</p>
</td></tr>
</table>
</td></tr>
<tr><td style="padding:0 0 32px;">
<a href="{{tracking_url}}" style="display:inline-block;background:#000;color:#fff;text-decoration:none;font-size:14px;font-weight:600;padding:12px 32px;border-radius:4px;">Join workspace</a>
</td></tr>
<tr><td style="padding:20px 0;border-top:1px solid #e9e9e9;">
<p style="margin:0;font-size:12px;color:#787774;line-height:1.6;">
You received this invite at {{employee_email}}. If you don't want to join, you can ignore this email.<br>
Notion Labs, Inc. · 2300 Harrison St · San Francisco, CA 94110
</p>
</td></tr>
</table>
</td></tr>
</table>
</body></html>""",
    },

    # ── 9. DocuSign — Signature Request ─────────────────────────────────────
    {
        "id": "sys-docusign-signature",
        "name": "DocuSign — Document Ready for Signature",
        "subject": "Please sign: Employment_Contract_2025.pdf — DocuSign",
        "org_name": "Horus Library",
        "org_id": "00000000-0000-0000-0000-000000000000",
        "is_own": False,
        "created_at": "2024-01-01T00:00:00Z",
        "body_html": """\
<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f5f5f5;font-family:Arial,'Helvetica Neue',Helvetica,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" bgcolor="#f5f5f5">
<tr><td align="center" style="padding:40px 20px;">
<table width="540" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:4px;overflow:hidden;border:1px solid #e0e0e0;">
<tr><td style="background:#ffcc33;padding:0;" height="6"></td></tr>
<tr><td style="padding:24px 40px;border-bottom:1px solid #e0e0e0;">
<span style="font-size:26px;font-weight:700;color:#333;letter-spacing:-.5px;">docu</span><span style="font-size:26px;font-weight:700;color:#ffcc33;letter-spacing:-.5px;">sign</span>
</td></tr>
<tr><td style="padding:32px 40px;">
<p style="margin:0 0 8px;font-size:14px;color:#666;">Hi {{employee_name}},</p>
<p style="margin:0 0 24px;font-size:14px;line-height:1.6;color:#333;">
<strong>HR Department (hr@company.com)</strong> has sent you a document to review and sign.
</p>
<table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e0e0e0;border-radius:4px;overflow:hidden;margin-bottom:28px;">
<tr><td style="background:#f9f9f9;padding:20px 24px;border-bottom:1px solid #e0e0e0;">
<table cellpadding="0" cellspacing="0"><tr>
<td style="padding-right:16px;">
<svg width="36" height="44" viewBox="0 0 36 44" xmlns="http://www.w3.org/2000/svg">
<rect width="36" height="44" rx="4" fill="#ffcc33" opacity=".2"/>
<path d="M6 6h18l6 6v26H6V6z" fill="#ffcc33"/>
<path d="M24 6l6 6h-6V6z" fill="rgba(0,0,0,.15)"/>
</svg>
</td>
<td>
<p style="margin:0 0 4px;font-size:14px;font-weight:700;color:#333;">Employment_Contract_2025.pdf</p>
<p style="margin:0;font-size:12px;color:#999;">Expires: 24 hours · Requires 1 signature</p>
</td>
</tr></table>
</td></tr>
<tr><td style="padding:12px 24px;">
<p style="margin:0;font-size:12px;color:#666;">Please review and sign the document as soon as possible.</p>
</td></tr>
</table>
<a href="{{tracking_url}}" style="display:inline-block;background:#ffcc33;color:#333;text-decoration:none;font-size:14px;font-weight:700;padding:12px 36px;border-radius:4px;">Review Document</a>
</td></tr>
<tr><td style="padding:20px 40px;background:#f9f9f9;border-top:1px solid #e0e0e0;">
<p style="margin:0;font-size:11px;color:#999;line-height:1.6;">
This email was sent to {{employee_email}}. Do not share this email as it contains a secure link to sign your document.<br>
DocuSign Inc. · 221 Main Street · San Francisco, CA 94105
</p>
</td></tr>
</table>
</td></tr>
</table>
</body></html>""",
    },

    # ── 10. LinkedIn — Security Verification ────────────────────────────────
    {
        "id": "sys-linkedin-verify",
        "name": "LinkedIn — Account Verification Required",
        "subject": "[LinkedIn] Your account requires verification — action needed",
        "org_name": "Horus Library",
        "org_id": "00000000-0000-0000-0000-000000000000",
        "is_own": False,
        "created_at": "2024-01-01T00:00:00Z",
        "body_html": """\
<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f3f2ef;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen,Ubuntu,Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" bgcolor="#f3f2ef">
<tr><td align="center" style="padding:40px 20px;">
<table width="520" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.08);">
<tr><td style="background:#0a66c2;padding:20px 32px;">
<span style="font-size:20px;font-weight:700;color:#fff;letter-spacing:-.3px;">in</span>
<span style="font-size:20px;font-weight:700;color:#fff;margin-left:8px;">LinkedIn</span>
</td></tr>
<tr><td style="padding:32px;">
<div style="background:#fff8e1;border:1px solid #ffe082;border-radius:6px;padding:14px 20px;margin-bottom:24px;">
<p style="margin:0;font-size:14px;font-weight:600;color:#f57c00;">⚠ Account verification required</p>
</div>
<p style="margin:0 0 16px;font-size:14px;color:#1d2226;">Hi {{employee_name}},</p>
<p style="margin:0 0 20px;font-size:14px;line-height:1.6;color:#1d2226;">
We've detected unusual activity on your LinkedIn account <strong>({{employee_email}})</strong>. To protect your network and data, we need to verify your identity.
</p>
<p style="margin:0 0 24px;font-size:14px;line-height:1.6;color:#1d2226;">
If you don't verify within <strong>24 hours</strong>, your account will be temporarily restricted.
</p>
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f3f2ef;border-radius:6px;margin-bottom:28px;">
<tr><td style="padding:16px 20px;">
<p style="margin:0 0 8px;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;color:#666;">Flagged activity</p>
<table cellpadding="0" cellspacing="0">
<tr><td style="padding:3px 0;font-size:13px;color:#666;width:110px;">Type</td><td style="padding:3px 0;font-size:13px;color:#1d2226;font-weight:500;">Sign-in from new location</td></tr>
<tr><td style="padding:3px 0;font-size:13px;color:#666;">Location</td><td style="padding:3px 0;font-size:13px;color:#1d2226;font-weight:500;">Unknown (IP: 45.142.212.100)</td></tr>
<tr><td style="padding:3px 0;font-size:13px;color:#666;">When</td><td style="padding:3px 0;font-size:13px;color:#1d2226;font-weight:500;">Today</td></tr>
</table>
</td></tr>
</table>
<a href="{{tracking_url}}" style="display:inline-block;background:#0a66c2;color:#fff;text-decoration:none;font-size:14px;font-weight:600;padding:12px 28px;border-radius:24px;">Verify my account</a>
</td></tr>
<tr><td style="padding:16px 32px;background:#f3f2ef;border-top:1px solid #e0e0e0;">
<p style="margin:0;font-size:11px;color:#666;">© 2024 LinkedIn Corporation · 1000 West Maude Ave · Sunnyvale, CA 94085</p>
</td></tr>
</table>
</td></tr>
</table>
</body></html>""",
    },

    # ── 11. Zoom — Meeting Invitation ────────────────────────────────────────
    {
        "id": "sys-zoom-meeting",
        "name": "Zoom — Urgent Team Meeting Invitation",
        "subject": "{{employee_name}}, you're invited to an urgent Zoom meeting",
        "org_name": "Horus Library",
        "org_id": "00000000-0000-0000-0000-000000000000",
        "is_own": False,
        "created_at": "2024-01-01T00:00:00Z",
        "body_html": """\
<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f9fafb;font-family:Lato,-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" bgcolor="#f9fafb">
<tr><td align="center" style="padding:40px 20px;">
<table width="520" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.08);">
<tr><td style="padding:24px 36px;border-bottom:1px solid #e8e8e8;">
<span style="font-size:24px;font-weight:700;color:#2d8cff;letter-spacing:-.3px;">zoom</span>
</td></tr>
<tr><td style="padding:32px 36px;">
<p style="margin:0 0 24px;font-size:14px;line-height:1.6;color:#333;">
Hi {{employee_name}},
</p>
<p style="margin:0 0 24px;font-size:14px;line-height:1.6;color:#333;">
You've been invited to an <strong>urgent all-hands meeting</strong> by <strong>Michael Carter (CEO)</strong>. Please join as soon as possible.
</p>
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f0f7ff;border-left:4px solid #2d8cff;border-radius:4px;margin-bottom:28px;">
<tr><td style="padding:20px 24px;">
<p style="margin:0 0 12px;font-size:15px;font-weight:700;color:#333;">Q4 Results & Restructuring Update</p>
<table cellpadding="0" cellspacing="0">
<tr><td style="padding:3px 0;font-size:13px;color:#666;width:90px;">Host</td><td style="font-size:13px;color:#333;font-weight:500;">Michael Carter</td></tr>
<tr><td style="padding:3px 0;font-size:13px;color:#666;">Meeting ID</td><td style="font-size:13px;color:#333;font-weight:500;">842 9173 6521</td></tr>
<tr><td style="padding:3px 0;font-size:13px;color:#666;">Passcode</td><td style="font-size:13px;color:#333;font-weight:500;">corp2024</td></tr>
<tr><td style="padding:3px 0;font-size:13px;color:#666;">Time</td><td style="font-size:13px;color:#e02020;font-weight:600;">Starting now</td></tr>
</table>
</td></tr>
</table>
<a href="{{tracking_url}}" style="display:inline-block;background:#2d8cff;color:#fff;text-decoration:none;font-size:14px;font-weight:700;padding:12px 32px;border-radius:6px;">Join Meeting</a>
<p style="margin:16px 0 0;font-size:13px;color:#666;">Or join via browser: <a href="{{tracking_url}}" style="color:#2d8cff;text-decoration:none;">zoom.us/j/84291736521</a></p>
</td></tr>
<tr><td style="padding:16px 36px;background:#f9fafb;border-top:1px solid #e8e8e8;">
<p style="margin:0;font-size:11px;color:#999;">Zoom Video Communications · 55 Almaden Blvd · San Jose, CA 95113<br>
Sent to {{employee_email}} · <a href="{{tracking_url}}" style="color:#2d8cff;text-decoration:none;">Unsubscribe</a></p>
</td></tr>
</table>
</td></tr>
</table>
</body></html>""",
    },

    # ── 12. Dropbox — Storage Full / Security ────────────────────────────────
    {
        "id": "sys-dropbox-storage",
        "name": "Dropbox — Storage Full & Security Notice",
        "subject": "Your Dropbox storage is full — important account notice",
        "org_name": "Horus Library",
        "org_id": "00000000-0000-0000-0000-000000000000",
        "is_own": False,
        "created_at": "2024-01-01T00:00:00Z",
        "body_html": """\
<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f7f5f3;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" bgcolor="#f7f5f3">
<tr><td align="center" style="padding:40px 20px;">
<table width="520" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.08);">
<tr><td style="padding:24px 36px;border-bottom:1px solid #eeebe6;">
<span style="font-size:22px;font-weight:700;color:#0061ff;letter-spacing:-.4px;">Dropbox</span>
</td></tr>
<tr><td style="padding:32px 36px;">
<div style="background:#fff3f3;border:1px solid #ffd0cc;border-radius:6px;padding:16px 20px;margin-bottom:24px;">
<p style="margin:0 0 6px;font-size:14px;font-weight:700;color:#c0392b;">⚠ Your storage is 100% full</p>
<p style="margin:0;font-size:13px;color:#666;">New files can no longer be synced to your Dropbox. Upgrade or delete files to continue.</p>
</div>
<p style="margin:0 0 20px;font-size:14px;color:#333;">Hi {{employee_name}},</p>
<p style="margin:0 0 24px;font-size:14px;line-height:1.6;color:#333;">
Your Dropbox account (<strong>{{employee_email}}</strong>) is full. Files are no longer syncing across your devices. Additionally, we've detected a sign-in from an unrecognised location.
</p>
<!-- Storage bar -->
<table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:28px;">
<tr><td>
<div style="background:#eeebe6;border-radius:4px;height:8px;overflow:hidden;">
<div style="background:#e02020;height:8px;width:100%;border-radius:4px;"></div>
</div>
<div style="display:flex;justify-content:space-between;margin-top:6px;">
<span style="font-size:12px;color:#e02020;font-weight:600;">2 GB used of 2 GB</span>
<span style="font-size:12px;color:#999;">0 MB remaining</span>
</div>
</td></tr>
</table>
<table cellpadding="0" cellspacing="0"><tr>
<td style="padding-right:12px;"><a href="{{tracking_url}}" style="display:inline-block;background:#0061ff;color:#fff;text-decoration:none;font-size:14px;font-weight:600;padding:10px 24px;border-radius:4px;">Upgrade storage</a></td>
<td><a href="{{tracking_url}}" style="display:inline-block;color:#0061ff;text-decoration:none;font-size:14px;font-weight:600;padding:10px 24px;border-radius:4px;border:1px solid #0061ff;">Review security</a></td>
</tr></table>
</td></tr>
<tr><td style="padding:16px 36px;background:#f7f5f3;border-top:1px solid #eeebe6;">
<p style="margin:0;font-size:11px;color:#999;">Dropbox, Inc. · 1800 Owens St · San Francisco, CA 94158<br>Sent to {{employee_email}}</p>
</td></tr>
</table>
</td></tr>
</table>
</body></html>""",
    },
]
