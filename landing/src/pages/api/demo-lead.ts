import type { APIRoute } from 'astro';
import { Resend } from 'resend';

export const prerender = false;

const DEMO_URL = 'https://app.horusagents.com/login?demo=1';

export const POST: APIRoute = async ({ request, redirect }) => {
  const form = await request.formData();
  const email = String(form.get('email') ?? '').trim();

  if (!email || !email.includes('@')) {
    return redirect('/demo?error=missing', 303);
  }

  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) return redirect('/demo?error=config', 303);

  const resend = new Resend(apiKey);

  // Email al usuario con el enlace y las instrucciones
  const { error: userError } = await resend.emails.send({
    from: 'Horus <noreply@horusagents.com>',
    to: email,
    subject: 'Your Horus demo access',
    html: `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family:system-ui,sans-serif;background:#0A0E1A;color:#F0EBE1;margin:0;padding:32px;">
  <div style="max-width:560px;margin:0 auto;background:#0F1526;border:1px solid rgba(255,255,255,0.08);border-radius:12px;overflow:hidden;">
    <div style="background:rgba(232,185,74,0.10);border-bottom:1px solid rgba(232,185,74,0.18);padding:20px 28px;">
      <span style="font-size:18px;font-weight:700;letter-spacing:-0.02em;">Horus</span>
    </div>
    <div style="padding:32px 28px;">
      <p style="margin:0 0 8px;font-size:22px;font-weight:700;color:#fff;letter-spacing:-0.02em;">Your demo is ready.</p>
      <p style="margin:0 0 28px;font-size:14px;color:#7A8499;line-height:1.6;">The environment is pre-loaded with 30 days of posture history, real CVE findings, and a simulated phishing campaign.</p>

      <a href="${DEMO_URL}" style="display:inline-block;background:#E8B94A;color:#0A0E1A;font-weight:700;font-size:14px;padding:12px 24px;border-radius:9px;text-decoration:none;margin-bottom:32px;">
        Open live demo →
      </a>

      <p style="margin:0 0 10px;font-size:13px;font-weight:600;color:#fff;">What to explore:</p>
      <ul style="margin:0 0 28px;padding-left:20px;font-size:13px;color:#7A8499;line-height:2;">
        <li><strong style="color:#F0EBE1;">Posture dashboard</strong> — risk score, exposed assets and historical trend</li>
        <li><strong style="color:#F0EBE1;">Findings</strong> — real CVEs with CVSS severity, context and remediation guidance</li>
        <li><strong style="color:#F0EBE1;">Incidents</strong> — case management with full timeline and Red/Blue debate</li>
        <li><strong style="color:#F0EBE1;">Phishing</strong> — simulated campaign with click rates and awareness screen</li>
        <li><strong style="color:#F0EBE1;">Iris</strong> — continuous attack surface monitoring</li>
      </ul>

      <p style="margin:0;font-size:12px;color:rgba(122,132,153,0.5);">Read-only access. Nothing you see affects real systems.</p>
    </div>
    <div style="padding:14px 28px;border-top:1px solid rgba(255,255,255,0.07);font-size:11px;color:rgba(122,132,153,0.4);">horusagents.com</div>
  </div>
</body>
</html>`,
  });

  if (userError) {
    console.error('[demo-lead] Failed to send user email:', JSON.stringify(userError));
  } else {
    console.log('[demo-lead] Access email sent to:', email);
  }

  // Internal lead notification
  await resend.emails.send({
    from: 'Horus Leads <noreply@horusagents.com>',
    to: 'contact@horusagents.com',
    replyTo: email,
    subject: `[Demo] ${email}`,
    html: `<p style="font-family:system-ui;background:#0A0E1A;color:#F0EBE1;padding:32px;">New demo request: <a href="mailto:${email}" style="color:#2C6BED;">${email}</a></p>`,
  });

  return redirect('/demo/thanks', 303);
};
