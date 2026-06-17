import type { APIRoute } from 'astro';
import { Resend } from 'resend';

export const prerender = false;

const PLANS: Record<string, string> = {
  pro: 'Pro (managed cloud)',
  sovereign: 'Sovereign (on-prem / enterprise)',
};

export const POST: APIRoute = async ({ request, redirect }) => {
  const form = await request.formData();

  const name       = String(form.get('name')       ?? '').trim();
  const email      = String(form.get('email')      ?? '').trim();
  const company    = String(form.get('company')    ?? '').trim();
  const employees  = String(form.get('employees')  ?? '').trim();
  const sector     = String(form.get('sector')     ?? '').trim();
  const plan       = String(form.get('plan')       ?? '').trim();
  const tools      = String(form.get('tools')      ?? '').trim();
  const message    = String(form.get('message')    ?? '').trim();

  if (!name || !email || !company) {
    return redirect('/contact?error=missing', 303);
  }

  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) {
    return redirect('/contact?error=config', 303);
  }

  const resend = new Resend(apiKey);

  const planLabel = PLANS[plan] ?? plan;

  const { error } = await resend.emails.send({
    from: 'Horus Leads <noreply@horusagents.com>',
    to:   'contact@horusagents.com',
    replyTo: email,
    subject: `[Lead] ${planLabel} — ${company}`,
    html: `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family:system-ui,sans-serif;background:#0A0E1A;color:#F0EBE1;margin:0;padding:32px;">
  <div style="max-width:580px;margin:0 auto;background:#0F1526;border:1px solid rgba(255,255,255,0.08);border-radius:12px;overflow:hidden;">
    <div style="background:rgba(232,185,74,0.12);border-bottom:1px solid rgba(232,185,74,0.2);padding:20px 28px;display:flex;align-items:center;gap:10px;">
      <span style="font-size:18px;font-weight:700;letter-spacing:-0.02em;">Horus</span>
      <span style="font-size:12px;color:#E8B94A;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;">· New lead</span>
    </div>
    <div style="padding:28px;">
      <table style="width:100%;border-collapse:collapse;">
        <tr><td style="padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.07);color:#7A8499;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;width:160px;">Plan</td><td style="padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.07);font-size:14px;color:#E8B94A;font-weight:600;">${planLabel}</td></tr>
        <tr><td style="padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.07);color:#7A8499;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;">Name</td><td style="padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.07);font-size:14px;">${name}</td></tr>
        <tr><td style="padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.07);color:#7A8499;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;">Email</td><td style="padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.07);font-size:14px;"><a href="mailto:${email}" style="color:#2C6BED;">${email}</a></td></tr>
        <tr><td style="padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.07);color:#7A8499;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;">Company</td><td style="padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.07);font-size:14px;">${company}</td></tr>
        <tr><td style="padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.07);color:#7A8499;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;">Employees</td><td style="padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.07);font-size:14px;">${employees}</td></tr>
        <tr><td style="padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.07);color:#7A8499;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;">Sector</td><td style="padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.07);font-size:14px;">${sector}</td></tr>
        ${tools ? `<tr><td style="padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.07);color:#7A8499;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;">Current tools</td><td style="padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.07);font-size:14px;">${tools}</td></tr>` : ''}
        ${message ? `<tr><td style="padding:10px 0;color:#7A8499;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;vertical-align:top;">Message</td><td style="padding:10px 0;font-size:14px;color:#7A8499;line-height:1.6;">${message.replace(/\n/g, '<br>')}</td></tr>` : ''}
      </table>
    </div>
    <div style="padding:16px 28px;border-top:1px solid rgba(255,255,255,0.07);font-size:11px;color:rgba(122,132,153,0.5);">horusagents.com · lead form</div>
  </div>
</body>
</html>`,
  });

  if (error) {
    console.error('Resend error:', error);
    return redirect('/contact?error=send', 303);
  }

  return redirect('/contact/thanks', 303);
};
