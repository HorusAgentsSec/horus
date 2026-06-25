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
    subject: 'Tu acceso a la demo de Horus',
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
      <p style="margin:0 0 8px;font-size:22px;font-weight:700;color:#fff;letter-spacing:-0.02em;">Tu demo está lista.</p>
      <p style="margin:0 0 28px;font-size:14px;color:#7A8499;line-height:1.6;">El entorno está pre-cargado con 30 días de historial de postura, hallazgos CVE reales y una campaña de phishing simulada.</p>

      <a href="${DEMO_URL}" style="display:inline-block;background:#E8B94A;color:#0A0E1A;font-weight:700;font-size:14px;padding:12px 24px;border-radius:9px;text-decoration:none;margin-bottom:32px;">
        Abrir la demo →
      </a>

      <p style="margin:0 0 10px;font-size:13px;font-weight:600;color:#fff;">Qué puedes explorar:</p>
      <ul style="margin:0 0 28px;padding-left:20px;font-size:13px;color:#7A8499;line-height:2;">
        <li><strong style="color:#F0EBE1;">Posture dashboard</strong> — puntuación de riesgo, activos expuestos y tendencia histórica</li>
        <li><strong style="color:#F0EBE1;">Findings</strong> — CVEs reales con severidad CVSS, contexto y recomendaciones de remediación</li>
        <li><strong style="color:#F0EBE1;">Incidents</strong> — gestión de casos con timeline completo y debate Red/Blue</li>
        <li><strong style="color:#F0EBE1;">Phishing</strong> — campaña simulada con tasas de click y pantalla de concienciación</li>
        <li><strong style="color:#F0EBE1;">Iris</strong> — monitorización continua de superficie de ataque</li>
      </ul>

      <p style="margin:0;font-size:12px;color:rgba(122,132,153,0.5);">El acceso es de solo lectura. Nada de lo que veas afecta a sistemas reales.</p>
    </div>
    <div style="padding:14px 28px;border-top:1px solid rgba(255,255,255,0.07);font-size:11px;color:rgba(122,132,153,0.4);">horusagents.com</div>
  </div>
</body>
</html>`,
  });

  if (userError) {
    console.error('[demo-lead] Error enviando al usuario:', JSON.stringify(userError));
  } else {
    console.log('[demo-lead] Email de acceso enviado a:', email);
  }

  // Notificación de lead interna
  await resend.emails.send({
    from: 'Horus Leads <noreply@horusagents.com>',
    to: 'contact@horusagents.com',
    replyTo: email,
    subject: `[Demo] ${email}`,
    html: `<p style="font-family:system-ui;background:#0A0E1A;color:#F0EBE1;padding:32px;">Nueva solicitud de demo: <a href="mailto:${email}" style="color:#2C6BED;">${email}</a></p>`,
  });

  return redirect('/demo/thanks', 303);
};
