import type { APIRoute } from 'astro';
import { Resend } from 'resend';

export const prerender = false;

export const POST: APIRoute = async ({ request, redirect }) => {
  const form = await request.formData();
  const email = String(form.get('email') ?? '').trim();

  if (!email || !email.includes('@')) {
    return redirect('/demo?error=missing', 303);
  }

  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) return redirect('/demo?error=config', 303);

  const resend = new Resend(apiKey);

  const { error } = await resend.emails.send({
    from: 'Horus Leads <noreply@horusagents.com>',
    to: 'contact@horusagents.com',
    reply_to: email,
    subject: `[Demo] ${email}`,
    html: `<p style="font-family:system-ui;background:#0A0E1A;color:#F0EBE1;padding:32px;">Nueva solicitud de demo: <a href="mailto:${email}" style="color:#2C6BED;">${email}</a></p>`,
  });

  if (error) {
    console.error('Resend error:', error);
    // ponytail: no bloquear la demo si falla el envío
  }

  return redirect('https://app.horusagents.com/login?demo=1', 303);
};
