// ponytail: llama Resend via fetch directo, sin npm package en el runtime de CF Pages.
export async function onRequestPost({ request, env }) {
  const { email } = await request.json().catch(() => ({}))
  if (!email || !String(email).includes('@')) {
    return Response.json({ error: 'invalid email' }, { status: 400 })
  }

  const apiKey = env.RESEND_API_KEY
  if (!apiKey) return Response.json({ error: 'config' }, { status: 500 })

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}` },
    body: JSON.stringify({
      from: 'Horus Leads <noreply@horusagents.com>',
      to: 'contact@horusagents.com',
      reply_to: email,
      subject: `[Demo] ${email}`,
      html: `<p style="font-family:system-ui;color:#0A0E1A;">Nueva solicitud de demo: <a href="mailto:${email}">${email}</a></p>`,
    }),
  })

  if (!res.ok) {
    console.error('Resend error', await res.text())
    return Response.json({ error: 'send' }, { status: 500 })
  }

  return Response.json({ ok: true })
}
