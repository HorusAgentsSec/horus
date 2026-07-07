// Proxia /api/* al backend (Fly) desde el mismo origen. Así el navegador nunca
// hace una petición cross-origin: cero CORS y la CSP `connect-src 'self'` basta.
// El destino se configura con la variable API_ORIGIN en Cloudflare Pages
// (Settings → Environment variables), p. ej. https://horus-api.fly.dev
// ponytail: proxy en vez de tocar las llamadas /api del cliente ni abrir CORS/CSP.
export async function onRequest(context) {
  const { request, env } = context
  // Por defecto apunta al backend de Fly; se puede sobreescribir con la variable
  // API_ORIGIN en Cloudflare Pages sin redeploy de código.
  const origin = (env.API_ORIGIN || 'https://horus-api.fly.dev').replace(/\/$/, '')

  const url = new URL(request.url)
  const target = origin + url.pathname + url.search // url.pathname ya incluye /api/...

  // Reenvía método, cabeceras y cuerpo tal cual; devuelve la respuesta sin tocar
  // (incluye los streams SSE de /api/adversarial/runs/:id/stream).
  return fetch(target, {
    method: request.method,
    headers: request.headers,
    body: request.method === 'GET' || request.method === 'HEAD' ? undefined : request.body,
    redirect: 'manual',
  })
}
