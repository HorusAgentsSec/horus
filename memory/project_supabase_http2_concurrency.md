---
name: project_supabase_http2_concurrency
description: Por qué los queries de Supabase fallaban con "Server disconnected" bajo concurrencia y el fix HTTP/1.1
metadata:
  type: project
---

El cliente global service-role de Supabase (`backend/core/supabase_client.py`) se comparte entre todos los hilos del worker pool (scans concurrentes, p.ej. `scan-all`) y los background tasks de discovery.

`postgrest` 0.17.2 cablea `http2=True` en su sesión httpx. Un httpx **sync** sobre HTTP/2 multiplexa todas las peticiones en una sola conexión TCP; manejar esa conexión desde varios hilos a la vez corrompe la máquina de estados HTTP/2 y el servidor la tira → `httpx.RemoteProtocolError: Server disconnected`. Síntoma: discovery y pipelines fallando con "Server disconnected" cuando hay carga concurrente.

**Fix**: helper `_force_http1()` que reconstruye `client.postgrest.session` como `httpx.Client(http2=False, ...)` copiando base_url/headers/timeout. HTTP/1.1 usa un pool de conexiones con locks, seguro entre hilos. Aplicado tanto al cliente service-role global como a `get_authed_client`. Verificado: 120 queries en 16 hilos, 0 errores.

`ClientOptions` de supabase 2.9.0 no expone `http2` ni inyección de httpx_client, por eso se parchea la sesión a posteriori. Relacionado con [[project_llm_dev_provider]] (otro caso de timeouts/colgados en runs).
