# Horus — Bug Report (Testing manual interactivo, 2026-06-09)

Testing realizado con Chrome DevTools MCP (a2e) navegando todas las páginas de la aplicación de forma interactiva.

---

## BUGS CRÍTICOS

### BUG-01 — Asset Detail devuelve HTTP 500
- **Página**: `/assets/:id`
- **Reproducción**: Hacer clic en cualquier asset de la lista en `/assets` para ir a su detalle.
- **Síntoma**: Se muestra un banner rojo "HTTP 500" en la página de detalle del asset.
- **Causa probable**: `GET /api/assets/{id}` falla en el backend. Puede ser un error en la query SQL o un campo que no existe.
- **Impacto**: Alto — no es posible ver el detalle de ningún asset.

---

### BUG-02 — `/api/posture/normalized` devuelve 500 en el Dashboard
- **Página**: `/dashboard`
- **Reproducción**: Navegar al dashboard (ocurre al cargar la página).
- **Síntoma**: La llamada `GET /api/posture/normalized` retorna HTTP 500. No hay error visible en la UI, pero algún widget del dashboard no carga datos.
- **Causa probable**: Error en el endpoint `/posture/normalized` del backend.
- **Impacto**: Medio — el dashboard carga parcialmente pero pierde datos de postura.

---

### BUG-03 — Discovery jobs fallan con `name 'source_id' is not defined`
- **Página**: `/jobs` (Job History)
- **Reproducción**: Ejecutar un job de Discovery. El job aparece en el historial como "Failed".
- **Síntoma**: El detalle del job muestra el error `name 'source_id' is not defined` — variable no definida en el código Python del agente de discovery.
- **Causa probable**: Bug en `backend/agents/` — variable `source_id` referenciada antes de ser asignada en el flujo de discovery.
- **Impacto**: Alto — el Discovery automático no funciona.

---

### BUG-04 — Discovery jobs fallan con `Server disconnected`
- **Página**: `/jobs` (Job History)
- **Reproducción**: Ejecutar jobs de Discovery repetidamente.
- **Síntoma**: Algunos jobs de discovery fallan con el error `Server disconnected`, indicando desconexión del servidor durante la ejecución.
- **Causa probable**: Timeout o cierre inesperado de conexión en el backend durante jobs largos.
- **Impacto**: Medio — los jobs de discovery son intermitentemente inestables.

---

### BUG-05 — Settings: "Save Changes" no hace nada
- **Página**: `/settings`
- **Reproducción**: Modificar el campo "Shodan API Key" y hacer clic en "Save Changes".
- **Síntoma**: No se dispara ninguna llamada de red (`POST`/`PUT` a la API), y no aparece ningún feedback visual (sin toast, sin mensaje de éxito/error, sin spinner). El botón parece estar completamente roto.
- **Causa probable**: El handler del botón no está conectado o hay un error silencioso al intentar llamar al API.
- **Impacto**: Alto — el usuario no puede guardar su clave de Shodan.

---

## BUGS MODERADOS

### BUG-06 — Permissions: guardar sin nombre crea policy con nombre vacío
- **Página**: `/permissions`
- **Reproducción**: Clic en "+ New Policy" → dejar el campo "Policy name" vacío → clic en "Save".
- **Síntoma**: La policy se guarda sin error con `name: ""` (string vacío), usando el scope de la org como nombre visible en la lista ("Org"). No hay validación del campo nombre.
- **Causa probable**: Falta validación en frontend (campo requerido) y/o en backend (validación del body).
- **Impacto**: Medio — se pueden crear policies sin nombre, confundiendo al usuario.

---

### BUG-07 — AuthPhishing: modal de resultados desalineado (offset izquierda)
- **Página**: `/auth-phishing`
- **Reproducción**: Crear una campaña de phishing → lanzarla → hacer clic en "Results".
- **Síntoma**: El modal de resultados aparece desplazado hacia la izquierda, parcialmente oculto detrás de la barra lateral. El título se muestra truncado (ej: "hishing #2 - Email real — Results" en lugar del título completo).
- **Causa probable**: El modal usa `position: fixed` sin compensar el ancho del sidebar (`240px`). El `left` del modal debería ser `240px` o usar `margin-left: 240px`.
- **Impacto**: Medio — el modal es usable pero el contenido está parcialmente oculto.

---

## UX ISSUES (no críticos, pero afectan la experiencia)

### UX-01 — Export PDF sin feedback visual
- **Página**: `/findings` (o desde el dashboard)
- **Reproducción**: Hacer clic en "Export PDF".
- **Síntoma**: El PDF se descarga correctamente (HTTP 200), pero no hay spinner de carga ni toast de confirmación durante el proceso. El usuario no sabe si algo está pasando.
- **Impacto**: Bajo — funcional pero confuso para el usuario.

---

### UX-02 — Finding Detail sin navegación de vuelta
- **Página**: `/findings/:id`
- **Reproducción**: Navegar a cualquier finding desde la lista → llegar a la página de detalle.
- **Síntoma**: No hay botón "← Volver a Findings", breadcrumb, ni enlace de retorno. El usuario debe usar el botón "Atrás" del navegador o el menú lateral.
- **Impacto**: Bajo — mala UX de navegación.

---

### UX-03 — Audit log: filtro de acciones incompleto
- **Página**: `/audit`
- **Síntoma**: El desplegable "All actions" solo incluye ~10 tipos de acción (Member invited, Role changed, Scan triggered, etc.), pero el log contiene más de 20 tipos distintos (`campaign.launched`, `adversarial.run_triggered`, `discovery.run`, `job.canceled`, `integration.created`, `employee.created`, etc.) que no son filtrables.
- **Impacto**: Bajo — el usuario no puede filtrar por todos los tipos de evento que existen.

---

## BUGS RESUELTOS DURANTE EL TESTING

### FIXED-01 — `cronstrue` npm package no instalado en el contenedor Docker
- **Síntoma**: `GET` a la página Schedules devolvía 500; Vite mostraba `Failed to resolve import "cronstrue"`.
- **Fix aplicado**: `docker exec horus-frontend-1 npm install` — instaló cronstrue@3.14.0.
- **Estado**: ✅ Resuelto.

---

## Resumen

| ID | Página | Severidad | Estado |
|----|--------|-----------|--------|
| BUG-01 | `/assets/:id` | 🔴 Crítico | ✅ Resuelto |
| BUG-02 | `/dashboard` | 🟠 Moderado | ✅ Resuelto |
| BUG-03 | `/jobs` (discovery) | 🔴 Crítico | ✅ Resuelto (ya corregido; jobs 09-jun OK) |
| BUG-04 | `/jobs` (discovery) | 🟠 Moderado | ✅ Resuelto (ya corregido; jobs 09-jun OK) |
| BUG-05 | `/settings` | 🔴 Crítico | ✅ Resuelto |
| BUG-06 | `/permissions` | 🟡 Moderado | ✅ Resuelto |
| BUG-07 | `/auth-phishing` | 🟡 Moderado | ✅ Resuelto |
| UX-01 | `/findings` | 🟢 Bajo | ✅ Resuelto |
| UX-02 | `/findings/:id` | 🟢 Bajo | ✅ Resuelto |
| UX-03 | `/audit` | 🟢 Bajo | ✅ Resuelto |
| FIXED-01 | Frontend Docker | — | ✅ Resuelto |

---

## Notas de resolución (2026-06-09)

- **BUG-01**: dos sub-llamadas de `/assets/:id` fallaban con `42703` (columna inexistente).
  `scans.triggered_by_label` no es columna → ahora se selecciona `triggered_by`/`triggered_by_user_id`
  y la etiqueta se deriva con `_with_triggered_by_labels` (reutilizado de `scans.py`).
  `asset_inventory.service_name` no existía → migración `20260609210000_inventory_service_name.sql`
  añade la columna y `core/inventory.py` la rellena desde el `service` del scanner nmap.
- **BUG-02**: `findings.updated_at` no existe → `posture.py` ahora usa `last_seen_at` (proxy de cierre).
- **BUG-03/04**: errores históricos (07-jun). Los jobs de discovery del 09-jun completan sin error;
  el código actual de discovery está limpio. Solo quedaban registros antiguos en la tabla `jobs`.
- **BUG-05**: nueva tabla `org_settings` + endpoint `GET/PUT /api/settings`. El input Shodan y el
  botón "Save Changes" ahora persisten de verdad (con estados Saving…/Saved/error). El secreto no se
  devuelve al navegador (solo `shodan_api_key_set`).
- **BUG-06**: validación de nombre en `PermissionPolicyCreate/Update` (backend) + campo requerido y
  mensaje de error en el frontend.
- **BUG-07**: el modal de resultados pasa de `fixed inset-0` a `fixed inset-y-0 left-60 right-0`
  para no quedar tapado por el sidebar (`w-60`, z-10).
- **UX-01**: el export de PDF (PostureTimeline) ya tenía spinner/error; se añade confirmación
  "PDF downloaded ✓".
- **UX-02**: botón "← Back to Findings" en `/findings/:id`.
- **UX-03**: `ACTION_META` del Audit log ampliado a las 30+ acciones reales que emite el backend.

---

## Páginas verificadas

| Página | Estado |
|--------|--------|
| `/dashboard` | ✅ Funcional (con BUG-02 parcial) |
| `/assets` | ✅ Lista OK |
| `/assets/:id` | ❌ HTTP 500 |
| `/discovery` | ✅ Funcional |
| `/watchtower` | ✅ Funcional |
| `/scans` | ✅ Funcional |
| `/scans/:id` | ✅ Funcional |
| `/schedules` | ✅ Funcional (tras fix cronstrue) |
| `/jobs` | ✅ Funcional (con jobs fallidos de discovery) |
| `/findings` | ✅ Funcional |
| `/findings/:id` | ✅ Funcional (con UX-02) |
| `/adversarial` | ✅ Funcional |
| `/auth-phishing` | ✅ Funcional (con BUG-07) |
| `/credential-exposure` | ✅ Funcional |
| `/permissions` | ✅ Funcional (con BUG-06) |
| `/team` | ✅ Funcional |
| `/audit` | ✅ Funcional (con UX-03) |
| `/integrations` | ✅ Funcional |
| `/settings` | ❌ Save Changes roto (BUG-05) |
| `/analytics` | ✅ Funcional |
