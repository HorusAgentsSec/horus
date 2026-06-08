# Horus — TODO

> **🎯 Goal**
> El objetivo de esta app es que **se configure una vez y funcione de la forma más autónoma posible**:
> mínima intervención humana, máximo valor añadido. El usuario define sus activos, sus reglas y sus
> automatizaciones una sola vez; a partir de ahí la plataforma descubre, escanea, correlaciona,
> prioriza y notifica por sí sola, y solo pide al humano lo que de verdad requiere una decisión.

---

## 🧮 Complejidad — routing de modelo por tarea

> Cada tarea **pendiente** lleva una etiqueta de **Complejidad** para enrutar el modelo de IA adecuado
> y ahorrar tokens (el desarrollo lo hacen agentes). Las tareas ya hechas (`[x]`) no la llevan.
>
> | Complejidad | Cuándo | Modelo sugerido |
> |---|---|---|
> | 🟢 **Muy sencilla** | mecánica, config, listas, headers, ajustes de reglas | Haiku 4.5 (`claude-haiku-4-5`) |
> | 🟡 **Normal** | feature acotada siguiendo patrones ya existentes | Sonnet 4.6 (`claude-sonnet-4-6`) |
> | 🔴 **Difícil** | diseño nuevo, motores de ejecución, integraciones cloud, seguridad activa, infra | Opus 4.8 (`claude-opus-4-8`) |

---

## 🤖 Autonomía y automatización

- [x] **Cronjobs / scans programados** — HECHO: scheduler refresca en vivo al crear/editar/borrar
      (`scheduler.schedule_job`/`unschedule_job`, antes solo cargaba al arrancar — bug de "configúralo
      una vez"), endpoint DELETE añadido, y página `pages/Schedules.tsx` (presets de cron + selección
      de assets/tools). Con notificaciones = bucle autónomo completo.
      Mejoras HECHAS (2026-06-07): **reintentos** auto de scans programados fallidos (`scan_max_retries`,
      en `executor._run_scan_safe` resetea a pending y reencola; user-triggered no reintenta) y
      **last_run/next_run en la UI** (API `/schedules` enriquece con último job + `scheduler.next_run_for`).
      Pendiente: ventanas de mantenimiento.
- [x] **Tabla `jobs` — histórico de toda la ejecución de fondo** — HECHO (2026-06-07): migración
      `20260607160000_jobs.sql` (org-scoped + globales `org_id null`, RLS, aplicada). `core/jobs.py`
      `job_run(job_type, org_id, ref_id, trigger)` context manager best-effort (inserta running →
      cierra completed/failed + duración + detalle). Cableado en TODOS los entrypoints del scheduler
      (scan_schedule, discovery, cve_sync, watchtower, posture_snapshot, posture_report) + triggers
      manuales (watchtower/discovery `/run` con trigger=manual). API `api/jobs.py` (`GET /jobs` filtros
      type/status, `/jobs/stats`). UI `pages/Jobs.tsx` ("Job history" en sidebar) — tipo, estado, trigger,
      duración, detalle. Tests `test_jobs.py` (3) + `test_executor_retry.py` (5). Verificado en vivo
      (row watchtower completed escrita). Suite 124 passed.
- [ ] `🔴 Difícil` **Sistema de flowcharts / workflows** — orquestador visual para encadenar procesos.
      Ejemplo objetivo: *"escanea la web → escanea la intranet → envía Slack con los resultados"*.
      Nodos: scan(asset/grupo), esperar, condición (ej. si hay CRITICAL), notificar, abrir ticket,
      ejecutar remediación. Persistir el grafo y ejecutarlo con el pool de workers existente. Podemos usar un sistema similar al de github workflows.
- [~] `🟡 Normal` **Auto-discovery de activos** — encontrar activos solos, sin alta manual:
      - [x] **Por dominio** — HECHO: `core/discovery.py` (CT logs vía crt.sh + resolución DNS,
            guard SSRF como puerta para no añadir nada interno; cap de assets/run), tabla
            `discovery_sources` (programable vía cron, reusa el scheduler), API `api/discovery.py`
            (CRUD analyst+ + `/run` en background), página `pages/Discovery.tsx`. Pasivo: no escanea.
            Probado: bse.eu → 72 subdominios; lógica resolver/dedupe/guard verificada.
      - [x] **Red privada** — HECHO: sweep nmap `-sn` de un CIDR → assets internos
            (`is_internal=true`, type `ip`). Guards: solo CIDR **privado** (RFC1918, rechaza públicos
            = anti-abuso) y cap de tamaño (max /22, `discovery_network_max_hosts`). Tabla extendida
            (`kind` domain/network + `network_cidr`), validación en el API, UI con selector de tipo.
            Probado: guard de CIDR (priv/púb/oversized) + parser de nmap. NOTA: no se probó un sweep
            real (no barrer redes ajenas en dev); falta probar contra una LAN propia.
      - [x] Fallback CT certspotter — HECHO: `discover_subdomains` usa crt.sh (con retry) y cae a
            certspotter si falla. Probado en vivo (crt.sh dio 502+timeout → retry lo absorbió; fallo
            forzado → certspotter, 20 subdominios). Pendiente: brute-force DNS de subdominios comunes.

## 👁️ Watchtower — monitorización continua de exposición (CTEM)

- [x] **Watchtower** — HECHO (2026-06-07): convierte el scan puntual en valor recurrente.
      Persiste el inventario de software por activo (`asset_inventory`, antes efímero) y un
      job diario (`watchtower_cron`, 30 min tras el sync de KEV) re-correlaciona ese inventario
      contra los CVE que **acaban de entrar en CISA KEV** — SIN re-escanear — y alerta
      (finding + notificación) por cada nueva exposición. Determinista, 0 tokens LLM.
      Piezas: migración `20260605170000_watchtower.sql` (`asset_inventory` + `watchtower_alerts`,
      RLS org-scoped, aplicada en remoto); `core/inventory.py` (upsert en el pipeline);
      `core/watchtower.py` (`match_exposures` puro + `run_watchtower`); `notify.notify_watchtower`
      (bell + slack + email, sin gate de severidad — KEV-active siempre alerta);
      `scheduler._register_watchtower`; API `api/watchtower.py` (`/alerts`, `/inventory`,
      `/run` admin); página `pages/Watchtower.tsx` + ruta + link en sidebar.
      Tests: `backend/tests/test_watchtower.py` (7, lógica pura). Verificado end-to-end contra
      datos reales: nginx 1.18.0 → CVE-2023-44487 (KEV) → alerta `high` creada, luego limpieza.
      NOTA: `_newly_kev_cves` topa al límite por defecto de PostgREST (1000 filas) — irrelevante
      con `lookback_days=3` (KEV añade unos pocos/día); paginar si se usa una ventana enorme.
      PENDIENTE (mejoras): ~~disparo `epss_spike`~~ HECHO (2026-06-07, ver abajo); reverse-index
      CVE→productos para no recorrer todo el inventario en orgs grandes.
- [x] **Watchtower — disparo `epss_spike`** — HECHO (2026-06-07): alerta temprana cuando el EPSS de un
      CVE ya en el inventario salta día-a-día (a menudo antes de entrar en KEV). Migración
      `20260607150000_epss_previous.sql` (columna `epss_previous` + función `snapshot_epss()` con
      `statement_timeout=240s` — el copy de 338K filas excede el timeout 8s de PostgREST; aplicada +
      baseline inicializado). El sync (`cve_intel.run_sync`) llama a `snapshot_epss()` (RPC, 9.1s) antes
      de sobrescribir scores. `watchtower._epss_spikes` + `is_epss_spike` puro (floor 0.5, delta 0.2);
      `run_watchtower` fusiona KEV+spikes (KEV precede); `_presentation` da título/severidad/explotabilidad
      por motivo (spike: severidad piso medium no high, exploitability high, no "actively exploited").
      `notify_watchtower(kind=)` con copy por motivo (📈 vs 🚨). Config `watchtower_epss_*`. Tests
      `test_watchtower.py` (+6, total 13). Queries verificadas contra BD real. Suite 116 passed.

## 🔔 Integraciones / notificaciones

- [x] **Slack + email** — HECHO (backend + UI): `core/notify.py` (dispatch best-effort, resumen
      de findings, filtro por severidad + KEV-active), API `api/integrations.py` (CRUD admin +
      `/test`, secretos redactados), hook en pipeline al completar scan, y página
      `pages/Integrations.tsx` (admin-gated, formularios slack/email + botón Test). Pendiente solo
      probar entrega real con un webhook/SMTP de verdad.
- [ ] `🟡 Normal` Otros destinos a futuro: Teams, webhook genérico, Jira/ticketing.
- [x] In-app notifications — HECHO: `notify._notify_in_app` crea una notificación por admin/analyst
      al completar scan (gated por umbral de severidad), y la campana 🔔 de `Header.tsx` ya es
      funcional (badge con contador, dropdown, marcar-leída, navega al scan; poll cada 60s).
- [ ] `🔴 Difícil` Integrar con plataformas de cloud como AWS y GCP para auditar pipelines de CI/CD, logs de esas plataformas, etc. 
## 🧠 Inteligencia / correlación CVE (mejoras incrementales)

- [x] **Alias-map de productos** — HECHO: `PRODUCT_ALIASES` en `cpe_intel.py` (~25 productos:
      apache→http_server, openssh→openbsd/openssh, IIS→internet_information_services, mysql→oracle…)
      + `_resolve_cpe` (full name → primer token → wildcard). `cves_for` resuelve el alias cuando
      vendor=None. Probado en vivo: Apache httpd 2.4.41 pasó de 0 a **75 CVEs**. Ampliar el map
      según aparezcan productos sin cobertura.
- [ ] `🟡 Normal` **NVD CVSS para todos los CVE de KEV** — enriquecer los ~1.6k de KEV con su CVSS
      (hoy solo se rellena CVSS de los CVE que pasan por correlación on-demand).
- [ ] `🟡 Normal` **Correlación más rica** — usar también el `service`/banner, no solo product+version.

## ✅ Calidad de findings

- [ ] `🟢 Muy sencilla` **Marcar/ocultar falsos positivos probables** — los scripts `http-*-xss` / `http-csrf` de nmap
      señalan potencial, no confirmado. Bajar su confianza o marcarlos "needs verification".
- [ ] `🔴 Difícil` **Validación activa opcional** — confirmar un finding correlado por versión con una prueba
      ligera, para subir la confianza de 0.7 a "confirmado".
- [ ] `🟢 Muy sencilla` Revisar periódicamente la lista `INFORMATIONAL_SCRIPTS` según aparezca ruido nuevo.
- [x] **Agrupar findings por servicio** — HECHO: `AnalyzedFinding.source_service` (set por
      CorrelationAgent) se persiste en `raw_data`, y `Findings.tsx` agrupa los correlados en una
      fila desplegable por servicio ("nginx 1.18.0 — 6 CVEs · N actively exploited", severidad
      peor del grupo). Los findings directos del scanner (vulners…) siguen sueltos. Verificado.

## 👁️ UX / percepción

- [x] **Timeline de postura (riesgo en el tiempo)** — HECHO (2026-06-07): el gráfico ejecutivo
      "¿baja nuestro riesgo?" que justifica renovar. `risk_score` determinista (findings abiertos
      ponderados por severidad + bonus KEV-active; menor = mejor) capturado en snapshots diarios.
      Piezas: migración `20260605180000_posture_snapshots.sql` (tabla `posture_snapshots`, RLS
      org-scoped, unique `(org_id,snapshot_date)`, aplicada); `core/posture.py`
      (`score_from_counts` puro + `compute_posture`/`snapshot_posture`/`snapshot_all_orgs`);
      snapshot tras cada scan (pipeline), tras alertas de Watchtower, y cron diario
      (`_register_posture_snapshot`, `0 6 * * *`); API `GET /api/posture/timeline?days=N`
      (timeline + current + trend_delta); componente `components/PostureTimeline.tsx` (recharts,
      área apilada por severidad + score actual + flecha de tendencia) embebido en el Dashboard.
      Tests: `backend/tests/test_posture.py` (6). Verificado end-to-end: org real risk=43
      (2 critical + 3 low + 2 KEV-active), snapshot persistido y leído.
- [~] **Progreso del scan en tiempo real** — PARCIAL (2026-06-07): cada agente ahora escribe un
      resumen en `agent_runs.output_state` al completarse (`_agent_detail` en pipeline), y el
      `AgentRunTimeline` (poll cada 2.5s) lo muestra — incluida la **deliberación red/blue expandible**
      del paso de validación (transparencia del debate "en vivo" a granularidad de agente). Pendiente:
      streaming finding-a-finding real (hoy aparece al completar cada agente) y/o Supabase Realtime.
      NOTA: arreglado de paso un bug latente — el check constraint de `agent_runs.agent_type` no incluía
      'validation' (migración `20260607140000`, aplicada), sin el cual la validación nunca corría en prod.
- [ ] `🟡 Normal` Vista de detalle de finding con CVSS + EPSS + KEV + remediación sugerida en una sola pantalla.
- [x] **Report ejecutivo persistido por scan** — HECHO (2026-06-07): el `ReporterAgent` (que antes
      generaba un report y lo tiraba) ahora es verdict/SSVC-aware (excluye falsos positivos, ordena
      top_priorities por urgencia SSVC), se persiste en `scans.report` (migración
      `20260607130000_scan_report.sql`, aplicada) y se muestra en `ScanDetail.tsx` (resumen ejecutivo
      + breakdown + próximos pasos). Cierra el desperdicio de tokens del Reporter.

## 🔐 Seguridad / infraestructura

- [ ] `🟡 Normal` **Rate limiting con store compartido (Redis)** — hoy es in-memory por proceso/worker.
- [ ] `🟢 Muy sencilla` **CSP a nivel de documento** en el host de producción del SPA (React).
- [ ] `🟡 Normal` **Revocación de sesión** al cambiar contraseña.

---

## 🧬 Metodología TradingAgents — cerrar la brecha (investigación 2026-06-07)

> **Contexto.** Nuestro pipeline es **lineal** (Recon→Analyst→Correlation→ThreatIntel→Remediation→
> RiskManager→Reporter) sobre un `ScanState`. El framework TradingAgents real (Tauric Research,
> arXiv 2412.20138) y la investigación de Agentic-SOC (Google SecOps, paper CORTEX arXiv 2510.00311)
> tienen 3 rasgos que nos faltan, y los 3 atacan problemas ya abiertos en este TODO. Adaptación:
> *bull/bear researchers* → **debate red-team vs blue-team** sobre cada finding ambiguo;
> *reflection+memory de trades* → **memoria de veredictos humanos** que mejora runs futuros;
> *risk team + portfolio manager* → **motor de decisión SSVC** determinista.

- [x] **Fase A — Motor de decisión SSVC (determinista, fundacional)** — HECHO (2026-06-07):
      `core/ssvc.py` (árbol deployer puro `decide()` + mappers desde nuestras señales: exploitability
      KEV/EPSS→Exploitation, is_internal→Exposure, CVSS/severity→Technical Impact, heurística
      conservadora→Automatable). Salida: prioridad Act/Attend/Track*/Track + modo. `RiskManagerAgent`
      ya NO usa LLM (las reglas de permisos deciden primero; el resto cae a SSVC, 0 tokens). SSVC
      persistido por finding en `raw_data.ssvc` (pipeline `_persist_results`). UI: `PriorityBadge.tsx`
      en `FindingCard`. Tests: `test_ssvc.py` (13). Suite 81 passed. Sanity real: CVSS 9.1 interno sin
      exploit → Track (CVSS gritaría crítico; SSVC lo despioriza correctamente — ese es el valor).
- [x] **Fase B — Debate adversarial Red/Blue para validar findings** — HECHO (2026-06-07):
      `ValidationAgent` (entre ThreatIntel y Remediation). Gate puro `core/validation.py`
      (`auto_verdict`: KEV-active→confirmed, info→needs_verification, conf≥0.9→confirmed,
      conf≤0.2 sin exploit→needs_verification; resto→debate). El debate es UNA llamada estructurada por
      finding ambiguo que fuerza red (por qué es real) + blue (por qué es falso positivo) + juez →
      veredicto (confirmed/likely/needs_verification/false_positive) + confianza calibrada. Cap por scan
      (`validation_max_debates=15`). Veredicto+debate persistidos en `raw_data`; RemediationAgent salta
      los false_positive. UI: `VerdictBadge` + panel del debate red/blue + panel SSVC en `FindingDetail`;
      hint de veredicto en `FindingCard`. Config `validation_enabled/max_debates` + `LLM_VALIDATION_MODEL`.
      Tests `test_validation.py` (10). Suite 91 passed. Cierra "marcar falsos positivos" + "validación activa".
- [x] **Federación de la memoria de veredictos (flywheel cross-customer, FOSO #1)** — HECHO (2026-06-07):
      el feedback per-org se agrega entre TODA la flota, anónimo, para que un cliente nuevo se beneficie
      desde el día uno. Migración `20260607170000_community_verdicts.sql` (tabla `community_verdicts` solo
      firma+counts, SIN org_id; función `refresh_community_verdicts(min_orgs,ratio)` con **k-anonimato**:
      una firma solo da veredicto comunitario si ≥3 orgs distintas y mayoría ≥60%; aplicada).
      `verdict_memory.recall_community` + `refresh_community`. `ValidationAgent` precedencia **KEV > prior
      org > prior comunitario > auto > debate** (el usuario puede sobreescribir). Job diario
      `_run_community_refresh` (`0 4 * * *`, en jobs). Tests +3. **Verificado en vivo: agregación + recall +
      k-anonimato (1 org con min_orgs=3 → None).** Suite 157 passed.
- [x] **Fase C — Memoria de resultados / reflexión (el bucle que compone)** — HECHO (2026-06-07):
      migración `20260607120000_finding_verdicts.sql` (tabla append-only, RLS `current_org_id()` —
      **PENDIENTE aplicar a remoto**; el runtime degrada a "sin memoria" hasta entonces).
      `core/verdict_memory.py`: `finding_signature` puro y estable (svc:producto sin versión / cve: / title:
      slug) que generaliza entre assets/scans; `record_human_verdict` (best-effort) y `recall` (1 round-trip,
      último por firma). Enganches: `update_finding` (status false_positive→fp, resolved/accepted_risk→confirmed)
      y `approve_suggestion` (→confirmed). `ValidationAgent` recupera priores al inicio y los aplica: prioridad
      **KEV-active > prior humano > auto_verdict > debate** (FP previo auto-suprime sin gastar tokens; KEV
      override de un FP rancio). UI: nota "Validation: …" en `FindingDetail` cuando el veredicto viene de
      memoria. Tests `test_verdict_memory.py` (8). Suite 98 passed.
- [x] **Fase D — Equipo de analistas especialistas en paralelo** — HECHO (2026-06-07):
      `backend/agents/analyst_team.py` — `classify_domain` (router puro por keywords, precedencia
      TLS>web>network>generic) + `SpecialistAnalyst` (un analista por dominio con prompt especializado).
      `AnalystAgent` reescrito: agrupa raw_findings por dominio y corre los especialistas en paralelo
      (`ThreadPoolExecutor`, max 4) mergeando la salida; si hay un solo dominio o el equipo está off,
      cae al generalista (comportamiento previo). Token accounting agregado en el hilo principal (sin
      race). Especialista fallido no hunde a los demás. Config `analyst_team_enabled`. Salida idéntica
      (AnalyzedFinding) → downstream intacto. Tests `test_analyst_team.py` (8). Suite 107 passed.

## 🔒 Privacidad / soberanía de datos (foso competitivo)

> **Contexto (2026-06-07).** Una herramienta de *seguridad* que manda el mapa de tu infra (hostnames
> internos, IPs, vulnerabilidades) a un LLM en la nube es ella misma una superficie de ataque. El
> comprador paranoico (banca, salud, gobierno, GDPR) no lo tolera → segmento que un competidor
> "solo-GPT" no puede servir. Privacidad-por-diseño = feature + wedge de mercado + foso de confianza.
> NOTA realista: FHE/MPC sobre inferencia de LLM **no es viable hoy** (órdenes de magnitud lento) —
> no venderlo. Lo real es la escalera de abajo. As en la manga: **nuestro núcleo (correlación CVE,
> SSVC, posture) es determinista y NO necesita LLM** → podemos correr sin que datos sensibles salgan.

- [x] **Capa de redacción / pseudonimización antes de cualquier llamada LLM** — HECHO (2026-06-07):
      `core/redaction.py` — `Redactor` (mapa bidireccional estable; redacta seeds host/nombre + IPs +
      emails + FQDNs con allowlist de dominios de referencia nvd/mitre/etc; seeds <4 chars ignorados
      para no clobbering; word-boundary). `build_redactor(state)` siembra desde el asset. Integrado en
      `BaseAgent.call_llm` (redacta user_content antes de enviar, restaura la respuesta); el pipeline
      siembra `agent.redactor` por run; AnalystAgent lo propaga a los especialistas paralelos. Config
      `redaction_enabled` (default **True**, privacy-by-design) + `.env.example`. Tests `test_redaction.py`
      (10, incl. integración: verificado que al modelo le llega `[HOST_1]` y la respuesta se restaura —
      0 leak). Suite 137 passed. Los agentes deterministas no se ven afectados (no llaman LLM).
- [x] **Modo sin-nube / determinista** — HECHO (2026-06-07): `llm_enabled` (default True; False = modo
      sin-nube). Con False el pipeline ENTERO corre con 0 llamadas LLM: AnalystAgent `_run_deterministic`
      (clasifica desde la salida del scanner, confidence 0.5, fingerprint igual); ValidationAgent salta el
      debate → `needs_verification` para ambiguos (auto_verdict+memoria siguen); RemediationAgent se salta;
      ReporterAgent `_deterministic_report` (resumen templated + próximos pasos ordenados por SSVC).
      Correlación CVE + ThreatIntel + SSVC + posture + Watchtower ya eran deterministas. Config
      `llm_enabled` + `.env.example`. Tests `test_no_cloud_mode.py` (2, con `_client` que revienta si se
      llama → garantiza 0 LLM). Suite 139 passed. Demo real: report "found 2 open finding(s): 1 high,
      1 medium. None are urgent by SSVC" con 0 tokens, 0 datos saliendo.
- [x] **BYO-model / on-prem / en tu VPC + visibilidad del modo** — HECHO (2026-06-07): empaquetado del
      tier soberano. `core/privacy.py` deriva el modo real (no_cloud / byo_local / cloud_redacted / cloud)
      desde `llm_enabled` + `is_local_endpoint(base_url)` (loopback/RFC1918/.internal/.local) + `redaction_enabled`,
      con `data_leaves_perimeter` y descripción honesta (nunca expone la API key). API `GET /api/privacy`.
      UI: panel "Data privacy" en `Settings.tsx` (badge verde "No data leaves" / ámbar "Data leaves
      (protected)" + endpoint + flags). Guía `docs/PRIVACY.md` (matriz de 4 modos + cómo configurar
      Ollama/vLLM + limitaciones honestas + roadmap TEE/federación) enlazada desde README. Tests
      `test_privacy.py` (15). Suite 154 passed. Typecheck limpio.
- [ ] `🔴 Difícil` **Confidential computing (TEE)** — roadmap premium: modelo SOTA en enclave (Intel TDX / AMD
      SEV-SNP / NVIDIA H100 CC) + attestation remota → el proveedor no ve el plaintext. No urgente.
- Tiers de pricing: Sovereign(on-prem) / Private(TEE+redacción) / Standard(cloud+redacción).

## ✔️ Hecho recientemente (2026-06-05)

- Arreglado el cuelgue del pipeline (Ollama CPU 5.6 tok/s vs timeout 60s) → OpenRouter para dev.
- BD `cve_intel`: 338K CVEs (CISA KEV + FIRST EPSS), sync diario.
- Correlación CPE→CVE on-demand contra NVD + caché (`cpe_intel.py`).
- `ThreatIntelAgent` ahora determinista (JOIN a `cve_intel`, 0 tokens, sin CVEs alucinados).
- `CorrelationAgent` integrado en el pipeline (servicios detectados → findings de CVE).
- Filtrado de scripts informativos de nmap + dedupe vulners↔NVD por `cve_id`.
- Primer scan real con hallazgos (bse.eu).
