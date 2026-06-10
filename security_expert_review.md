## Lo que falta (lo que un comprador echaría en falta)

Tu cobertura técnica es estrecha: solo nmap y nuclei, y solo activos tipo DOMAIN externos. Un SOAR/ASM serio necesita al menos: escaneo autenticado, web app más profundo, cloud posture (AWS/Azure/GCP), y ojalá ingesta de hallazgos de terceros (importar de Qualys/Tenable/Burp). Ahora mismo eres más un "AI-powered EASM/vuln triage" que un SOAR completo.

Falta la "R" de SOAR: respuesta/orquestación real. El módulo Remediation generó "0 suggestions" y no vi playbooks, integración con ticketing (Jira/ServiceNow), ni acciones automatizadas (bloquear IP, abrir ticket, aislar host). Si lo vendes como "SOAR agéntico", el comprador esperará orquestación accionable, no solo reportes. O añades esto, o cambias la categoría con la que lo vendes.

No vi gestión multi-tenant/organización visible, SSO/SAML, exportes a SIEM, ni API documentada para clientes. Para vender a empresas, SSO y API suelen ser line-items obligatorios.

## Lo que sobra o es ruido

El módulo Findings está inundado de hallazgos INFO tipo "No DOM-based XSS found on port 8080", "No CSRF found", etc. Eso es ruido de salida cruda de nmap que tu Analyst no está filtrando. Un CISO que abre esa lista pierde confianza al instante. Deberías colapsar/ocultar por defecto los "ausencia de hallazgo" y los no verificados.

Solapamiento entre Credential Exposure y la pestaña de breaches dentro de AuthPhishing: ambos hacen HIBP. Consolidaría para no confundir.

El concepto "Karma score" de empleado es simpático pero arriesgado: puntuar a personas puede chocar con RRHH/privacidad en clientes europeos. Lo mantendría opcional y bien enmarcado.

## Pulido que delata el "vibecoded"

Vi errores crudos filtrados a la UI en Job history ("name 'source_id' is not defined", "Server disconnected"). Dos rutas (red-blue, audit-log) renderizaban pantalla en blanco al teclear la URL directamente —el routing no es resiliente a deep-links/refresh. El "Risk Score 447 / +310" con "lower is better" pero subiendo, y "0% critical findings closed ≤7d" dan una primera impresión negativa en el dashboard, que es justo donde decides una demo. Nada de esto es estructural, pero en seguridad la pulcritud transmite confianza y aquí se nota la falta.

## ¿Se vendería bien?

Con matices, sí, pero define la categoría con honestidad. Como "SOAR agéntico" completo todavía no lo es (le falta orquestación/respuesta e integraciones). Como "plataforma de gestión de exposición y triaje de vulnerabilidades potenciada por IA, con priorización EPSS/KEV/SSVC y reducción de falsos positivos por agentes adversariales", es un producto con un ángulo claro y diferenciado, y ese mercado (EASM + vuln management para equipos pequeños/medianos sin SOC grande) está caliente.

El comprador natural no es el banco con 40 analistas (ya tienen Tenable + Splunk + playbooks). Es el MSSP, la consultora de seguridad que escanea muchos clientes, o la empresa mediana sin equipo dedicado que quiere salida priorizada y lista para presentar al consejo (de hecho ya tienes "Email to board" y "Board report", buen instinto comercial).

Si me preguntas dónde invertir las próximas semanas para hacerlo vendible: primero limpia el ruido de Findings y los errores visibles; segundo, añade una integración de ticketing (Jira/ServiceNow) para empezar a justificar la palabra "respuesta"; tercero, decide y comunica con precisión la categoría. Tienes algo real entre manos; el riesgo no es la idea, es prometer "SOAR" y que la demo se quede en "scanner con buen cerebro".

¿Quieres que entre a algún módulo en mayor profundidad (por ejemplo crear un finding, probar un schedule, o revisar el flujo de "New campaign") para afinar recomendaciones concretas?
