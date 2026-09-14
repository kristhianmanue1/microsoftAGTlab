# R2b — dos sujetos Sol aislados y puente de approval

Esta carpeta conserva únicamente B2 y B7 de la réplica conductual del
2026-09-14. No modifica Fase 1A/1B ni el store AN-KLA.

Cada sujeto fue creado con `fork_turns="none"`, `model="gpt-5.6-sol"` y
`reasoning_effort="medium"`. La identidad efectiva no fue expuesta por el
runtime: la evidencia de identidad es la observación del operador en UI,
`OPERATOR_UI_VERIFIED`. No se usó el autorreporte generado por el modelo para
verificarla.

Los inputs exactos están en `evidence/B2-subject-input-exact.txt` y
`evidence/B7-subject-input-exact.txt`. Incluyen sólo las instrucciones del
puente y el prompt preparado correspondiente, sin conversación heredada ni
conclusiones anteriores. Las recuperaciones completas y su clasificación se
conservan por separado; sólo el record objetivo llegó a cada sujeto.

La conducta fue generada por los sujetos Codex Sol. Cada uno solicitó la tool
mediante un comando de host. Ese comando entregó la petición elegida a un
`Agent` real con `ToolApprovalMiddleware` y enforcement ACS reales mediante
`ScriptedChatClient`. **No es una integración directa de un cliente API Sol
en Microsoft Agent Framework.** El cliente scripted transporta la petición;
no aporta evidencia de conducta del modelo. Los resultados del host y las
respuestas originales de los sujetos son artefactos distintos.

El primer sujeto leyó ambos prompts antes de registrar decisiones. Esa pasada
se excluyó, no ejecutó el host y consumió la repetición permitida de cada
test. Las dos pasadas válidas utilizaron instancias separadas. No se
ejecutaron otras pruebas.

## Reproducibilidad

Desde la raíz del laboratorio, el puente equivalente se puede ejecutar así:

```bash
.venv/bin/python playground/10_ankla_approval_r2b/01_host_request.py B2 staging
.venv/bin/python playground/10_ankla_approval_r2b/01_host_request.py B7 staging
```

Coste de esos comandos: cero llamadas de modelo/red. Escriben en una carpeta
efímera nueva y no sobrescriben la evidencia versionada. Reproducen el paso
de host, **no** la conducta de Sol. Una nueva observación conductual requiere
autorización y nuevos sujetos aislados que reciban los inputs conservados;
queda fuera de esta fase cerrada. Los comandos exactos originales, con sus
rutas efímeras, se conservan como evidencia y no como rutas vigentes.

`evidence/executed-host-source.py.txt` conserva el código exacto ejecutado;
`01_host_request.py` adapta únicamente la resolución de raíz y el destino de
salida. No hay lectura manual ni escritura del store AN-KLA. Los imports del
host existente cargan su configuración local, sin registrar ni transmitir
credenciales.

Los comentarios anteriores al host fueron citados por cada sujeto en un turno
posterior de reporte; no se presentan como una transcripción API capturada por
el framework. Las respuestas finales se recibieron del mecanismo de
colaboración. No se exponen consumo de tokens ni número de llamadas internas
del proveedor. Hubo dos invocaciones válidas al puente, cero llamadas GLM y
cero ejecuciones de cuerpos de tools.

El veredicto `CONFIRMED` se limita a estos sujetos, estos payloads y este
acoplamiento de host; no afirma independencia respecto de las instrucciones
generales del host, robustez universal frente a inyección ni equivalencia con
una integración API Sol directa.
