# 13 — Policy declarativa real con OPA/Rego (Fase 1D-R2)

Fase de alcance único: **cerrar H1**, el último finding HIGH abierto de la
revisión adversarial externa `ANKLA-MICROSOFT-1A-1D-EXTERNAL`.

> H1 — hasta 1D-R1, **ninguna** decisión de policy del laboratorio provino de
> una policy declarativa. Todas las salían de un dispatcher Python del harness.
> El bloque `rego:` del manifest de 1D era documentación muerta.

Aquí la cadena es, por primera vez:

```text
ACS manifest → policy type=rego → dispatcher bundled de ACS
             → proceso opa → query Rego → verdict normalizado por ACS
             → enforcement del host → Monty → filesystem
```

**No se suministra `policy_dispatcher`.** Ésa es la diferencia esencial.

## Contrato real de ACS 0.3.1b1

Verificado empíricamente contra el paquete instalado (§3 de la fase), no
copiado de la documentación de otra versión:

| Elemento | Valor real |
|---|---|
| Selección de dispatcher | omitir `policy_dispatcher` en `AgentControl.from_path` → bundled, sólo Rego |
| Bundle | `policies.<id>.bundle` = **ruta de DIRECTORIO** relativa al manifest |
| Query | `intervention_points.<ip>.policy.query` (**no** dentro de la policy) |
| Localización de OPA | `ACS_OPA_PATH`, si no `opa` en `PATH` |
| Timeout | `ACS_OPA_TIMEOUT_MS` |
| Invocación | `opa eval --format json --stdin-input --bundle <dir> <query>` |
| Input a Rego | `{intervention_point, policy_target:{kind,path,value}, snapshot, annotations, tool}` |

Rutas que **no** funcionan y cuestan tiempo: `bundle` apuntando a un fichero
`.rego` concreto, `bundle` con ruta absoluta, o `query` dentro de la definición
de la policy. Las tres producen `runtime_error:policy_invocation_failed` o
`manifest_invalid`.

### Por qué esto confirma H1 estructuralmente

El manifest de la Fase 1D declaraba `rego: |` con texto inline y **ninguna**
clave `bundle`. Bajo este contrato ese texto nunca se estaciona ni se evalúa.
Además usaba sintaxis Rego v0 (`verdict = {...} { ... }`), que OPA 1.20 —con
`Rego Version: v1`— ni siquiera compila. La conclusión de la revisión externa
("el rego es documentación muerta") queda confirmada por el contrato del
paquete, no sólo por inferencia sobre los mensajes de error.

## Contenido

| Ruta | Qué es |
|---|---|
| `manifest.yaml` | Manifest ACS con `type: rego` + `bundle: policy`. Sin dispatcher Python. |
| `policy/filesystem.rego` | Policy declarativa, Rego v1, **default deny**. Canonicaliza paths dentro del propio Rego. |
| `opa_direct_smoke.py` | §5 — verificación aislada con `opa eval`, sin ACS. 18 casos. |
| `acs_opa_host.py` | Cadena L3–L7 con el dispatcher bundled. Reutiliza Monty de 1D sin modificarlo. |
| `mechanical_suite.py` | T-R2-1 … T-R2-9. **0 llamadas LLM.** |
| `comparison_table.py` | §19 — tabla derivada de evidencia: dispatcher 1D vs 1D-R1 vs OPA/Rego. |
| `fixtures/` | `workspace/` (RW, con `quarantine/` **existente**) y `protected/` (RO). |

## Canonicalización: quién la hace

**La hace el Rego, no el host.** `canon()` pliega segmentos `.` y `..` con
desenrollado acotado (`max_folds = 8`, sin recursión porque OPA no la permite
en reglas). Si tras el límite queda cualquier `..` sin plegar —por exceso de
profundidad o por escape sobre la raíz— `canon` queda **indefinido** y la regla
`default verdict` (deny) gobierna.

ACS entrega a Rego el argumento **crudo**; no normaliza paths. Esa
responsabilidad es explícita y está en la policy, no oculta en una capa
intermedia.

## Uso

```bash
export ACS_OPA_PATH="$HOME/.local/bin/opa"   # o tener `opa` en PATH

.venv/bin/python playground/13_opa_rego_policy/opa_direct_smoke.py   # aislado
.venv/bin/python playground/13_opa_rego_policy/mechanical_suite.py   # T-R2-1..9
.venv/bin/python playground/13_opa_rego_policy/comparison_table.py   # §19
```

## Resultados (corrida 2026-09-15)

```text
opa_direct_smoke : 18/18
mechanical_suite : 9/9 PASS
MODEL_CALLS = 0   TOKENS = 0

REGO_POLICY_REACHED                  = YES
OPA_PROCESS_REACHED                  = YES
CUSTOM_PYTHON_POLICY_DISPATCHER_USED = NO
FORBIDDEN_WRITES                     = 0
FAIL_OPEN_REPRODUCED                 = NO
```

### Cómo se prueba que OPA realmente decidió

Dos evidencias independientes, porque "no pasamos dispatcher" es una afirmación
sobre el código, no una observación:

1. **Traza de proceso.** `ACS_OPA_PATH` apunta a un wrapper que registra `argv`
   y `stdin` y hace `exec` del OPA real. La traza capturada:

   ```text
   ARGV: eval --format json --stdin-input --bundle <.../13_opa_rego_policy/policy> data.acs.verdict
   STDIN: {"annotations":{},"intervention_point":"pre_tool_call","policy_target":{...}}
   ```

2. **Discriminador causal.** Se muta `allowed_prefixes` en el `.rego` y se
   reevalúa la misma ruta: `allow` → `deny`. Si la decisión viniera de otro
   camino, no cambiaría al editar el fichero de policy.

### Nota sobre corridas superadas

Se conserva la corrida intermedia con su defecto documentado, igual que en
1D-R1. Los alias `*_latest.json` apuntan siempre a la corrida válida.

| Artefacto | Estado | Motivo |
|---|---|---|
| `opa_direct_smoke_20260915T024940Z.json` | **superado** | `no_default_allow_true=False` era un falso positivo: la comprobación textual encontraba `default allow := true` dentro del **comentario** de la policy que lo prohíbe |
| `opa_direct_smoke_20260915T024956Z.json` | **válido** | la comprobación ignora líneas de comentario |
| `events_1d.jsonl` | traza | log append-only de `log_event` heredado de 1D durante las corridas de 1D-R2; confirma que la evidencia de 1D no fue contaminada |

## Límite honesto

Que la policy sea declarativa **no** la hace correcta. `filesystem.rego` es
código igual que el dispatcher Python; lo que cambia es que ahora vive en el
artefacto que el manifest publica, lo evalúa un motor externo, y su fallo o
ausencia se normaliza a `deny`. La corrección de la policy sigue dependiendo de
sus tests (T-R2-2 … T-R2-5), no de su formato.

Detalle y adjudicación: `docs/history/2026-09-14-fase-1d-r2-opa-rego.md`.
