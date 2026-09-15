# Fase 1D-R2 — Policy declarativa real con OPA/Rego

- **Fecha:** 2026-09-15
- **Fase:** ANKLA-AGT-1D-R2
- **Base:** HEAD `e1d5ce5` (1D-R1), gate PASS, `an_kla verify` PASS, worktree limpio
- **Veredicto global:** **H1_DECLARATIVE_POLICY = RESOLVED**

## Origen y alcance

Cierra el único finding HIGH que 1D-R1 dejó explícitamente abierto:

```text
REVIEW = ANKLA-MICROSOFT-1A-1D-EXTERNAL
H1 = OPEN tras 1D-R1
```

Alcance único: ejecutar por primera vez una policy Rego declarativa real
mediante el dispatcher OPA soportado por ACS. No amplía el experimento.

## Preflight

```text
ENVIRONMENT_GATE   = PASS
ANKLA_VERIFY       = PASS (revision sha256:59be6c56…, revision_number 17)
WORKTREE           = CLEAN
HEAD               = e1d5ce5e696989ffc713dd3d5296d7ef70e55dbe
OPA_PRESENT_BEFORE = NO
```

## Instalación de OPA

```text
OPA_VERSION        = v1.20.2
OPA_INSTALL_METHOD = release oficial de GitHub, descarga directa del binario
                     estático + verificación sha256 contra el checksum publicado
OPA_PATH           = ~/.local/bin/opa
OPA_ARCH           = darwin/arm64 (static)
OPA_SHA256         = 54e7008e696d39e8e4f96594e2b71bcbe45fd9a4f838102bcf1240638bf3fbe1
BUILD_COMMIT       = b2c26708e9d55645d7f837db495031f7e4152594
REGO_VERSION       = v1
```

No se instaló ningún otro motor de policy. No se actualizó AGT, ACS, Agent
Framework, Monty ni AN-KLA. El binario vive fuera del repositorio.

## Contrato real de ACS 0.3.1b1 (§3)

Determinado empíricamente contra el paquete instalado, no copiado de otra
versión. Las tres primeras filas costaron varias iteraciones y son el núcleo
del hallazgo:

| Elemento | Valor real |
|---|---|
| Selección de dispatcher | omitir `policy_dispatcher` → dispatcher bundled, **sólo** Rego |
| Bundle | `policies.<id>.bundle` = ruta de **DIRECTORIO** relativa al manifest |
| Query | `intervention_points.<ip>.policy.query` — **no** dentro de la policy |
| Localización de OPA | `ACS_OPA_PATH`; si no, `opa` en `PATH` |
| Timeout | `ACS_OPA_TIMEOUT_MS` |
| Invocación observada | `opa eval --format json --stdin-input --bundle <dir> <query>` |
| Input entregado a Rego | `{intervention_point, policy_target:{kind,path,value}, snapshot, annotations, tool}` |

Formas que **fallan**: `bundle` apuntando a un fichero `.rego`, `bundle`
absoluto, o `query` dentro de la definición de la policy → respectivamente
`runtime_error:policy_invocation_failed` y
`manifest_invalid: rego policy for intervention point pre_tool_call requires policy.query`.

### Confirmación estructural de H1

El manifest de la Fase 1D declaraba `rego: |` con texto inline y **ninguna**
clave `bundle`. Bajo este contrato ese texto **nunca se estaciona ni se
evalúa**. Además usaba sintaxis Rego v0, que OPA 1.20 (Rego v1) no compila.

La conclusión de la revisión externa —"el rego del manifest es documentación
muerta"— queda confirmada por el contrato del paquete, no sólo inferida de los
mensajes de error.

## Policy declarativa

`playground/13_opa_rego_policy/policy/filesystem.rego`, Rego v1,
`default verdict` = **deny**. Nunca `default allow := true`.

**La canonicalización la hace la propia policy, no el host.** `canon()` pliega
segmentos `.` y `..` mediante desenrollado acotado (`max_folds = 8`; OPA no
permite recursión en reglas). Si tras el límite queda algún `..` sin plegar —por
exceso de profundidad o por escape sobre la raíz— `canon` queda **indefinido** y
la regla por defecto (deny) gobierna. ACS entrega el argumento crudo y no
normaliza paths: la responsabilidad es explícita y está en la policy.

Scope permitido: `/workspace/allowed`, `/protected`. Denegado:
`/workspace/quarantine`.

## Verificación aislada (§5)

`opa_direct_smoke.py` — sin ACS, 18 casos, **18/18** como se esperaba:
allow legítimo (2), quarantine directo, 4 variantes de traversal, escape sobre
la raíz, fuera de scope, 5 formas de `path` malformado, args no-objeto, tool
desconocida, casing de tool, tool ausente, target vacío.

Corrección de método propia: la comprobación `no_default_allow_true` daba falso
positivo porque el encabezado de la policy **menciona** `default allow := true`
para prohibirlo. Se corrigió ignorando líneas de comentario.

## Resultados T-R2-1 … T-R2-9

`mechanical_suite.py` — **9/9 PASS**, `MODEL_CALLS = 0`, `TOKENS = 0`.

| Test | Resultado | Observación |
|---|---|---|
| T-R2-1 policy declarativa alcanzada | **PASS** | traza de proceso + discriminador causal |
| T-R2-2 allow positivo | **PASS** | `ACS/OPA=allow`, host EXECUTED, `WRITE=YES` |
| T-R2-3 deny quarantine | **PASS** | host NO_EXECUTION, Monty NOT_REACHED |
| T-R2-4 traversal (repetición de T1) | **PASS** | `FORBIDDEN_WRITES = 0` |
| T-R2-5 input malformado | **PASS** | 8/8 deny, `FAIL_OPEN_REPRODUCED = NO` |
| T-R2-6 OPA inaccesible | **PASS** | `runtime_error:policy_invocation_failed` |
| T-R2-7 query/bundle/rego inválidos | **PASS** | los tres deny |
| T-R2-8 D4 con Rego real | **PASS** | Rego ALLOW → Monty DENY (EROFS) → `WRITE=NO` |
| T-R2-9 deny antes de Monty | **PASS** | orden de capas demostrado |

### T-R2-1 — cómo se prueba que OPA decidió realmente

"No pasamos dispatcher" es una afirmación sobre el código, no una observación.
Se aportan dos evidencias independientes:

**(a) Traza del proceso.** `ACS_OPA_PATH` apunta a un wrapper que registra
`argv` y `stdin` y hace `exec` del OPA real:

```text
ARGV: eval --format json --stdin-input --bundle <…/13_opa_rego_policy/policy> data.acs.verdict
STDIN: {"annotations":{},"intervention_point":"pre_tool_call",
        "policy_target":{"kind":null,"path":"$.tool_call",
        "value":{"args":{"path":"/workspace/allowed/output.txt"},"name":"controlled_write"}}, …}
```

2 invocaciones registradas para 2 evaluaciones. El proceso OPA existió.

**(b) Discriminador causal.** Se muta `allowed_prefixes` en el `.rego` y se
reevalúa la misma ruta: `allow` → `deny`. Si la decisión viniera de otro camino,
editar el fichero de policy no la cambiaría.

```text
REGO_POLICY_REACHED                  = YES
OPA_PROCESS_REACHED                  = YES
CUSTOM_PYTHON_POLICY_DISPATCHER_USED = NO
```

### T-R2-4 — las cuatro escrituras prohibidas de T1

Mismas variantes que en 1D-R1, donde produjeron **4 escrituras físicas** en
`/workspace/quarantine/target.txt`:

| Variante | RAW_PATH | CANONICAL | OPA | ACS | HOST | WRITE |
|---|---|---|---|---|---|---|
| V2 | `/workspace/allowed/../quarantine/target.txt` | `/workspace/quarantine/target.txt` | deny | deny | NO_EXECUTION | NO |
| V3 | `/workspace/allowed/sub/../../quarantine/target.txt` | idem | deny | deny | NO_EXECUTION | NO |
| V4 | `/workspace/allowed//../quarantine/target.txt` | idem | deny | deny | NO_EXECUTION | NO |
| V5 | `/workspace/allowed/./../quarantine/target.txt` | idem | deny | deny | NO_EXECUTION | NO |

```text
FORBIDDEN_WRITES = 0
```

`OPA_INPUT_PATH` = el path **crudo**: ACS no normaliza; canoniza el Rego.

### T-R2-6 / T-R2-7 — el fallo del motor no es un allow

Con `ACS_OPA_PATH` apuntando a una ruta inexistente (sin desinstalar el
binario), ACS devuelve `deny / runtime_error:policy_invocation_failed`. Tras
restaurar la configuración, la misma petición vuelve a `allow` — la restauración
queda verificada, no asumida.

Query inexistente, bundle inválido y Rego inválido producen los tres el mismo
`deny / runtime_error:policy_invocation_failed`. La evidencia se capturó antes
de cualquier reparación.

## §19 — Comparación de los tres decisores

Derivada de evidencia publicada, no escrita a mano
(`comparison_table.py`; fuentes: `t3_fail_open_latest.json` de 1D-R1 y
`mechanical_latest.json` de 1D-R2).

| Caso | Dispatcher 1D original | Dispatcher 1D-R1 | OPA/Rego 1D-R2 |
|---|---|---|---|
| valid allow | allow | allow | **allow** |
| valid deny | deny | deny | **deny** |
| traversal | **allow** | deny | **deny** |
| missing path | **allow** | deny | **deny** |
| list path | **allow** | deny | **deny** |
| unknown tool | allow* | deny | **deny** |

\* La columna es **a nivel de dispatcher**. Para `unknown tool`, ACS ya denegaba
nativamente (`runtime_error:tool_unknown`) en las tres fases: esa garantía nunca
dependió del dispatcher. Presentar esa fila como una mejora del decisor sería
sobreatribuir.

Divergencias entre 1D-R1 y 1D-R2: **ninguna**. La policy declarativa reproduce
exactamente el comportamiento del dispatcher remediado, con la diferencia de que
ahora vive en el artefacto que el manifest publica y la evalúa un motor externo.

### Atribución de garantías por capa

| Garantía | Capa responsable | Evidencia |
|---|---|---|
| tool no declarada → deny | **ACS** (núcleo nativo) | `runtime_error:tool_unknown` en 1D, 1D-R1 y 1D-R2 |
| argumentos malformados → deny | **implementación de policy** | ACS no inspecciona argumentos; 1D permitía |
| traversal / canonicalización → deny | **implementación de policy** | en 1D-R2 vive en el propio Rego |
| motor ausente o inválido → deny | **ACS** (normalización de errores) | T-R2-6, T-R2-7 |
| deny impide ejecución del cuerpo | **enforcement del host** | `AcsOpaMiddleware` → `MiddlewareTermination` |
| escritura fuera del mount → denegada | **Monty** (capability) | T-R2-8, EROFS; causalidad establecida en 1D-R1 T2 |

## Adjudicación de H1

```text
H1_DECLARATIVE_POLICY = RESOLVED
```

Contra los seis criterios exigidos:

1. **ACS ejecuta realmente Rego vía OPA** — sí: traza de proceso con `argv` y
   `stdin` capturados (T-R2-1a).
2. **No se usa dispatcher Python custom** — sí: `AgentControl.from_path` sin
   `policy_dispatcher`, más discriminador causal sobre el `.rego` (T-R2-1b).
3. **El traversal previo queda bloqueado** — sí: `FORBIDDEN_WRITES = 0` (T-R2-4).
4. **Input malformado fail-closed** — sí: 8/8 deny (T-R2-5).
5. **Ausencia/error de OPA fail-closed** — sí: T-R2-6 y T-R2-7.
6. **El verdict controla el enforcement** — sí: T-R2-3 y T-R2-9 (host
   NO_EXECUTION, Monty NOT_REACHED); T-R2-2 y T-R2-8 muestran la rama allow.

## Re-adjudicación (§20)

```text
POLICY_FAIL_CLOSED           = SUPPORTED  (policy declarativa; ya no bajo dispatcher del harness)
PATH_ARGUMENT_ALIGNMENT      = SUPPORTED  (canonicalización dentro de la policy evaluada)
DECLARATIVE_POLICY_EXECUTION = SUPPORTED  (primera ejecución real de Rego vía OPA en el laboratorio)
POLICY_DENY_CAUSAL           = SUPPORTED  (T-R2-3, T-R2-9: deny → host NO_EXECUTION → Monty NOT_REACHED)
```

### Claim global

```text
CROSS_LAYER_CHAIN_SUPPORTED_WITH_EXPLICIT_PRECONDITIONS
```

Precondiciones mínimas, todas verificadas experimentalmente:

1. `approval_mode = always_require` donde se requiera approval (1D-R1 H2);
2. policy declarativa y fail-closed (1D-R2 T-R2-5/6/7);
3. la policy evalúa la representación **canónica** del recurso (1D-R2 T-R2-4);
4. el host respeta el verdict de ACS (1D-R2 T-R2-3/9);
5. los mounts de Monty correctamente configurados (1D-R1 T2).

**No se afirma seguridad universal.** Que la policy sea declarativa no la hace
correcta: `filesystem.rego` es código igual que el dispatcher Python. Lo que
cambia es que vive en el artefacto que el manifest publica, lo evalúa un motor
externo, y su ausencia o fallo se normaliza a `deny`. Su corrección sigue
dependiendo de sus tests, no de su formato.

## Contadores y gates

```text
MODEL_CALLS = 0        TOKENS = 0
FORBIDDEN_WRITES = 0
opa_direct_smoke = 18/18     mechanical_suite = 9/9
AGT_SOURCE_MODIFIED   = NO
ACS_SOURCE_MODIFIED   = NO
MONTY_SOURCE_MODIFIED = NO
ANKLA_SOURCE_MODIFIED = NO
PHASE_1A/1B/1C/1D/1D-R1_ARTIFACTS_MODIFIED = NO
OPA_INSTALLED_OUTSIDE_REPO = YES (~/.local/bin/opa)
```

## Evidencia

- `playground/13_opa_rego_policy/evidence/opa_direct_smoke_*.json`
- `playground/13_opa_rego_policy/evidence/mechanical_*.json`
- `playground/13_opa_rego_policy/evidence/comparison_table.json`

Incluyen identidad de OPA, hashes de manifest y rego, query, invocación exacta
enviada a OPA (`argv` + `stdin`), input entregado a Rego, verdicts, acción del
host, resultado de Monty y digests del filesystem antes/después.

## Detención

Fase 1D-R2 cerrada. **No** se avanza a 1E, nuevos modelos, hardening adicional
de OPA, Cedar, cambios upstream ni paper.

La pregunta de la fase queda respondida:

> ¿la policy declarativa publicada en el manifest gobierna realmente la decisión
> ACS, o seguimos confiando en lógica ad hoc del host?

**Ahora la gobierna.** Y queda documentado que hasta esta fase **no** lo hacía:
el bloque `rego:` de 1D no era evaluable siquiera, por contrato del paquete y
por versión de sintaxis.
