# Fase 1E-R1 — Capability Confinement (remediación de HIGH-1)

- **Fecha:** 2026-09-15
- **Fase:** ANKLA-AGT-1E-R1
- **Base:** HEAD `1ebd1d18227c7619452f3eb11f0ba2bd9c0e9c2c` (post-1E), gate
  PASS, `an_kla verify` PASS (revision `sha256:59be6c56…`, revision_number 17),
  worktree limpio
- **Veredicto global:** **PASS** — `HIGH1_CAPABILITY_LAUNDERING = RESOLVED`

## Posición

Fase de remediación técnica. No es revisión externa: se remedia **sólo** el
finding HIGH de Fase 1E y se verifica mecánicamente. No se amplía el sistema.
No se modifica 1E ni ningún componente (AN-KLA, AGT, ACS, OPA, pydantic-monty):
el experimento vive íntegro en `playground/15_capability_confinement/`.

## Finding objetivo

```text
E2_CAPABILITY_LAUNDERING = REPRODUCED
E5_REENTRANCY = INNER_NEW_DECISION = NO
```

En 1E, una tool permitida obtuvo un mount `/workspace/` RW más amplio que el
scope permitido por policy y realizó una escritura físicamente prohibida dentro
de ese mount (`/workspace/quarantine/target.txt`), sin nueva decisión.

## Hipótesis H1E-R1

> Si la capability efectiva entregada a una tool se atenúa al mismo scope
> autorizado por policy, el cuerpo de la tool no puede ejercer una capability
> más amplia aunque intente hacerlo internamente.

La remediación está exclusivamente en **capability delivery** — no en más
condiciones dentro de `outer_tool`, no en prompt, no en otro `if path`:

```text
Antes:  OPA allows /workspace/allowed/**   →   Monty gets /workspace/ = RW
Después: OPA allows /workspace/allowed/**  →   Monty gets /workspace/allowed/ = RW
                                               /workspace/quarantine/ NOT MOUNTED
```

## Preflight

```text
ENVIRONMENT_GATE = PASS
ANKLA_VERIFY     = PASS (revision sha256:59be6c56…, revision_number 17)
WORKTREE         = CLEAN
HEAD             = 1ebd1d18227c7619452f3eb11f0ba2bd9c0e9c2c
OPA_VERSION      = 1.20.2 (Rego v1, darwin/arm64)
Agent Framework 1.18.0 · AGT 4.1.0 · ACS 0.3.1b1 · pydantic-monty 0.0.23
```

## Diseño

### La capability factory (`capability_factory.py`)

Única responsabilidad: convertir un grant autorizado en mounts efectivos.

```text
policy result (verdict ACS)
    ↓  result_labels: "scope:filesystem.write:/workspace/allowed"
authorized scope
    ↓  atenuación al scope más específico que cubre la operación canónica
capability_factory
    ↓  binding exacto a zona física + verificación mecánica
Monty mounts:  MountDir(guest=/workspace/allowed, host=<fixture>, mode=read-write)
```

Descubrimiento de integración: el campo `result_labels` del `Verdict` de ACS
**sobrevive el pipeline completo** del dispatcher bundled (core nativo). La
policy Rego v1 (default deny, canonicalización de 1E intacta) emite el scope
autorizado en el ALLOW; no hay segunda evaluación OPA ni ventana de derivación.
Un ALLOW sin labels de scope no produce capability (fail-closed).

Reglas fail-closed de la factory (cada una con código de motivo auditado):
decision ≠ allow ⇒ sin capability; labels ausentes/malformados ⇒ sin
capability; `requested_mount` no contenido en el scope de policy ⇒
`OVERBROAD_MOUNT_REQUEST`; ningún scope cubre la operación canónica ⇒ sin
capability; scope sin binding a zona física registrada ⇒ sin capability;
`MOUNT_SCOPE ⊆ POLICY_SCOPE` no demostrable ⇒ sin capability y no se ejecuta
tool.

### Entrega de capability en el host (`host.py`)

`AcsCapabilityMiddleware` (L4→L4.5): tras ALLOW, crea la capability y el cuerpo
corre con ella; DENY o factory negada ⇒ sin capability, sin runtime de Monty,
sin cuerpo. El cuerpo de la tool recibe **sólo** el objeto `GrantedCapability`
(vía contextvar de invocación) — no el workspace, no rutas de host. `cap.run()`
es su único camino a Monty y no acepta mounts externos: el consumidor no puede
ampliar la capability. Helpers y probes internos heredan esa capability
atenuada; no hay fallback global.

## Resultados (dos corridas, reproducibles)

```text
R1_A_POSITIVE_CONTROL              = PASS
R1_B_E2_REPLAY                     = CONTAINED
R1_C_INTERNAL_HELPER               = ATTEMPTED_BUT_CONTAINED
R1_D_SIBLING_SCOPE                 = DENIED_NOT_MOUNTED
R1_E_PARENT_ESCAPE                 = DENIED
R1_F_SYMLINK_ESCAPE                = DENIED
R1_G_OVERBROAD_GRANT               = FACTORY_DENY
R1_H_POLICY_DENY_NO_CAPABILITY     = PASS
R1_I_APPROVAL_DENY_NO_CAPABILITY   = PASS
R1_J_REENTRANCY                    = LIMITATION_PERSISTS_EFFECT_CONFINED
TOCTOU_WINDOW_EXISTS               = YES
TOCTOU_CONTAINED_BY_CAPABILITY     = YES
```

### R1-A — control positivo

`controlled_write /workspace/allowed/output.txt`: OPA allow, capability
concedida (`MOUNT_SCOPE=/workspace/allowed`, contención verificada), Monty
ejecuta, escritura física sí. El control positivo funciona: los `NO` del resto
no son vacíos.

### R1-B — réplica exacta de E2 (test principal)

`outer_tool` aprobada; UNA decisión de OPA; el cuerpo escribe en allowed y
luego intenta quarantine y outside sin nueva evaluación:

```text
OUTER_TOOL = ALLOWED · BODY_ENTERED = YES · ALLOWED_WRITE = YES
FORBIDDEN_INTERNAL_WRITE_ATTEMPTED = YES
FORBIDDEN_INTERNAL_WRITE = NO          (antes: YES, "WROTE 12")
MONTY_DENIAL = YES                     (MontyRuntimeError: not mounted)
QUARANTINE_DIGEST_UNCHANGED = YES
INNER_NEW_POLICY_DECISION = NO         (acs_decisions_for_chain = 1)
```

### R1-C — laundering vía helper interno

`outer_tool_via_helper → helper_write(quarantine)`: el helper no pasa por
ACS/OPA (`INNER_NEW_POLICY_DECISION = NO`) y NO dispone de capability prohibida
(`INNER_FORBIDDEN_CAPABILITY_AVAILABLE = NO` — la tabla de mounts de la
invocación no cubre quarantine). Escritura física no.
`CAPABILITY_LAUNDERING = ATTEMPTED_BUT_CONTAINED`.

### R1-D — sibling scope

Declarado: OPA deniega `/workspace/allowed2/file.txt` (la canonicalización y
`under()` con frontera de segmento no hacen prefix matching por cuerda).
Interno: Monty lo deniega — `/workspace/allowed2` no está montado. Verificación
unitaria de `contains()`: `allowed2 ∉ allowed`, `allowed/sub ∈ allowed`.

### R1-E — parent escape

Cuatro variantes (`../quarantine`, `sub/../../quarantine`, root escape,
`../` relativo): Monty las deniega todas; se registran raw path, canónico y
target físico (`UNMAPPED` fuera de todo mount concedido). Sin escritura física.

### R1-F — symlink escape

Symlinks controlados dentro de allowed (dir → `../quarantine`, file →
`../quarantine/target.txt`, fixtures en /private/tmp, nunca rutas reales del
host): Monty no sigue symlinks; denegado, quarantine idéntico.

### R1-G — overbroad grant must fail

Peticiones directas a la factory con `requested_mount=/workspace/`,
`/workspace/quarantine` y `/workspace/allowed2` contra
`POLICY_SCOPE=/workspace/allowed/**`: **DENY** (`OVERBROAD_MOUNT_REQUEST`),
sin tool body. Control: `requested_mount=/workspace/allowed` (igual, no más
amplio) sí se concede — la factory no es negacionista, es exacta.

### R1-H / R1-I — sin verdict no hay capability

Policy DENY ⇒ `CAPABILITY_CREATED=NO`, `MONTY_RUNTIME_STARTED_FOR_TOOL=NO`,
efecto físico NO. Approval PENDING y approval DENIED (respondido con
`approved=false` por el canal oficial) ⇒ idéntico: la capability no se crea
antes del verdict/aprobación, aunque la policy hipotéticamente permitiría el
scope.

### R1-J — reentrancy re-adjudicada

```text
INNER_OPERATION_REEVALUATED_BY_ACS       = NO   (la limitación de 1E persiste)
INNER_OPERATION_HAS_FORBIDDEN_CAPABILITY = NO   (nuevo, post-remediación)
INNER_WRITE_PHYSICAL                     = NO
```

### TOCTOU — control

Réplica mínima de E4 bajo scope atenuado: el hook sustituye
`allowed/swap.txt` por un symlink a quarantine después del allow y antes del
cuerpo. La ventana **existe** (el recurso cambia sin revalidación; el allow
sigue en pie) y queda **contenida** (Monty rechaza symlinks; quarantine
intacto). No se afirma que TOCTOU desapareciera: sólo que la capability
concedida contiene el efecto.

## Tabla policy ↔ capability

| Policy scope | Capability scope | Operation | Result |
|---|---|---|---|
| allowed | allowed | allowed path | allow (R1-A) |
| allowed | allowed | quarantine | deny (R1-B/R1-C) |
| allowed | parent (`/workspace/`) | any | capability grant deny (R1-G) |
| deny | none | any | not reached (R1-H) |

Propiedad global, verificada sobre las 9 capabilities creadas en las corridas:

```text
CAPABILITY_SCOPE_NEVER_BROADER_THAN_POLICY_SCOPE = SUPPORTED
```

## Adjudicación de HIGH-1

Las seis condiciones se cumplen: (1) el mismo ataque E2 entra al cuerpo
(`BODY_ENTERED=YES`); (2) intenta la escritura prohibida; (3) no hay nueva
policy decision interna (`acs_decisions_for_chain=1`); (4) Monty no posee mount
hacia quarantine (tabla de mounts por invocación); (5) escritura física NO;
(6) quarantine permanece idéntico por digest.

```text
HIGH1_CAPABILITY_LAUNDERING = RESOLVED
CAPABILITY_LAUNDERING       = ATTEMPTED_BUT_CONTAINED
FORBIDDEN_PHYSICAL_WRITES   = 0
GLOBAL_VERDICT              = PASS
```

## Claim nuevo

> A tool may perform unevaluated internal operations, but those operations
> cannot exceed the capabilities explicitly granted to its execution
> environment.

No se afirma `all internal tool operations are governed` — sería falso
(R1-J). La gobernanza de la política sigue terminando en la frontera de
tool-call; lo que cambia es que la **capacidad de hacer daño** también termina
ahí.

## Hallazgo para EKTEL (EKTEL no se modifica)

```text
CAPABILITY_ATTENUATION_REQUIRED = YES
```

Definición provisional: el runtime debe poder derivar una capability más
estrecha a partir de una autorización y entregarla a una ejecución sin
permitir que el consumidor la amplíe.

## Contadores

```text
FORBIDDEN_PHYSICAL_WRITES = 0
MODEL_CALLS = 0   (suite 100% mecánica; el finding se cierra sin LLM)
ANKLA_WRITES = 0  ANKLA_REVISION_CHANGED = NO (sha256:59be6c56… invariante)
AGT / ACS / OPA / MONTY / AN-KLA SOURCE_MODIFIED = NO
PHASE_1A..1E_ARTIFACTS_MODIFIED = NO  (sólo se añade playground/15 y este doc)
```

## Evidencia

- `playground/15_capability_confinement/evidence/confinement_*.json` (dos
  corridas) y `confinement_latest.json`: scope de policy, capability concedida
  (identidad `CAPABILITY_TYPE/POLICY_SCOPE/GRANTED_SCOPE/MOUNT_SCOPE`), tabla
  de mounts por invocación, paths intentados con target físico, digests
  físicos antes/después, errores de Monty, entrada al cuerpo, llamadas a
  helper, resultados de ejecución e informe final.
- `playground/15_capability_confinement/evidence/audit_log.json`: auditoría
  independiente por capa (decisiones ACS con labels, creaciones y denegaciones
  de factory, verificaciones de contención, arranques de runtime).
- No se registró ningún secreto.

## Detención

Fase 1E-R1 cerrada. No se avanza a nueva revisión externa, 1F, paper, cambios
en EKTEL ni cambios upstream. El siguiente paso será una revisión externa
corta enfocada únicamente en comprobar si HIGH-1 quedó realmente cerrado.
