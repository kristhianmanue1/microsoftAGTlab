# Fase 1E-R2 — Capability Integrity & Trust Binding

**Fase:** ANKLA-AGT-1E-R2 · **Fecha:** 2026-09-15 · **Base:** HEAD
`fe739ade473b9fd66cf9be79567100da27eb0876` (post-1E-R1) · **Coste:** 0
llamadas a modelo (suite 100% mecánica, `MODEL_CALLS = 0`) · **AN-KLA: 0
escrituras** (revisión `sha256:59be6c56…` invariante antes/después).

Remediación mecánica de los findings abiertos por la revisión externa
`ANKLA-AGT-1E-R1-EXTERNAL`. Los artefactos 1E y 1E-R1 permanecen intactos.

## Objetivo de la fase

Cerrar exactamente estos findings (ningún otro):

```text
A2_MOUNT_INJECTION
A3_POST_GRANT_MUTATION
A9_RESULT_LABEL_SCOPE_TRUST
```

## Remediaciones implementadas

- `GrantedCapability` frozen con verificación de integridad (sello HMAC);
- revalidación del sello ANTES de crear mounts (materialización dentro de
  `run()`, sin override posterior);
- único camino autorizado de creación de runtime Monty;
- `ZoneRegistry` como trust root;
- el veredicto transporta identidad de zona/capability, nunca paths
  arbitrarios.

```text
A2_MOUNT_INJECTION             = REPRODUCED → R2-3
A3_POST_GRANT_MUTATION         = REPRODUCED → R2-1 (HIGH principal)
A4_E2_REPLAY                   = SUSTAIN    → R2-6 (regresión)
A9_RESULT_LABEL_SCOPE_TRUST    = PARTIAL    → R2-4 / R2-5
A11/A12_NO_VERDICT_NO_CAPABILITY = SUSTAIN  → R2-7 (regresión)
A13_REENTRANCY                 = NO_REEVALUATION → R2-8 (readjudicación)

A1, A5, A6 = NOT_REPRODUCED · A7 = DENIED · A8 = NO · A10 = NOT_REPRODUCED_IN_PIPELINE
(esos findings no se tocan: no hay nada que remediar)
```

## Preflight (registrado al inicio de la fase)

```text
ENVIRONMENT_GATE = PASS (exit 0)
ANKLA_VERIFY     = PASS (ok:true, revision sha256:59be6c56…, revision_number 17)
HEAD             = fe739ade473b9fd66cf9be79567100da27eb0876
WORKTREE         = CLEAN
OPA_VERSION      = 1.20.2
```

## Objetivo

> Una capability concedida debe quedar estructuralmente ligada a los
> atributos autorizados en el momento del grant, y el consumidor no debe
> poder ampliarla posteriormente.

Propiedades bajo prueba:

```text
GRANT_IMMUTABLE_AFTER_CREATION
MOUNT_DERIVED_ONLY_FROM_VALIDATED_GRANT
NO_ALTERNATE_MOUNT_INJECTION
POLICY_SCOPE_BOUND_TO_GRANT_SCOPE
```

## Principio de diseño (casi todo el cambio respecto de R1)

No más `if` dentro de la tool. No confiar en que el consumidor "no
modificará" el objeto. La capability es segura frente a un consumidor hostil
dentro del modelo de amenaza experimental.

### R2-A — capability inmutable y sellada (`capability.py`)

`GrantedCapability` es un `@dataclass(frozen=True)` con inmutabilidad
transitiva real: `operation_paths` es tuple, `policy_binding` es tuple de
tuples, `identity` es un `MappingProxyType` sobre snapshot fresco. Pero
**`frozen=True` SOLO no basta** — un consumidor hostil lo salta con
`object.__setattr__` (vector reproducido en R2-1: el bypass SÍ muta el
campo). Por eso la autenticidad descansa en un **sello HMAC-SHA256** sobre
la identidad completa del grant, con clave de proceso privada del módulo:

```text
__post_init__ verifica el sello → un objeto forjado o un clon
    dataclasses.replace(...) con campos ampliados NO LLEGA A EXISTIR.
run() RE-verifica el sello sobre los valores ACTUALES de los campos
    antes de materializar nada → si alguien mutó el objeto por debajo de
    frozen, el runtime NO ARRANCA (fail-closed, auditado).
Los mounts se materializan DENTRO de run() a partir del grant verificado:
    no hay tabla cacheada que sustituir ni override posterior.
```

### R2-B — un solo camino a Monty

Ruta completa (R2-B): todas las rutas hacia creación de Monty runtime en los
fuentes de la fase son inspeccionadas mecánicamente por la suite:

```text
MONTY_RUNTIME_CREATION_PATHS   = 1   (GrantedCapability.run, capability.py)
AUTHORIZED_PATHS               = 1
UNAUTHORIZED_ALTERNATIVE_PATHS = 0
```

La firma de la factory NO acepta mounts (`requested_mount` de R1 fue
eliminado) y `run(code, *, label="")` no tiene parámetros de mounts, host
paths ni workspace roots. `host.py` no importa `pydantic_monty`. Kwargs de
inyección → `TypeError` (sin runtime).

### R2-C — binding policy → zone (`capability_factory.py`)

Remediación de A9: los `result_labels` no son raíz de confianza. La policy
ya NO transporta paths; nombra una identidad lógica:

```text
R1:  label "scope:filesystem.write:/workspace/allowed"  (path → host confía)
R2:  label "zone:filesystem.write:workspace.allowed"    (sólo identidad)

OPA elige zona lógica autorizada
    ↓
zone_registry del HOST (raíz de confianza, pre-registrada, inmutable:
    MappingProxyType + Zone frozen) resuelve zona →
    capability / guest_root / host_root
    ↓
la factory verifica la operación contra la zona (canonical + contains)
    ↓
capability inmutable sellada emitida
```

La policy NO puede fabricar `host_path` ni mount path: sólo seleccionar una
identidad conocida. Zone_id desconocido, malformado, de otra capability o
labels vacíos ⇒ fail-closed (`MALFORMED_ZONE_LABEL`, `UNBOUND_ZONE_ID`,
`NO_ZONE_FOR_CAPABILITY`, `NO_ZONE_LABELS`).

## Ficheros

| Fichero | Papel |
|---|---|
| `capability.py` | `GrantedCapability` inmutable + sello HMAC + `run()` con re-verificación |
| `capability_factory.py` | `Zone`/`ZoneRegistry` (trust root) + factory con binding policy→zone |
| `host.py` | cadena ACS → factory → cuerpo → Monty; tools + cuerpos hostiles |
| `mechanical_suite.py` | tests R2-A, R2-1..R2-8, TOCTOU + informe y evidencia |
| `policy/filesystem.rego` | policy Rego v1 (default deny; labels `zone:` sin paths) |
| `manifest.yaml` | manifest ACS (sin policy_dispatcher: OPA bundled) |
| `fixtures/` | allowed / quarantine / outside (copiadas a /private/tmp) |
| `evidence/` | JSON de cada corrida + audit log independiente |

## Ejecución

```bash
.venv/bin/python playground/16_capability_integrity/mechanical_suite.py
```

## Resultados (cuatro corridas 2026-09-15, reproducibles y equivalentes)

Dos corridas de la fase de remediación (04:39:39Z y 04:43:09Z) y dos corridas
de congelación (04:52:58Z y 04:53:02Z): las cuatro `GLOBAL_VERDICT = PASS`
con resultados equivalentes test a test (`RESULTS_EQUIVALENT = YES`).

| Test | Escenario | Resultado |
|---|---|---|
| R2-A | control positivo: allow + grant sellado + escritura permitida | PASS |
| R2-1 | **A3 post-grant mutation** (HIGH principal) | **CLOSED** |
| R2-2 | object replacement (gemelos hostiles) | CLOSED |
| R2-3 | **A2 mount injection** — rutas hacia Monty | CLOSED |
| R2-4 | **A9 trust root** — zone_registry como raíz | CLOSED |
| R2-5 | binding policy→zone→grant | SUPPORTED |
| R2-6 | A4 sustain — réplica E2 (laundering interno) | SUSTAINED |
| R2-7 | A11/A12 sustain — sin verdict no hay capability | PASS |
| R2-8 | A13 — reentrancy (limitación persiste) | LIMITATION_PERSISTS_EFFECT_CONFINED |
| TOCTOU | ventana decisión→ejecución bajo grant sellado | WINDOW_CONTAINED |

**Corrida descartada (provenance):** la primera corrida completa de la fase
falló ANTES de escribir evidencia por un bug de integración propio del
harness (pydantic-monty exige `list` de `MountDir`, la suite pasaba tuple;
`TypeError: mount must be a MountDir, a list of MountDir, or None`).
Corregido el harness se obtuvieron las cuatro corridas válidas de arriba.
No se descartó ni borró ninguna corrida fallida ya registrada.

### R2-1 en detalle (el ataque reproducido por la revisión, ahora cerrado)

El cuerpo recibe un grant válido (`mount_before = /workspace/allowed RW`) e
intenta ampliarlo a `/workspace` RW para escribir en quarantine:

```text
SETATTR mount_scope/host_path/granted_scope/mode/zone_id = NO (FrozenInstanceError)
MUTATE operation_paths/policy_binding/identity           = NO (AttributeError)
BYPASS object.__setattr__ (salta frozen)                 = ACCEPTED … pero INERT:
GRANT_INVALIDATED_AFTER_BYPASS                           = YES
ESCALATION_RUNTIME_STARTED                               = NO
ESCALATION_REFUSED_BY_SEAL                               = YES (GrantVerificationFailed)
DATACLASSES_REPLACE_WIDEN                                = NO (GrantVerificationFailed)
FORGED_CONSTRUCTION                                      = NO (GrantVerificationFailed)
RUN_EXTRA_MOUNTS_KWARG                                   = NO (TypeError)
MUTATION_ACCEPTED                                        = NO
QUARANTINE_DIGEST_UNCHANGED                              = YES
MONTY_RUNTIMES_STARTED (delta)                           = 1 (sólo la escritura declarada)
```

El bypass de `frozen` muta el objeto pero invalida el sello: no hay runtime,
no hay efecto. Ésa es la diferencia estructural respecto de R1, donde el
mismo vector producía `write quarantine succeeds`.

### R2-2 en detalle (object replacement)

`dataclasses.replace` y la forja desde cero no llegan a existir (el sello se
verifica en `__post_init__`). `copy.copy` salta `__init__` y SÍ produce un
gemelo — pero con autoridad IDÉNTICA (`AUTHORITY_IDENTICAL = YES`): su
escalación alcanza a Monty y es denegada por no existir el mount
(`MONTY_DENIED = YES`). Un gemelo auténtico mutado por debajo de frozen es
rechazado por el sello (`RUN_REFUSED = YES`). La capability original sigue
operativa (liveness). `REPLACEMENT_TO_WIDER_AUTHORITY = IMPOSSIBLE`.

### R2-4 en detalle (trust root)

Veredictos forjados contra el registro real: label estilo R1 con path →
`MALFORMED_ZONE_LABEL`; zone inexistente → `UNBOUND_ZONE_ID`; capability
equivocada → `NO_ZONE_FOR_CAPABILITY`; path como zone_id →
`MALFORMED_ZONE_LABEL`; labels vacíos → `NO_ZONE_LABELS`. Inserción en el
registro y `setattr` sobre una Zone → rechazados (registro inmutable). El
grant emitido deriva exclusivamente del registro (`MOUNT_SCOPE ==
guest_root`, `HOST_PATH == host_root` de la zona nombrada).

## Adjudicación

```text
GRANT_IMMUTABLE_AFTER_CREATION          = ENFORCED
MOUNT_DERIVED_ONLY_FROM_VALIDATED_GRANT = SUPPORTED
NO_ALTERNATE_MOUNT_INJECTION            = SUPPORTED
POLICY_SCOPE_BOUND_TO_GRANT_SCOPE       = SUPPORTED
CAPABILITY_SCOPE_NEVER_BROADER_THAN_POLICY_SCOPE = SUPPORTED
A2_MOUNT_INJECTION    = CLOSED
A3_POST_GRANT_MUTATION = CLOSED
A4_E2_REPLAY          = SUSTAINED
A9_RESULT_LABEL_SCOPE_TRUST = CLOSED
A11/A12_NO_VERDICT_NO_CAPABILITY = PASS
A13_REENTRANCY        = NO_REEVALUATION (limitación documentada, efecto confinado)
HIGH1_CAPABILITY_LAUNDERING = RESOLVED (sostenido con grants sellados)
FORBIDDEN_PHYSICAL_WRITES   = 0
GLOBAL_VERDICT        = PASS
```

## Limitaciones que permanecen (explícitas, no negociables)

```text
INNER_OPERATION_REEVALUATED_BY_ACS = NO
TOCTOU_WINDOW_EXISTS = YES
ZoneRegistry is part of trust root
capability confinement != universal sandbox security
```

- Modelo de amenaza: consumidor hostil = cuerpo de la tool con el objeto
  capability en la mano. Un atacante con ejecución arbitraria en el proceso
  host está FUERA de alcance (podría escribir el FS directamente sin Monty).
- El sello HMAC usa clave de proceso privada de `capability.py`; no es
  criptografía persistente entre procesos, es binding estructural en-vivo.
- A13: las operaciones internas de una tool NO son reevaluadas por ACS
  (`INNER_OPERATION_REEVALUATED_BY_ACS = NO`); lo que cambia es que la
  capacidad de daño termina en el grant.
- TOCTOU: la ventana de sustitución de recursos EXISTE
  (`TOCTOU_WINDOW_EXISTS = YES`); queda contenida por el grant sellado +
  Monty. No se afirma su eliminación.
- NO se declara esta fase `formally verified`, `secure`,
  `production-ready` ni `complete mediation universal`. La revisión de si
  estas propiedades bastan corresponde al reviewer externo.
- 0 llamadas a modelo: el cierre es mecánico; sin LLM.

## Procedencia metodológica — prompt truncado

Las instrucciones originales recibidas por el agente para esta fase se
**truncaron después del enunciado del test R2-2**. Registrar:

> El agente implementó R2-3…R2-8 a partir de los findings previos y del
> objetivo de remediación, no de un prompt completo proporcionado por el
> Mediador.

Los tests R2-3..R2-8 y TOCTOU derivan directamente de los hallazgos de
`ANKLA-AGT-1E-R1-EXTERNAL` (A2, A4, A9, A11/A12, A13, E4) y del objetivo
declarado. Esto se conserva como provenance metodológica. No se oculta.

## ZoneRegistry — TRUST_ROOT_COMPONENT

```text
ZoneRegistry = TRUST_ROOT_COMPONENT
```

Lo que garantiza (observado y probado en R2-4/R2-5):

- mapping `zone_id → host/guest roots`, fijado por el HOST;
- registro pre-registrado antes de cualquier veredicto (construido una vez,
  inmutable después: `MappingProxyType` + `Zone` frozen, validado en
  registro);
- el registro NO se deriva de memoria (no proviene de AN-KLA ni de ningún
  estado recuperado: lo construye el host sobre fixtures físicas en
  /private/tmp);
- los paths NO provienen directamente de `result_labels` (la policy nombra
  identidades; el registro resuelve raíces);
- una zone desconocida falla closed (`UNBOUND_ZONE_ID` → sin capability, sin
  runtime).

Lo que NO se afirma: que el ZoneRegistry sea seguro frente a todos los
ataques posibles (host compromise, supply-chain del host, colusión de
registro). Esa adjudicación corresponde al reviewer externo.

## Contrato observado de GrantedCapability

```text
GrantedCapability
- no acepta mounts externos arbitrarios;
- queda ligada a capability + zone (binding auditable en identity);
- verifica integridad (sello) antes de materializar Monty;
- mutación post-grant invalida la ejecución.
```

Estrategia concreta implementada:

- `@dataclass(frozen=True)`;
- integridad transitiva (tuples, `MappingProxyType`; sin colecciones
  mutables internas);
- sello HMAC-SHA256 con clave de proceso privada del módulo `capability.py`,
  verificado en `__post_init__` y re-verificado en cada `run()`;
- `run()` revalida el sello ANTES de materializar mounts y no acepta
  parámetros de mounts/paths.

Alcance del sello: es una **protección de integridad dentro del modelo de
amenaza probado** (consumidor hostil con el objeto en la mano). NO se
presenta como autenticación externa, ni como criptografía persistente entre
procesos, ni como resistencia frente a un atacante con ejecución arbitraria
en el proceso host.

## Contadores

```text
MODEL_CALLS = 0
ANKLA_WRITES = 0  ANKLA_REVISION_CHANGED = NO (sha256:59be6c56… invariante)
AGT / ACS / OPA / MONTY / AN-KLA SOURCE_MODIFIED = NO
PHASE_1A..1E_R1_ARTIFACTS_MODIFIED = NO (sólo se añade playground/16 y este doc)
```
