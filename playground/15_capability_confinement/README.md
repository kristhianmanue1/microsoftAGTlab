# Fase 1E-R1 — Capability Confinement

**Fase:** ANKLA-AGT-1E-R1 · **Fecha:** 2026-09-15 · **Base:** HEAD
`1ebd1d1` · **Coste:** 0 llamadas a modelo (suite 100% mecánica) · **AN-KLA:
0 escrituras** (revisión `sha256:59be6c56…` invariante antes/después).

Remediación del finding HIGH de Fase 1E (ver
`playground/14_adversarial_hardening/`, que permanece intacto):

```text
E2_CAPABILITY_LAUNDERING = REPRODUCED
E5_REENTRANCY = INNER_NEW_DECISION = NO
```

## Hipótesis H1E-R1

> Si la capability efectiva entregada a una tool se atenúa al mismo scope
> autorizado por policy, el cuerpo de la tool no puede ejercer una capability
> más amplia aunque intente hacerlo internamente.

Propiedad under test:

```text
policy scope >= granted capability scope >= effective operation scope
```

## Qué cambió (capability delivery, nada más)

Antes (1E): OPA permite `/workspace/allowed/**` pero el host montaba
`/workspace/` completo en RW → el cuerpo de una tool permitida escribía en
`/workspace/quarantine/` sin que ninguna capa lo evaluara ni lo impidiera.

Después (1E-R1): el veredicto ALLOW de la policy transporta el scope
autorizado en `result_labels` (`scope:filesystem.write:/workspace/allowed`) y
la **capability factory** deriva de ahí los mounts efectivos:

```text
OPA allows /workspace/allowed/**
    ↓ result_labels (scope autorizado)
capability_factory  — atenuación + verificación MOUNT_SCOPE ⊆ POLICY_SCOPE
    ↓
Monty gets:  /workspace/allowed/ = RW
             /workspace/quarantine/   NOT MOUNTED
```

El cuerpo de la tool no recibe el workspace: recibe sólo el objeto
`GrantedCapability`, que es su único camino a Monty y no acepta mounts
externos. Sin allow no hay capability; sin capability no hay runtime; sin
runtime no hay efecto.

## Ficheros

| Fichero | Papel |
|---|---|
| `capability_factory.py` | fábrica experimental: verdict → scope → mounts, fail-closed |
| `host.py` | cadena ACS → factory → cuerpo → Monty; workspace y tools |
| `mechanical_suite.py` | tests R1-A..R1-J + TOCTOU + informe y evidencia |
| `policy/filesystem.rego` | policy Rego v1 (default deny, canonicalización, scope en labels) |
| `manifest.yaml` | manifest ACS (sin policy_dispatcher: OPA bundled) |
| `fixtures/` | allowed / quarantine / outside (copiadas a /private/tmp) |
| `evidence/` | JSON de cada corrida + audit log independiente |

## Ejecución

```bash
.venv/bin/python playground/15_capability_confinement/mechanical_suite.py
```

## Resultados (corridas 2026-09-15, reproducibles)

| Test | Escenario | Resultado |
|---|---|---|
| R1-A | control positivo: allow + escritura permitida | PASS |
| R1-B | **réplica exacta de E2** (laundering interno) | **CONTAINED** |
| R1-C | helper interno sin ACS/OPA | ATTEMPTED_BUT_CONTAINED |
| R1-D | sibling `/workspace/allowed2` | DENIED_NOT_MOUNTED |
| R1-E | traversal `../quarantine`, root escape | DENIED |
| R1-F | symlinks controlados dentro de allowed | DENIED |
| R1-G | mount pedido más amplio que el scope | FACTORY_DENY |
| R1-H | policy DENY ⇒ capability | PASS (no capability, no runtime) |
| R1-I | approval PENDING/DENIED ⇒ capability | PASS |
| R1-J | reentrancy (E5) re-adjudicada | LIMITATION_PERSISTS_EFFECT_CONFINED |
| TOCTOU | ventana decisión→ejecución bajo scope atenuado | WINDOW_CONTAINED |

R1-B en detalle (las siete condiciones del finding HIGH, todas contenidas):

```text
OUTER_TOOL = ALLOWED · BODY_ENTERED = YES · ALLOWED_WRITE = YES
FORBIDDEN_INTERNAL_WRITE_ATTEMPTED = YES · FORBIDDEN_INTERNAL_WRITE = NO
MONTY_DENIAL = YES · QUARANTINE_DIGEST_UNCHANGED = YES
INNER_NEW_POLICY_DECISION = NO
```

Tabla policy ↔ capability:

| Policy scope | Capability scope | Operation | Result |
|---|---|---|---|
| allowed | allowed | allowed path | allow |
| allowed | allowed | quarantine | deny |
| allowed | parent (`/workspace/`) | any | capability grant deny |
| deny | none | any | not reached |

## Adjudicación

```text
CAPABILITY_SCOPE_NEVER_BROADER_THAN_POLICY_SCOPE = SUPPORTED
CAPABILITY_LAUNDERING       = ATTEMPTED_BUT_CONTAINED
HIGH1_CAPABILITY_LAUNDERING = RESOLVED
FORBIDDEN_PHYSICAL_WRITES   = 0
GLOBAL_VERDICT              = PASS
```

Claim nuevo (deliberadamente acotado):

> A tool may perform unevaluated internal operations, but those operations
> cannot exceed the capabilities explicitly granted to its execution
> environment.

NO se afirma `all internal tool operations are governed`: seguiría siendo
falso (R1-J: `INNER_OPERATION_REEVALUATED_BY_ACS = NO` persiste). La ventana
TOCTOU tampoco desapareció: quedó **contenida** por la capa de capability.

## Hallazgo para EKTEL (sin modificar EKTEL)

```text
CAPABILITY_ATTENUATION_REQUIRED = YES
```

Definición provisional: el runtime debe poder derivar una capability más
estrecha a partir de una autorización y entregarla a una ejecución sin
permitir que el consumidor la amplíe.

## Límites

- La factory exige binding exacto scope→zona (`zone_registry`) y labels de
  scope bien formados; cualquier desviación es fail-closed (sin capability).
- El canal del scope es `result_labels` del veredicto ACS — verificado que
  sobrevive el pipeline completo (ver evidencia `ACS_RESULT_LABELS`).
- No se probó con modelos reales (0 llamadas); el finding se cierra sin LLM.
