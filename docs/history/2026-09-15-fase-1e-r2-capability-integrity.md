# Fase 1E-R2 — Capability Integrity & Trust Binding (remediación de revisión externa)

- **Fecha:** 2026-09-15
- **Fase:** ANKLA-AGT-1E-R2
- **Base:** HEAD `fe739ade473b9fd66cf9be79567100da27eb0876` (post-1E-R1),
  gate PASS, `an_kla verify` PASS (revision `sha256:59be6c56…`,
  revision_number 17), worktree limpio, OPA 1.20.2
- **Veredicto global:** **PASS** — `A3_POST_GRANT_MUTATION = CLOSED`,
  `A2_MOUNT_INJECTION = CLOSED`, `A9_RESULT_LABEL_SCOPE_TRUST = CLOSED`

## Posición

Fase de remediación técnica y mecánica (`MODEL_CALLS = 0`). No es revisión
externa: cierra exclusivamente los findings abiertos por
`ANKLA-AGT-1E-R1-EXTERNAL` que la revisión reprodujo o sostuvo (A2, A3, A4,
A9, A11/A12, A13). Los findings NOT_REPRODUCED/DENIED/NO (A1, A5, A6, A7,
A8, A10) no se tocan. No se modifica 1E ni 1E-R1 ni ningún componente
(AN-KLA, AGT, ACS, OPA, pydantic-monty): el experimento vive íntegro en
`playground/16_capability_integrity/`.

## Findings objetivo (veredicto de la revisión)

```text
A2_MOUNT_INJECTION             = REPRODUCED
A3_POST_GRANT_MUTATION         = REPRODUCED   ← HIGH principal
A4_E2_REPLAY                   = SUSTAIN
A9_RESULT_LABEL_SCOPE_TRUST    = PARTIAL
A11/A12_NO_VERDICT_NO_CAPABILITY = SUSTAIN
A13_REENTRANCY                 = NO_REEVALUATION
```

El ataque reproducido por la revisión sobre el prototipo de 1E-R1:

```text
mount_before = /workspace/allowed RW
↓ mutate GrantedCapability (objeto mutable, run() relee atributos sin revalidar)
mount_after = /workspace RW
↓
write quarantine succeeds
```

## Preflight

```text
ENVIRONMENT_GATE = PASS (exit 0)
ANKLA_VERIFY     = PASS (ok:true, revision sha256:59be6c56…, revision_number 17)
WORKTREE         = CLEAN
HEAD             = fe739ade473b9fd66cf9be79567100da27eb0876
OPA_VERSION      = 1.20.2
```

## Diseño (tres remediaciones, ningún `if` nuevo en tools)

### R2-A — `GrantedCapability` inmutable y sellada

`@dataclass(frozen=True)` con inmutabilidad transitiva (tuples,
`MappingProxyType` en `identity`). `frozen=True` SOLO se demostró
insuficiente: `object.__setattr__` lo bypasea (vector probado). La
autenticidad real es un **sello HMAC-SHA256** sobre la identidad completa
del grant (capability_type, zone_id, scopes, host_path, mode, operation
paths, policy binding, timestamp) con clave de proceso privada:

- `__post_init__` verifica el sello: forjas y clones `dataclasses.replace`
  con campos ampliados no llegan a existir.
- `run()` RE-verifica el sello sobre los valores actuales antes de
  materializar mounts: el bypass de frozen invalida el grant y el runtime no
  arranca.
- Los mounts se materializan dentro de `run()` desde el grant verificado;
  no hay tabla cacheada sustituible ni override posterior.

### R2-B — un solo camino autorizado a Monty

```text
MONTY_RUNTIME_CREATION_PATHS   = 1  (GrantedCapability.run)
AUTHORIZED_PATHS               = 1
UNAUTHORIZED_ALTERNATIVE_PATHS = 0
```

La factory ya no acepta `requested_mount` (eliminado de la firma) y
`run(code, *, label="")` no tiene kwargs de mounts/paths; `host.py` no
importa `pydantic_monty`. Inyección por kwargs ⇒ `TypeError` sin runtime.

### R2-C — binding policy → zone (trust root explícita)

A9: R1 validaba `mount ⊆ label` pero los labels no demostraban ser el scope
realmente autorizado. En R2 la policy ya no transporta paths: nombra una
identidad lógica (`zone:<capability>:<zone_id>`). El `ZoneRegistry`
pre-registrado por el HOST (inmutable: `MappingProxyType` + `Zone` frozen,
validado en registro) es la raíz de confianza que resuelve
identidad → capability/guest_root/host_root. La factory verifica la
operación contra la zona y emite el grant sellado. Regla resultante:

```text
OPA chooses authorized logical zone
↓ trusted registry resolves zone
↓ factory verifies requested operation against zone
↓ immutable capability emitted
```

La policy no puede fabricar host_path ni mount path; sólo seleccionar una
identidad conocida.

## Resultados (dos corridas 2026-09-15, reproducibles)

```text
R2_A_POSITIVE_CONTROL               = PASS
R2_1_POST_GRANT_MUTATION            = CLOSED
R2_2_OBJECT_REPLACEMENT             = CLOSED
R2_3_MOUNT_INJECTION                = CLOSED
R2_4_TRUST_ROOT_ZONE_BINDING        = CLOSED
R2_5_POLICY_SCOPE_BOUND_TO_GRANT_SCOPE = SUPPORTED
R2_6_E2_REPLAY                      = SUSTAINED
R2_7_NO_VERDICT_NO_CAPABILITY       = PASS
R2_8_REENTRANCY                     = LIMITATION_PERSISTS_EFFECT_CONFINED
TOCTOU_WINDOW_EXISTS                = YES
TOCTOU_CONTAINED_BY_CAPABILITY      = YES
```

Detalles decisivos:

- R2-1 (réplica del ataque A3): los ocho vectores por interfaz pública son
  rechazados (`FrozenInstanceError`/`AttributeError`); el bypass
  `object.__setattr__` SÍ muta el objeto (frozen no es la defensa) pero
  invalida el sello: `ESCALATION_RUNTIME_STARTED = NO`,
  `refused_by = GrantVerificationFailed`. `dataclasses.replace`, forja desde
  cero y kwargs de mounts: rechazados. Quarantine idéntico por digest; un
  solo runtime (la escritura declarada).
- R2-2: gemelos hostiles no pueden existir (sello en construcción);
  `copy.copy` produce un gemelo de autoridad idéntica cuya escalación
  alcanza a Monty y es denegada; el gemelo mutado por debajo de frozen es
  rechazado por el sello; la capability original conserva liveness.
- R2-4: labels estilo R1 con path, zonas inexistentes, capabilities
  equivocadas y paths como zone_id → fail-closed; registro y zonas
  inmutables; el grant deriva exclusivamente de los valores del registro.

## Propiedades y adjudicación

```text
GRANT_IMMUTABLE_AFTER_CREATION          = ENFORCED
MOUNT_DERIVED_ONLY_FROM_VALIDATED_GRANT = SUPPORTED
NO_ALTERNATE_MOUNT_INJECTION            = SUPPORTED
POLICY_SCOPE_BOUND_TO_GRANT_SCOPE       = SUPPORTED
CAPABILITY_SCOPE_NEVER_BROADER_THAN_POLICY_SCOPE = SUPPORTED
HIGH1_CAPABILITY_LAUNDERING = RESOLVED (sostenido con grants sellados)
FORBIDDEN_PHYSICAL_WRITES   = 0
GLOBAL_VERDICT              = PASS
```

## Límites

- Amenaza modelada: consumidor hostil con el objeto capability (cuerpo de
  tool). Ejecución arbitraria en el proceso host queda fuera de alcance.
- El sello es binding estructural en-vivo (clave de proceso), no
  criptografía persistente entre procesos.
- A13 persiste (sin reevaluación ACS de operaciones internas); el efecto
  sigue confinado al grant. TOCTOU: ventana contenida, no eliminada.

## Contadores

```text
MODEL_CALLS = 0
ANKLA_WRITES = 0  ANKLA_REVISION_CHANGED = NO (sha256:59be6c56… invariante)
AGT / ACS / OPA / MONTY / AN-KLA SOURCE_MODIFIED = NO
PHASE_1A..1E_R1_ARTIFACTS_MODIFIED = NO (sólo playground/16 y este doc)
```

## Evidencia

- `playground/16_capability_integrity/evidence/integrity_20260915T043939Z.json`
  y `integrity_20260915T044309Z.json` (+ `integrity_latest.json`): preflight
  (gate, HEAD, worktree, OPA, digests de fuentes), zone_registry, vectores
  de ataque con veredicto por vector, contadores por test, estados físicos
  antes/después e informe final.
- `playground/16_capability_integrity/evidence/audit_log.json`: auditoría
  independiente (decisiones ACS con labels `zone:`, verificaciones de
  binding, arranques y rechazos de runtime, observaciones de los cuerpos
  hostiles).
- No se registró ningún secreto.

## Detención

Fase 1E-R2 cerrada. No se avanza a nueva revisión externa, 1F, paper ni
cambios upstream. El siguiente paso natural será una revisión externa corta
que verifique si A2/A3/A9 quedaron realmente cerrados.
