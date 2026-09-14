# 10 — Monty Execution Boundary (Fase 1C)

Fase 1C del programa AN-KLA × Microsoft Agent Framework: evaluación
experimental de la frontera real de ejecución de Monty (`pydantic-monty`
0.0.23) como superficie de ejecución restringida para agentes.

Hipótesis H1C:

```text
agent intent != effective execution capability
authorization != execution capability
policy allow != filesystem access
model request != physical access
```

## Contenido

| Ruta | Qué es |
|---|---|
| `mechanical_suite.py` | Suite mecánica C1-C10 + test de código controlado (sección 8) + C0 de compatibilidad del bridge. **0 tokens, sin LLM.** |
| `glm_probe.py` | Prueba conductual C11/C12 con GLM 5.3 Flash. Máximo 2 corridas de agente. |
| `fixtures/` | Fixtures estáticas fuente (readonly/, readwrite/, outside/). Nunca se modifican: la suite y el probe copian a `/private/tmp`. |
| `evidence/` | Evidencia JSON por corrida (mounts, código, stdout, errores, digests antes/después). Sin secretos. |

## Uso

```bash
# 1. Suite mecánica (obligatoria primero; 0 tokens)
.venv/bin/python playground/10_monty_execution_boundary/mechanical_suite.py

# 2. Prueba conductual (gasta tokens reales; máx 2 corridas)
.venv/bin/python playground/10_monty_execution_boundary/glm_probe.py
```

## Hallazgos de API (inspección directa, sin docs externas)

```text
MONTY_VERSION = pydantic-monty 0.0.23 (+ pydantic-monty-client/runtime 0.0.23, binario .venv/bin/monty)
AGENT_FRAMEWORK_MONTY_VERSION = agent-framework-monty 1.0.0b260730
BRIDGE_COMPAT = INCOMPATIBLE
```

- `agent-framework-monty` (bridge `InlineCodeBridge`) usa la API antigua
  `Monty(code, script_name=...).start(...)`; en 0.0.23 `Monty` es un
  **worker-pool de subprocessos**: `with Monty() as pool:` →
  `pool.checkout(script_name=..., limits=...)` → `session.feed_run(code, mount=[...], print_callback=...)`.
  La tool oficial `MontyExecuteCodeTool` falla con
  `TypeError: Monty.__new__() takes 0 positional arguments` (caso C0 de la suite).
- La frontera de filesystem se declara con `pydantic_monty.MountDir(
  virtual_path, host_path, mode='overlay'|'read-only'|'read-write',
  write_bytes_limit=None, memory_usage_limit=100MB)`.
- Superficie OS restringida: `os.walk`, `os.listdir`, `os.getenv`,
  `os.environ` no están soportados (`RuntimeError`/`AttributeError`);
  `open()` y `pathlib.Path` operan sólo a través de mounts.
- `ResourceLimits`: `max_duration_secs`, `max_memory`, `gc_interval`,
  `max_recursion_depth`, `max_suspensions`.

## Resultados (corrida 2026-09-14)

Suite mecánica: **11/11 PASS**. Conductual: **C11 PASS, C12 PASS**.
Detalle completo en `evidence/` y en
`docs/history/2026-09-14-fase-1c-monty-execution-boundary.md`.

Declaración observada (no más que eso):

```text
MONTY = restricted interpreter (subprocess workers) with tested filesystem boundaries
```

No probado (y por tanto no declarado): aislamiento kernel, micro-VM,
side channels, escapes por extensión nativa, syscalls arbitrarios,
imports hostiles, agotamiento general de recursos.
