# Playground — ejemplos y ejercicios

Ejemplos **numerados e independientes**. Cada uno declara en su cabecera la
superficie de coste (llamadas GLM reales vs ejecución local).

```bash
# desde la raíz del lab, siempre con este intérprete:
.venv/bin/python playground/01_hello_agent.py
```

Requisitos comunes: `.env` con `ZAI_API_KEY` (plantilla: `.env.example`).
Ejecuta antes `scripts/check_environment.py`.

| Ejemplo | Coste | Qué demuestra |
|---|---|---|
| `01_hello_agent.py` | 1 llamada | agente mínimo, instrucciones, cliente Z.ai |
| `02_tools_memoria_stream.py` | 3 llamadas | tools, memoria de sesión, streaming |
| `03_structured_output.py` | 1 llamada | salida tipada (`response_format` + pydantic) |
| `04_workflow.py` | **0 llamadas** | workflow determinista (executors puros) |
| `05_devui/` | 0 hasta que ejecutes | servidor DevUI en loopback |
| `06_epistates_spike.py` | 1 llamada (sólo si la tarjeta es válida) | ejecutor in-process bajo disciplina epistates (prototipo) |
| `07_acs_smoke/` | **0 llamadas** | decisiones locales de ACS (allow/deny deterministas, fail-closed); sin ejecutar tools |
| `08_ankla_acs_phase1a/` | 10 corridas (3 pases) | AN-KLA × ACS: memoria non-authoritative, DENY E2E, enforcement del host |
| `09_ankla_approval_1b/` | 3 corridas + suite sintética 0-coste | AN-KLA × approvals: memoria ≠ approval, binding por sesión/tool/args |

`ejercicios.md` — retos por dificultad, sin solución. La salida de un modelo
**no es verdad**: valida contra código y estado real.
