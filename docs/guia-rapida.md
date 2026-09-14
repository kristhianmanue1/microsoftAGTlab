# Guía rápida — recetas ejecutadas en esta máquina

> **Regla de esta guía:** sólo entra aquí lo que se ejecutó localmente, con
> fecha y evidencia. Lo general/normativo vive en la documentación oficial del
> framework. Si algo aquí contradice al paquete instalado, gana el paquete:
> `inspect.signature` y `dir()` son la referencia, no esta guía.

Entorno de las recetas: Python 3.12.12, `agent-framework-core==1.18.0`,
proveedores con skew (ver `instalacion-local.md`), endpoint Z.ai del `.env`.

## 1. Cliente + agente mínimo

```python
from agent_framework import Agent
from agent_framework.openai import OpenAIChatCompletionClient

agent = Agent(
    client=OpenAIChatCompletionClient(model=..., api_key=..., base_url=...),
    name="...", instructions="...",
)
resultado = await agent.run("...")   # resultado.text
```

Evidencia: `playground/01_hello_agent.py` exit 0, 2026-09-11 [pass].

## 2. Tools y memoria de sesión

- `@tool` sobre funciones con type hints + docstring (el docstring es lo que
  ve el modelo).
- `session = agent.create_session()`; pasa `session=` en cada `run()` para
  continuidad multi-turno. Sin sesión, cada `run` es amnésico.
- Streaming: `async for update in agent.run(..., stream=True, session=session)`.

Evidencia: `playground/02_tools_memoria_stream.py` exit 0 (3/3 partes),
2026-09-11 [pass]. Residuo: la limpieza del stream HTTP puede imprimir un
traceback de `httpcore2` en el cierre de `asyncio.run` — intermitente, no
afecta el resultado (2/3 corridas limpias) [inconclusive: causa en el
transporte instalado, no en el código del lab].

## 3. Salida estructurada (patrón local obligatorio)

GLM por este endpoint **no** garantiza JSON crudo: puede envolverlo en fences
y añadir prosa, y usar nombres de campo propios aunque le des un schema
pydantic. El framework `.value` es fail-closed y explota con
`ValidationError`. Patrón que sí funciona:

1. `options=ChatOptions(response_format=MensajeModelo)` (o igual da, ver hallazgo);
2. instrucciones con las claves JSON **literales**;
3. extraer JSON tolerante (fences/prosa) desde `.text`;
4. validar SIEMPRE con `Modelo.model_validate_json` y fallar cerrado.

Evidencia: `playground/03_structured_output.py` exit 0 tras dos hallazgos
(fences + campos renombrados por el modelo), 2026-09-11 [pass].

## 4. Workflows sin LLM (coste cero)

```python
from agent_framework import WorkflowBuilder, WorkflowContext, executor

@executor
async def paso_a(entrada: str, ctx: WorkflowContext[str]) -> None:
    await ctx.send_message(entrada.upper())   # hacia el siguiente executor

@executor
async def paso_b(entrada: str, ctx: WorkflowContext[str]) -> None:
    await ctx.yield_output(entrada + "!")     # salida del workflow

wf = WorkflowBuilder(start_executor=paso_a).add_edge(paso_a, paso_b).build()
r = await wf.run("hola")
r.get_outputs()      # ['HOLA!']  ·  r.get_final_state()  # WorkflowRunState.IDLE
```

Nota verificada: el valor de retorno del executor NO se propaga; la
comunicación es explícita vía `ctx.send_message` / `ctx.yield_output`.
Evidencia: `playground/04_workflow.py` exit 0, 2026-09-11 [pass].

## 5. DevUI (servidor local, explícito)

```bash
.venv/bin/devui playground/05_devui --no-open     # loopback 127.0.0.1:8080
```

`--headless` para API sin UI. El módulo del agente NO inicia nada al
importarse. Evidencia: import y construcción del agente verificados sin
servidor, 2026-09-11 [pass]; arranque del servidor reservado a ejecución
humana explícita.

## 6. Ejecutor in-process bajo disciplina epistates (spike camino B)

Patrón verificado con la librería real de epistates (editable en este venv):

1. `validate_task_card(card)` ANTES de cualquier coste — falla cerrada con
   `ValidationError` ante tarjeta inválida (probado: sin autoridad, check
   desconocido, campo extra — los tres rechazados).
2. El agente corre en este proceso; el resultado es el retorno del `await`.
3. Evidencia portable: digests sha256 de tarjeta/prompt/salida, checks locales,
   `confirms: technical_run_only`. El artefacto `spike-evidence/v0` es
   PROTOTIPO del lab, no un contrato epistates.

Nota de API: `validate_task_card` no retorna la tarjeta (devuelve `None`);
levanta en inválido. Usa tu propio dict.

Evidencia: `playground/06_epistates_spike.py` exit 0, 2026-09-11 [pass];
tres ataques de tarjeta rechazados sin gastar tokens [pass].

## Descubrimiento de API sin red

```python
import inspect, agent_framework as af
inspect.signature(af.Agent.run)      # firma real instalada
[n for n in dir(af) if 'Workflow' in n]
```

Evidencia: usado para verificar todas las recetas de esta guía [pass].
