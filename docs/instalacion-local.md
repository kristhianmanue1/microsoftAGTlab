# Instalación local — facts de esta máquina (macOS)

**Fecha de verificación:** 2026-09-11. **Método:** comandos ejecutados contra
el `.venv/` de esta carpeta; cada línea declara su veredicto
`[pass|fail|inconclusive]`. Un fact datado no es vigencia perpetua: re-verifica
con `scripts/check_environment.py` y `inspect` si vas a confiar en él.

## Intérprete y gestor

- `.venv/bin/python` → Python 3.12.12 [pass]
- venv creado y gestionado con **uv** 0.9.27 (Homebrew); el venv **no tiene
  `pip`** [pass]
- congelado del entorno: `requirements-frozen.txt` (205 distribuciones,
  generado por `importlib.metadata`) [pass]

## Microsoft Agent Framework

- `agent-framework==1.18.0` (metapaquete) [pass]
- `agent-framework-core==1.18.0` — estable, coincide con la más reciente de
  PyPI a la fecha [pass]
- proveedores estables con **skew deliberado** de versiones:
  `openai 1.14.3`, `orchestrations 1.1.1`, `ag-ui 1.3.0`,
  `declarative 1.0.4`, `foundry 1.13.0`, `github-copilot 2.0.0` [pass]
- paquetes beta/alpha del framework: **22** (hornada `1.0.0b260910`:
  a2a, anthropic, azure-*, bedrock, chatkit, claude, copilotstudio, devui,
  gemini, mem0, mistral, ollama, redis, purview, tools…) [pass]

## Superficie instalada relevante para agentes

- entry points: `devui` (Developer UI), `mcp`, `a2a-db` [pass]
- subpaquetes importables: `_workflows` (Workflow, WorkflowBuilder, Executor,
  AgentExecutor…), `orchestrations`, `devui` (serve/DevServer), `tools`,
  `mem0`, `ollama`, `azure`, `gemini`, `github`, `foundry`, `lab`, `monty`
  [pass]
- vecinos útiles ya instalados: `mcp==1.30.0`, `a2a-sdk==1.1.2`,
  `claude-agent-sdk==0.2.152`, `openai-agents==0.22.2`, `openai==3.13.0`,
  `pydantic-monty` (runtime sandboxed para tools de código) [pass]

## Proveedor de modelos (Z.ai GLM)

- endpoint observado en `.env`: `https://api.z.ai/api/coding/paas/v4/`
  [pass]
- `.env.example` (plantilla) declara el endpoint general
  `https://api.z.ai/api/paas/v4/` — **difieren**: el `.env` real apunta al
  endpoint *coding* [inconclusive: decisión de configuración del mantenedor;
  ambos operan con los ejemplos del playground]
- modelo en uso: `glm-5.3-flash` [pass]
- `ZAI_API_KEY`: presente, valor nunca impreso ni registrado [pass]

## Compatibilidad observada GLM ↔ framework (fechada, puede cambiar)

- tools, sesiones y streaming: operativos [pass]
- `response_format` estricto: NO garantizado — GLM puede envolver JSON en
  fences, añadir prosa y renombrar campos; el framework `.value` explota
  fail-closed. Patrón tolerante requerido (`docs/guia-rapida.md` §3) [pass
  con patrón local]

## Cómo re-verificar todo esto

```bash
.venv/bin/python scripts/check_environment.py
.venv/bin/python -c "import agent_framework as af; print(af.__version__ if hasattr(af,'__version__') else 'sin attr')"
uv pip list --python .venv/bin/python
```
