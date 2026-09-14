# microsoftAGTlab

Laboratorio local del **Microsoft Agent Framework** (`agent-framework`) conectado
a **Z.ai GLM** mediante el cliente OpenAI-compatible. Es el **hub de contexto**
para que un agente de IA use este framework en esta máquina.

**Punto de entrada para agentes:** [`AGENTS.md`](AGENTS.md)

```bash
# 1) comprobar el entorno (no gasta tokens)
.venv/bin/python scripts/check_environment.py

# 2) primer ejemplo (gasta tokens: una llamada GLM)
.venv/bin/python playground/01_hello_agent.py
```

- `docs/instalacion-local.md` — qué hay instalado aquí, con evidencia por línea.
- `docs/guia-rapida.md` — recetas ejecutadas localmente, fechadas.
- `playground/` — ejemplos numerados y ejercicios.
- `project-manifest.yaml` — declaración al ecosistema (schema `pinax/project-manifest/v1`).

El `.env` (con `ZAI_API_KEY` real) **no se versiona jamás**; la plantilla es
`.env.example`.
