# Instalación local — facts de esta máquina (macOS)

**Fecha de verificación:** 2026-09-14 (re-verifica base 2026-09-11).
**Método:** comandos ejecutados contra
el `.venv/` de esta carpeta; cada línea declara su veredicto
`[pass|fail|inconclusive]`. Un fact datado no es vigencia perpetua: re-verifica
con `scripts/check_environment.py` y `inspect` si vas a confiar en él.

## Intérprete y gestor

- `.venv/bin/python` → Python 3.12.12 [pass]
- venv creado y gestionado con **uv** 0.9.27 (Homebrew); el venv **no tiene
  `pip`** [pass]
- congelado del entorno: `requirements-frozen.txt` (222 distribuciones tras
  instalar AGT+ACS el 2026-09-14; era 205) [pass]

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

## Governance: AGT + ACS (instalados 2026-09-14)

- `agent-governance-toolkit==4.1.0` (metapaquete, Public Preview) con
  `-core/-cli/-integrations/-protocols` 4.1.0 [pass]
- combinación coherente publicada: meta 4.1.0 fija core `<5.0` — el core
  5.0.0 de PyPI NO es la combinación del metapaquete vigente [pass]
- entry points nuevos: `agt`, `agent-governance`, `agent-os` (emite
  DeprecationWarning: usar `agent-governance-toolkit-core`), `agentmesh`,
  `hypervisor`, `mcp-scan`, `agent-sre` [pass]
- `agent-control-specification==0.3.1b1` (Alpha, owner PyPI microsoft)
  [pass]
- ACS en macOS arm64: sin wheel → compilado desde source con maturin/Rust
  (rustc/cargo 1.93.1 Homebrew ya presentes; no se instaló toolchain):
  build PASS 4m00s, `_native.abi3.so` Mach-O arm64 [pass]
- imports verificados sin modelos: `agent_framework`, `agent_os`,
  `agentmesh`, `agent_control_specification` [pass]
- nota API: `agent_os.kernel` (README de consolidación) corresponde a core
  5.0.0; en el 4.1.0 instalado el kernel es `agent_os.StatelessKernel`
  top-level [pass]
- smoke determinista sin GLM (`playground/07_acs_smoke/`): read_file →
  allow, delete_protected_file → deny, tool no declarada → deny
  fail-closed (`runtime_error:tool_unknown`); `ACS_POLICY_ENGINE =
  FUNCTIONAL`, `HOST_ENFORCEMENT = NOT_YET_TESTED` [pass]
- limitación: el dispatcher default de Rego del core nativo requiere un
  binario `opa` EXTERNO (no instalado); la ruta local verificada usa el
  `policy_dispatcher` del host [pass, con reserva]
- downgrade aceptado: `cryptography 50.0.1 → 48.0.1` (pin de core
  `<50.0,>=46.0.7`); seguro para dependencias activas; conflicto latente
  si alguien activa `openai-agents[encrypt]` (exige `<46`) [pass, datado]

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
