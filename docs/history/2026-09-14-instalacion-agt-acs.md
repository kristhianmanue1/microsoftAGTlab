# Bitácora — 2026-09-14 · Instalación AGT + ACS (preparación Fase 1)

Historia, no normativa. Registro de la instalación del **Agent Governance
Toolkit** (`agent-governance-toolkit==4.1.0`) y del **Agent Control
Specification** (`agent-control-specification==0.3.1b1`) en el `.venv` del
lab, con smoke local de decisiones ACS. Objetivo: preparar pruebas
`AN-KLA × Microsoft AGT / ACS`. No se ejecutaron pruebas conductuales con GLM.

## Fuentes upstream (oficiales, PyPI)

- `agent-governance-toolkit` 4.1.0 (2026-06-11, Public Preview, MIT) — owner
  PyPI `microsoft`; autor declarado "Microsoft Corporation". Metapaquete que
  instala core/cli/integrations/protocols 4.1.0. El core 4.x consolida cinco
  distribuciones previas (`agent-os-kernel`, `agentmesh-primitives`,
  `agentmesh-runtime`, `agent-hypervisor`, `agentmesh-platform`); los nombres
  viejos quedan como redirects deprecated (el entry point `agent-os` emite
  DeprecationWarning apuntando a `agent-governance-toolkit-core`).
- `agent-governance-toolkit-core` 5.0.0 existe en PyPI (2026-08-03) pero el
  metapaquete 4.1.0 lo fija a `<5.0`: la combinación coherente publicada es
  4.1.0 + core 4.1.0. El README de ACS indica que ACS es la "policy layer"
  de AGT 5.0 (meta 5.0 aún no publicado).
- `agent-control-specification` 0.3.1b1 (2026-08-03, Alpha, MIT) — owner PyPI
  `microsoft`. Runtime Rust + superficie Python fina (PyO3/maturin).
  Compatibilidad: `requires_python >=3.11` (Python 3.12 OK).
- Rust: NO se instaló toolchain nuevo. rustc/cargo 1.93.1 (Homebrew, stable)
  ya presentes; `rustup` no está instalado. Rust se usó como dependencia de
  build de ACS: `Rust = build dependency of ACS on this platform`, no de AN-KLA.

## Comandos ejecutados

```bash
uv pip install --python .venv/bin/python "agent-governance-toolkit[full]==4.1.0"
uv pip install --python .venv/bin/python "agent-control-specification==0.3.1b1"
```

- `--dry-run` previo de AGT[full]: 15 ADDED, 1 DOWNGRADE, sin tocar
  `agent-framework==1.18.0`, `openai`, `pydantic`.
- ACS en macOS arm64: sin wheel (sólo manylinux x86_64 + sdist) → build
  local desde source con maturin/Rust: **PASS en 4m00s**
  (`_native.abi3.so` Mach-O arm64, ~7 MB). `ACS_BUILT_FROM_SOURCE = YES`.

## Resolución de dependencias (freeze 207 → 222)

- ADDED (15): agent-governance-toolkit{,-core,-cli,-integrations,-protocols}
  4.1.0, agent-control-specification 0.3.1b1, croniter 6.2.4, dnspython 2.8.0,
  email-validator 2.3.0, markdown-it-py 4.2.0, mdurl 0.1.2, pygments 2.21.0,
  pynacl 1.6.2, rich 15.0.0, structlog 26.1.0.
- DOWNGRADED (1): `cryptography 50.0.1 → 48.0.1` — impuesto por el pin de
  core (`cryptography<50.0,>=46.0.7`). Seguro para las dependencias activas
  (msal, google-auth, azure-identity, an-kla-memory[sealed] lo aceptan).
  Latente: `openai-agents[encrypt]` exige `<46` y chocaría con ese pin si
  alguien activa ese extra.
- REMOVED/UPGRADED: ninguno. `agent-framework==1.18.0` intacto.

## Superficie verificada (imports y CLI, sin llamadas a modelos)

- entry points nuevos: `agt`, `agent-governance`, `agent-compliance`,
  `agent-os` (deprecated redirect), `agentmesh`, `hypervisor`, `mcp-scan`,
  `agent-sre`, `openshell-agentmesh`.
- imports OK: `agent_framework` (1.18.0), `agent_control_specification`,
  `agent_os` (StatelessKernel top-level; el path `agent_os.kernel` del README
  corresponde a core 5.0.0, NO al 4.1.0 instalado), `agentmesh`.
- `agent-framework-hyperlight` sigue ausente; `agt --help` operativo.

## Smoke ACS (playground/07_acs_smoke, 0 llamadas GLM)

- Manifest mínimo oficial validado contra el parser Rust
  (`agent_control_specification_version: "0.3.1-beta"`, policies rego,
  tools declaradas, `pre_tool_call` con `policy_target: $.tool_call`).
- Resultado determinista sin ejecutar tools:
  `read_file → allow`; `delete_protected_file → deny`; tool no declarada →
  deny fail-closed (`runtime_error:tool_unknown`).
- `ACS_POLICY_ENGINE = FUNCTIONAL` · `HOST_ENFORCEMENT = NOT_YET_TESTED`.
- Hallazgo de plataforma: el dispatcher default de Rego del core nativo
  ejecuta un binario `opa` EXTERNO (`ACS_OPA_PATH`/PATH) que no está
  instalado → `policy_invocation_failed` fail-closed. El smoke usa el
  `policy_dispatcher` del host (API oficial del SDK), decisión 100% local.
  Instalar OPA requeriría autorización nueva.

## AN-KLA y gate

- `verify` PASS antes y después; revisión sin cambios:
  `sha256:944ed25c…8339f7` (rev 4). Store intacto, sin escrituras.
- `check_environment.py` exit 0 antes, entre instalaciones y al cierre.

## Corrección colateral (declaración Git stale)

- `AGENTS.md` y `project-manifest.yaml` decían "sin Git inicializado";
  el repo está versionado en GitHub desde 2026-09-14 (ver
  `2026-09-14-primera-subida.md`). Se actualizó la frase en ambos; no se
  tocó el bloque gestionado AN-KLA ni se mezcló con claims de governance.

## Limitaciones

- ACS 0.3.1b1 es Alpha y AGT 4.1.0 Public Preview: APIs pueden cambiar.
- Sin binario `opa`: la ruta Rego del dispatcher default no es ejecutable
  aquí; sólo policy_dispatcher del host o `type: test/custom`.
- AGT core 4.1.0 ≠ docs de consolidación basadas en 5.0.0 (paths de import
  difieren: `agent_os.kernel` no existe en 4.1.0).
- El downgrade de cryptography deja un conflicto latente con
  `openai-agents[encrypt]`.
