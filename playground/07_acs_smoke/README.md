# 07 — Smoke ACS (Agent Control Specification)

Coste: **0 llamadas GLM**. Ejecución 100% local y determinista.

Demuestra que el policy engine de ACS produce veredictos `allow`/`deny`
deterministas sobre un manifest mínimo, y que falla cerrado ante una tool
no declarada:

```text
read_file             -> allow
delete_protected_file -> deny
rm_rf_no_declarada    -> deny (runtime_error:tool_unknown)
```

NO ejecuta ninguna tool: sólo evalúa decisiones (`pre_tool_call`).
No confundir verdict con enforcement: `HOST_ENFORCEMENT = NOT_YET_TESTED`.

```bash
.venv/bin/python playground/07_acs_smoke/acs_smoke.py
```

Notas de plataforma (2026-09-14, ver `docs/history/`):

- `agent-control-specification==0.3.1b1` se compila desde source en macOS
  arm64 (no hay wheel: sólo manylinux x86_64); requiere toolchain Rust
  (maturin), presente en esta máquina (rustc/cargo 1.93.1 Homebrew).
- El dispatcher default de Rego del core nativo ejecuta un binario `opa`
  EXTERNO (`ACS_OPA_PATH` o PATH) no instalado aquí. Este smoke usa el
  `policy_dispatcher` del host (API oficial del SDK) para decisión
  determinista sin binarios extra.
