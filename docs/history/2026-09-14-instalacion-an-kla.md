# Bitácora — 2026-09-14 · Instalación de AN-KLA Memory (EPI-AGTLAB-002)

Historia, no normativa. Registro de la integración de `an-kla-memory` como
memoria local de este lab, siguiendo la documentación canónica del proyecto
(`README.md` del repo `kristhianmanue1/an-kla-memory`).

## Qué se hizo

- Verificación previa: el paquete **no estaba** instalado en el venv del lab
  (`pip list` vacío, `import an_kla_memory` fallaba). El único vínculo
  existente era `epistates 0.1.0a2` (editable, `~/www/aria/epistates`), que lo
  menciona sólo en su documentación.
- Instalación fijada a la etiqueta exacta según la doc (no PyPI, no `main`):
  `uv pip install --python .venv/bin/python
  "an-kla-memory @ git+https://github.com/kristhianmanue1/an-kla-memory.git@v0.1.0-beta.28"`
  → `an-kla-memory==0.1.0b28` (commit `1e150b7`). Se usó `uv pip` porque este
  venv no tiene `pip`; el requirement es idéntico al de la doc.
- Secuencia de la doc ejecutada en la raíz del lab:
  1. `--version` → `0.1.0b28`.
  2. `init` → memoria local `.an-kla/` creada (attest, identity, memory,
     context); `context_diagnostics.installed: false` como esperado.
  3. `context plan --operation install` → plan `append` sobre `AGENTS.md`
     (plantilla `0.1.0-beta.26`).
  4. `context install` → bloque gestionado anexado a `AGENTS.md`; `AN-KLA.md`
     creado en la raíz.
  5. `context status` → `installed: true`, sin diagnósticos.
  6. `verify` → `ok: true`, memoria vacía (0 facts/events/episodes), identidad
     `complete`, perfil `posix-fsync-dir/v1`.

## Cambios en el repo

- `AGENTS.md`: bloque gestionado `an-kla:managed-begin/end` anexado (hash
  `sha256:a1478300…3e152`).
- `AN-KLA.md`: contrato de contexto nuevo (versión `0.1.0-beta.26`).
- `.an-kla/`: estado local — **no versionable**; añadido a `.gitignore`.
- `.gitignore`: sección nueva para `.an-kla/`.

## Notas

- La etiqueta instalada (`v0.1.0-beta.28`) difiere de la plantilla de contexto
  (`0.1.0-beta.26`): la doc lo declara explícito — la plantilla es un eje
  separado de la versión del paquete; `context status` distingue ambos.
- El repo sigue sin Git inicializado; al inicializarlo, `.gitignore` ya cubre
  `.env`, `.venv/` y `.an-kla/`.
