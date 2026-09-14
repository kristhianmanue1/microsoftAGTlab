# Bitácora — 2026-09-14 · Primera subida a GitHub (EPI-AGTLAB-003)

Historia, no normativa. Registro de la inicialización de Git y la primera
publicación del lab en `https://github.com/kristhianmanue1/microsoftAGTlab`
(público, rama `main`).

## Qué se hizo

- El remoto existía con un commit inicial (`6adabe3`, sólo `LICENSE`). Se
  incorporó con `git init -b main` → `fetch` → `reset --hard origin/main`
  (los archivos locales estaban sin trackear y no se tocaron), preservando
  historial lineal sin force-push.
- `.gitignore`: añadido `.DS_Store`. Ya cubría `.env`, `.venv/`, `__pycache__`
  y `.an-kla/` (memoria local, no versionable).
- Control anti-fuga antes del commit: `git ls-files` sin `.env`, `.venv/`,
  `.an-kla/` ni `.DS_Store`; grep `sk-` revisado a mano — dos coincidencias,
  ambas falsos positivos (`task-card`). `.env.example` verificado: sólo
  placeholder.
- Contenido del primer commit: contrato (AGENTS.md, AN-KLA.md,
  project-manifest.yaml), docs vigentes e históricos, playground completo
  (01–06 + ejercicios), gate, pyproject/requirements-frozen, LICENSE remoto.

## Cambios colaterales

- `project-manifest.yaml`: retirado de `pospuesto` el ítem de inicializar Git.
- `AGENTS.md`: se deja intacto (línea "Sin Git inicializado" queda como
  instrucción condicional histórica); no se toca el bloque gestionado AN-KLA.

## Notas

- `playground/06_epistates_spike.py` referencia una ruta absoluta local
  (`/Users/krisnova/www/aria/epistates/...`): no es secreto, pero el spike
  fallará cerrado en otras máquinas — aceptable para un prototipo declarado.
- Memoria AN-KLA: el fact `lab-map-20260914` decía "sin Git inicializado";
  tras la subida se emite `supersede` con el estado actualizado.
