# Bitácora — 2026-09-11 · Organización del lab (EPI-AGTLAB-001)

Historia, no normativa. Registro de la reorganización de esta carpeta como
hub de contexto del Microsoft Agent Framework, aplicando prácticas de skevi
(hogares por vida útil, clasificación por disparadores, evidencia por línea).

## Origen

- Petición del mantenedor (2026-09-11): organizar `microsoftAGTlab` con
  mejores prácticas de skevi como contexto para agentes que quieran usar
  Microsoft AGT en esta máquina; playground de ejemplos y ejercicios.
- Dimensionación previa: análisis de `~/www/aria/pinax` y cosecha del mapa
  del ecosistema (6 manifiestos, 9 proyectos sin manifiesto). Consumidores
  esperados: krathos, epistates, skopos, escrubery, ektel.

## Ronda adversarial del plan (2026-09-11)

Nueve hallazgos, decisión `PROCEED` con correcciones:

1. A1 consumidor genérico → docs que referencian, no duplican, proyectos aria.
2. A2 invisibilidad en el mapa → tarea F: `project-manifest.yaml` (pinax).
3. A3 guía enciclopédica → sólo recetas ejecutadas localmente, fechadas.
4. A4 pins a mano vs venv uv → `requirements-frozen.txt` generado (205 paquetes).
5. A5 fuga de secretos en el gate → barrera anti-fuga en `check_environment.py`.
6. A6 DevUI y puertos → sólo loopback, sólo ejecución explícita.
7. A7 coste de tokens → cada ejemplo declara su superficie de coste.
8. A8 `load_dotenv(override=True)` → documentado como decisión local.
9. A9 id de manifiesto → el validador pinax impuso kebab-case: id final
   `microsoftagt-lab` (carpeta `microsoftAGTlab`); forma validada exit 0.

## Hallazgos durante la ejecución

- **Gate:** la prueba adversarial inicial detectó que la barrera anti-fuga
  sólo filtraba una key (la del entorno) y no la del `.env`. Corregido:
  ahora filtra todos los candidatos KEY/SECRET/TOKEN/PASS de entorno y `.env`.
  Verificado en dos escenarios de fuga simulada: 0 filtraciones [pass].
- **Streaming (ejemplo 02):** traceback intermitente de limpieza en
  `httpcore2` al cerrar `asyncio.run`; no afecta el resultado (1 corrida con
  ruido, 1 limpia) [inconclusive: transporte instalado, no código del lab].
- **Salida estructurada (ejemplo 03):** dos hallazgos reales de GLM por este
  endpoint: (a) envuelve JSON en fences con prosa; (b) renombra campos del
  schema. Corregido con extracción tolerante + validación pydantic fail-closed
  + claves literales en instrucciones. El patrón quedó documentado en
  `docs/guia-rapida.md` [pass].
- **Workflows:** el valor de retorno del executor no se propaga; la
  comunicación explícita es `ctx.send_message` / `ctx.yield_output`
  [pass].

## Estado al cierre

- Gate `scripts/check_environment.py` exit 0.
- Ejemplos 01–04 exit 0; 05 verificado por import (sin servidor).
- Sin secretos en archivos versionables (`.env` fuera del alcance Git).

## Adenda misma fecha — decisión E4 y spike camino B

- El mantenedor decidió (conversación 2026-09-11) la **opción 4** del análisis
  de epistates: congelar E4 sin E4-O + corte Bounded explorando el ejecutor
  in-process. Registrado en
  `epistates/docs/plans/2026-09-11-ejecutores-supervisados-opcion.md`.
- `epistates==0.1.0a2` instalado **editable** en este venv desde
  `~/www/aria/epistates` (ruta local; no va en `pyproject.toml`).
  `requirements-frozen.txt` regenerado: 207 distribuciones.
- Nuevo `playground/06_epistates_spike.py`: task-card validada con el
  validador real → agente GLM in-process → evidencia `spike-evidence/v0`
  (prototipo, digests only). Exit 0. Adversarial: tres mutaciones de tarjeta
  rechazadas fail-closed sin gastar tokens [pass].

## Pospuesto

- Inicializar Git (sólo queda `.gitignore` listo) — decisión del mantenedor.
- Adopción de gates skevi (`check_sizes`/`check_plans`) — sin volumen real
  que justificarlo; igual que en epistates, opt-in diferido.
- Manifiesto cosechado por pinax en el mapa del ecosistema — requiere que
  `pinax build` apunte a esta raíz (verificar con el mantenedor).
