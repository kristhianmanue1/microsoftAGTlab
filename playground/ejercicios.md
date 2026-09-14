# Ejercicios — retos sin solución

Clasificados por dificultad. Los que consumen API están marcados con
**[tokens]**; los demás son locales y gratis. Ante duda de API, la fuente
normativa es el paquete instalado (`inspect.signature`, `dir()`), no memoria.

## Nivel 1 — calentamiento

1. **[tokens]** Modifica `01_hello_agent.py` para que el agente responda
   siempre con un haiku. Pista: sólo cambia `instructions`.
2. Cambia `04_workflow.py` para añadir un tercer executor que cuente los
   caracteres. Verifica la salida con `resultado.get_outputs()`.
3. Haz que `scripts/check_environment.py` también reporte la versión de
   `openai` instalada (dato, no fallo).

## Nivel 2 — patrón

4. **[tokens]** Crea `06_memoria_multi_turno.py`: tres preguntas encadenadas
   sobre un mismo tema en UNA sesión, y demuestra que la tercera respuesta
   usa contexto de la primera (compara con una sesión nueva).
5. **[tokens]** Crea `07_tool_condicional.py`: una tool que el agente debe
   invocar sólo si la pregunta lo requiere; documenta si la invocó o no
   (la decisión del modelo no es determinista).
6. Escribe un executor de workflow que rechace entradas vacías con una
   excepción y prueba qué hace el workflow con `run("")`.

## Nivel 3 — integración

7. **[tokens]** Combina `03` y `02`: salida estructurada de un análisis con
   datos obtenidos por una tool (el modelo decide llamar la tool y el
   resultado final es un objeto pydantic).
8. **[tokens]** Un workflow con dos AgentExecutor conectados: redactor →
   revisor. El revisor recibe el texto del redactor y produce el final.
9. Levanta DevUI (`playground/05_devui`) y converse con el agente desde la
   UI; registra en `docs/history/` qué tool calls observaste.
10. Añade a `scripts/check_environment.py` un chequeo de divergencia entre
    la versión del core y la del paquete `agent-framework` (metapaquete),
    con veredicto `[pass]` si coinciden y `[inconclusive]` si no.

## Frontera

- Nada de estos ejercicios autoriza: publicar, abrir puertos no-loopback,
  persistir secretos ni instalar dependencias nuevas sin decisión tuya.
- Si un ejercicio requiere cambiar el pin de `pyproject.toml`, es un cambio
  material: registra la decisión en `docs/history/`.
