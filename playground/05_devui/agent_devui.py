"""05 — DevUI: agente inspeccionable en el Developer UI.

Coste: 0 llamadas al importar; cada mensaje desde la UI gasta tokens.

Este módulo NO arranca servidores al importarse. Para lanzar el Developer UI
(execución explícita, binding loopback 127.0.0.1:8080 por defecto):

    .venv/bin/devui playground/05_devui --no-open

Añade `--headless` para modo API sin UI. La UI permite chatear con el agente
y ver tool calls. Ctrl+C para parar.
"""

import asyncio
import os

from dotenv import load_dotenv

from agent_framework import Agent, tool
from agent_framework.openai import OpenAIChatCompletionClient

load_dotenv(override=True)


@tool
def hora_local() -> str:
    """Devuelve una hora local simulada para demostrar tool calls en la UI."""
    return "12:00 (simulada)"


def build_agent() -> Agent:
    return Agent(
        client=OpenAIChatCompletionClient(
            model=os.environ.get("ZAI_MODEL", "glm-5.3-flash"),
            api_key=os.environ.get("ZAI_API_KEY"),
            base_url=os.environ.get("ZAI_BASE_URL", "https://api.z.ai/api/paas/v4/"),
        ),
        name="AgenteDevUI",
        instructions="Asistente de demo para el Developer UI. Usa la tool de la hora si te la piden.",
        tools=[hora_local],
    )


if __name__ == "__main__":
    from agent_framework.devui import serve

    serve(entities=[build_agent()])
