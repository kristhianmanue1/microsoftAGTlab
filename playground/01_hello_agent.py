"""01 — Hola, agente.

Coste: 1 llamada GLM. Demuestra el ciclo mínimo: cliente -> agente -> run.
Fuente de configuración: `.env` (ZAI_API_KEY, ZAI_BASE_URL, ZAI_MODEL).
"""

import asyncio
import os

from dotenv import load_dotenv

from agent_framework import Agent
from agent_framework.openai import OpenAIChatCompletionClient

load_dotenv(override=True)

ZAI_API_KEY = os.environ.get("ZAI_API_KEY")
ZAI_BASE_URL = os.environ.get("ZAI_BASE_URL", "https://api.z.ai/api/paas/v4/")
ZAI_MODEL = os.environ.get("ZAI_MODEL", "glm-5.3-flash")


async def main() -> None:
    agent = Agent(
        client=OpenAIChatCompletionClient(
            model=ZAI_MODEL,
            api_key=ZAI_API_KEY,
            base_url=ZAI_BASE_URL,
        ),
        name="HolaAgente",
        instructions="Eres un asistente conciso que responde en español.",
    )

    resultado = await agent.run("Preséntate en una frase y dime qué modelo eres.")
    print(resultado)


if __name__ == "__main__":
    asyncio.run(main())
