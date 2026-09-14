"""03 — Salida estructurada (typed output).

Coste: 1 llamada GLM. Demuestra `response_format` con un modelo pydantic.

HALLAZGO LOCAL (2026-09-11): GLM vía este endpoint no garantiza JSON crudo —
puede envolverlo en fences ```json y añadir prosa alrededor, y `.value`
(fall-closed del framework) explota con ValidationError. Patrón local:
parsear desde `.text` con extracción tolerante, validando SIEMPRE con
pydantic antes de usar el objeto.
"""

import asyncio
import os
import re
from typing import Literal

from dotenv import load_dotenv
from pydantic import BaseModel, Field, ValidationError

from agent_framework import Agent, ChatOptions
from agent_framework.openai import OpenAIChatCompletionClient

load_dotenv(override=True)


class Veredicto(BaseModel):
    tema: str = Field(description="Tema central de la pregunta")
    sentimiento: Literal["positivo", "neutral", "negativo"]
    confianza: float = Field(ge=0.0, le=1.0, description="0.0 a 1.0")


def _extract_json(texto: str) -> str:
    """Extrae el primer bloque JSON de una respuesta que puede traer fences o prosa."""
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", texto, re.DOTALL)
    if fence:
        return fence.group(1)
    balance = re.search(r"\{.*\}", texto, re.DOTALL)
    if balance:
        return balance.group(0)
    return texto


async def main() -> None:
    agent = Agent(
        client=OpenAIChatCompletionClient(
            model=os.environ["ZAI_MODEL"],
            api_key=os.environ["ZAI_API_KEY"],
            base_url=os.environ["ZAI_BASE_URL"],
        ),
        name="Analista",
        instructions=(
            "Analiza la entrada y responde ÚNICAMENTE con un objeto JSON válido, "
            "sin markdown ni texto adicional, usando EXACTAMENTE estas claves: "
            '{"tema": string, "sentimiento": "positivo" | "neutral" | "negativo", '
            '"confianza": número entre 0.0 y 1.0}.'
        ),
    )

    resultado = await agent.run(
        "Me encantó el nuevo teclado mecánico, aunque llegó un día tarde.",
        options=ChatOptions(response_format=Veredicto),
    )

    try:
        veredicto = Veredicto.model_validate_json(_extract_json(resultado.text))
    except ValidationError as exc:
        print("Respuesta no utilizable (fail-closed):", exc)
        raise SystemExit(1) from exc

    print(f"tema:       {veredicto.tema}")
    print(f"sentimiento:{veredicto.sentimiento}")
    print(f"confianza:  {veredicto.confianza}")


if __name__ == "__main__":
    asyncio.run(main())
