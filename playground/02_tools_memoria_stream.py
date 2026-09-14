"""02 — Tools, memoria de sesión y streaming.

Coste: 3 llamadas GLM. Demuestra:
  1) tools (`@tool`) que el modelo decide invocar;
  2) memoria de sesión (la segunda pregunta recuerda la primera);
  3) streaming de la respuesta en vivo.

Mejora local sobre el original: `calcular` ya no usa `eval`; usa un evaluador
AST con nodos permitidos y límites anti-DoS (falla cerrado ante cualquier
otra cosa).
"""

import ast
import asyncio
import operator
import os
import random

from dotenv import load_dotenv

from agent_framework import Agent, tool
from agent_framework.openai import OpenAIChatCompletionClient

load_dotenv(override=True)

# --- evaluador aritmético fail-closed (reemplaza a eval) -----------------

_BINOPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}
_UNARYOPS = {ast.USub: operator.neg, ast.UAdd: operator.pos}

_MAX_EXPR_CHARS = 64
_MAX_POW_BASE = 1000
_MAX_POW_EXPONENT = 10


def _safe_eval(node: ast.expr) -> float:
    if isinstance(node, ast.Expression):
        return _safe_eval(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _BINOPS:
        left, right = _safe_eval(node.left), _safe_eval(node.right)
        if isinstance(node.op, ast.Pow):
            if abs(left) > _MAX_POW_BASE or abs(right) > _MAX_POW_EXPONENT:
                raise ValueError("exponente fuera de rango")
        return _BINOPS[type(node.op)](left, right)
    if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARYOPS:
        return _UNARYOPS[type(node.op)](_safe_eval(node.operand))
    raise ValueError("expresión no permitida")


def calcular(expresion: str) -> str:
    """Evalúa una expresión aritmética simple, por ejemplo '2 + 2 * 3'."""
    if len(expresion) > _MAX_EXPR_CHARS:
        return "Expresión demasiado larga"
    try:
        tree = ast.parse(expresion, mode="eval")
        resultado = _safe_eval(tree)
    except (SyntaxError, ValueError, ZeroDivisionError) as exc:
        return f"Expresión rechazada: {exc}"
    return f"Resultado: {resultado}"


# --- tools del agente -----------------------------------------------------

@tool
def get_weather(location: str) -> str:
    """Obtiene el clima actual de una ciudad."""
    condiciones = ["soleado", "nublado", "lluvioso", "ventoso"]
    return f"En {location}: {random.choice(condiciones)}, 18°C"


@tool
def calculadora(expresion: str) -> str:
    """Evalúa una expresión aritmética simple, por ejemplo '2 + 2 * 3'."""
    return calcular(expresion)


async def main() -> None:
    agent = Agent(
        client=OpenAIChatCompletionClient(
            model=os.environ["ZAI_MODEL"],
            api_key=os.environ["ZAI_API_KEY"],
            base_url=os.environ["ZAI_BASE_URL"],
        ),
        name="Asistente",
        instructions="Eres un asistente útil y conciso. Usa las herramientas cuando sea necesario.",
        tools=[get_weather, calculadora],
    )

    session = agent.create_session()

    print("--- 1) Tools: agente que llama funciones ---")
    r1 = await agent.run(
        "¿Qué tiempo hace en Ciudad de México y cuánto es 12 * 8 + 5?",
        session=session,
    )
    print(r1, "\n")

    print("--- 2) Memoria: pregunta de seguimiento (sin repetir contexto) ---")
    r2 = await agent.run("¿Cuál fue el resultado de la operación que hiciste antes?", session=session)
    print(r2, "\n")

    print("--- 3) Streaming: respuesta en vivo ---")
    async for update in agent.run("Cuenta un chiste muy breve sobre el clima.", stream=True, session=session):
        print(update, end="", flush=True)
    print()


if __name__ == "__main__":
    asyncio.run(main())
