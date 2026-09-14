"""04 — Workflow determinista (sin LLM).

Coste: 0 llamadas — executors puros de Python. Demuestra el esqueleto de
workflows del framework: `@executor`, `WorkflowBuilder`, `send_message`,
`yield_output` y `WorkflowRunResult`.

Útil para probar la mecánica (aristas, estados, salidas) sin gastar tokens.
"""

import asyncio

from agent_framework import WorkflowBuilder, WorkflowContext, executor


@executor
async def mayusculas(texto: str, ctx: WorkflowContext[str]) -> None:
    await ctx.send_message(texto.upper())


@executor
async def exclamacion(texto: str, ctx: WorkflowContext[str]) -> None:
    await ctx.yield_output(texto + "!")


async def main() -> None:
    workflow = (
        WorkflowBuilder(start_executor=mayusculas)
        .add_edge(mayusculas, exclamacion)
        .build()
    )

    resultado = await workflow.run("hola workflow")
    print("salida:  ", resultado.get_outputs())
    print("estado:  ", resultado.get_final_state())


if __name__ == "__main__":
    asyncio.run(main())
