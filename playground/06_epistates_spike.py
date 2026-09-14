"""06 — Spike: ejecutor in-process bajo disciplina epistates.

Coste: 1 llamada GLM (sólo si la tarjeta es válida — fail-closed antes de coste).

Prototipo del camino B (análisis 2026-09-11 en epistates): demuestra qué
sobrevive y qué desaparece cuando el ejecutor no es un TUI externo sino un
objeto en este proceso.

  Sobrevive:  validate_task_card (contrato epistates), digest canónico de la
              tarjeta, evidencia portable (digests + checks), clasificación
              posterior por el mantenedor.
  Desaparece: puertos HTTP, preflight de tmux, dispatch send-keys, correlación
              de terminal, reconciliador. El "puerto soportado" es el await.

IMPORTANTE: el artefacto de evidencia es `spike-evidence/v0` — PROTOTIPO del
lab, NO un contrato epistates. Ningún validador oficial lo acepta, y no debe
presentarse como review-evidence ni audit-result. La decisión (OK/PARCIAL/BLOQ)
sigue siendo del mantenedor.
"""

import asyncio
import hashlib
import json
import os
import pathlib
import sys

from dotenv import load_dotenv

from agent_framework import Agent
from agent_framework.openai import OpenAIChatCompletionClient
from epistates import validate_task_card

load_dotenv(override=True)

CARD_PATH = pathlib.Path(
    "/Users/krisnova/www/aria/epistates/fixtures/task-card-valid.json"
)
SPIKE_SCHEMA = "microsoftagt-lab/spike-evidence/v0"


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def fail(msg: str, code: int = 1) -> None:
    print(f"BLOQ: {msg}", file=sys.stderr)
    sys.exit(code)


async def main() -> None:
    # 1) Contrato primero: la tarjeta se valida ANTES de cualquier coste.
    if not CARD_PATH.exists():
        fail(f"tarjeta no encontrada: {CARD_PATH}")
    card_bytes = CARD_PATH.read_bytes()
    card = json.loads(card_bytes)
    try:
        validate_task_card(card)
    except Exception as exc:
        fail(f"task-card inválida: {exc}", code=2)

    card_digest = sha256_bytes(card_bytes)
    print(f"tarjeta válida: {card.get('task_id')} · {card_digest}")

    # 2) Ejecutor in-process: el agente corre en ESTE proceso.
    agent = Agent(
        client=OpenAIChatCompletionClient(
            model=os.environ.get("ZAI_MODEL", "glm-5.3-flash"),
            api_key=os.environ.get("ZAI_API_KEY"),
            base_url=os.environ.get("ZAI_BASE_URL", "https://api.z.ai/api/paas/v4/"),
        ),
        name="EjecutorSpike",
        instructions=(
            "Eres un ejecutor de tareas. Recibirás el objetivo de una tarjeta "
            "de trabajo y responderás en máximo 3 frases: qué harías y qué "
            "evidencia dejarías. No ejecutes nada real."
        ),
    )

    prompt = f"Objetivo de la tarjeta: {card.get('objective')}"
    respuesta = await agent.run(prompt)

    # 3) Evidencia portable: digests, nunca contenido ni secretos.
    output_bytes = str(respuesta).encode("utf-8")
    prompt_bytes = prompt.encode("utf-8")
    evidence = {
        "schema": SPIKE_SCHEMA,
        "task_card_digest": card_digest,
        "executor": {
            "kind": "in-process",
            "framework": "agent-framework (core 1.18.0)",
            "model_autodeclarado": os.environ.get("ZAI_MODEL", "glm-5.3-flash"),
        },
        "prompt": {"sha256": sha256_bytes(prompt_bytes), "bytes": len(prompt_bytes)},
        "output": {"sha256": sha256_bytes(output_bytes), "bytes": len(output_bytes)},
        "checks": [
            {"check_id": "output_nonempty", "status": "pass" if output_bytes else "fail"}
        ],
        "confirms": "technical_run_only",
        "prototipo": "no es contrato epistates; decisión pendiente del mantenedor",
    }
    print(json.dumps(evidence, ensure_ascii=False, indent=2))
    print("\nTexto del ejecutor (dato, no prueba):")
    print(str(respuesta))


if __name__ == "__main__":
    asyncio.run(main())
