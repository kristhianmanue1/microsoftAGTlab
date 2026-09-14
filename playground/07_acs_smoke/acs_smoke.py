"""Smoke local ACS — decisión determinista, sin ejecutar tools y sin GLM.

Demuestra: ACS_POLICY_ENGINE = FUNCTIONAL (veredictos allow/deny deterministas).
NO demuestra: enforcement en host (ninguna tool se ejecuta).

Nota: el dispatcher default de Rego del core nativo ejecuta un binario `opa`
externo (ACS_OPA_PATH/PATH) no presente en esta máquina; se usa el
policy_dispatcher del host, API oficial del SDK para lógica determinista.
"""

import json
import pathlib
import sys

from agent_control_specification import AgentControl

HERE = pathlib.Path(__file__).parent
MANIFEST = HERE / "manifest.yaml"
DENY_TOOLS = {"delete_protected_file"}


class DeterministicToolDispatcher:
    """PolicyDispatcher oficial del SDK: decisión puramente local por nombre."""

    def evaluate(self, invocation):
        tool_name = None
        data = invocation.get("input") if isinstance(invocation, dict) else None
        data = data if isinstance(data, dict) else invocation
        if isinstance(data, dict):
            tool = data.get("tool")
            if isinstance(tool, dict):
                tool_name = tool.get("name")
        decision = "deny" if tool_name in DENY_TOOLS else "allow"
        return {"decision": decision, "message": f"local deterministic policy for {tool_name}"}


async def main() -> int:
    control = AgentControl.from_path(str(MANIFEST), policy_dispatcher=DeterministicToolDispatcher())
    casos = [
        ("read_file", "allow"),
        ("delete_protected_file", "deny"),
        ("rm_rf_no_declarada", "deny"),  # fail-closed: tool no declarada en el manifest
    ]
    resultados = []
    fallo = False
    for tool, esperado in casos:
        res = await control.evaluate_intervention_point(
            "pre_tool_call",
            {"tool_call": {"name": tool, "args": {"path": "docs/nota.md"}}},
        )
        decision = res.verdict.decision.value
        ok = decision == esperado
        fallo = fallo or not ok
        resultados.append((tool, decision, esperado, res.verdict.reason, ok))
        print(f"{tool:24s} -> {decision:5s} (esperado {esperado:5s}) reason={res.verdict.reason} {'OK' if ok else 'FALLO'}")
    print()
    print(json.dumps({"ACS_POLICY_ENGINE": "FUNCTIONAL" if not fallo else "FAILED",
                      "HOST_ENFORCEMENT": "NOT_YET_TESTED",
                      "casos": [r[0:4] for r in resultados]}, ensure_ascii=False, indent=2))
    return 1 if fallo else 0


if __name__ == "__main__":
    import asyncio
    raise SystemExit(asyncio.run(main()))
