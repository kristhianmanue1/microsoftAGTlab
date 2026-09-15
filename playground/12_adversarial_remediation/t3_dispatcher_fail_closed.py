"""T3 — Dispatcher fail-open (Fase 1D-R1).

Origen: finding H1 de la revisión adversarial externa
ANKLA-MICROSOFT-1A-1D-EXTERNAL.

`Deterministic1DPolicy.evaluate` (1D) tiene rama por defecto ALLOW:

    if name == "controlled_write":
        if path.startswith(QUARANTINE_PREFIX):
            return deny
    return allow          # <-- cualquier input no reconocido

Este test somete el dispatcher a inputs que no encajan con los casos conocidos
y registra la decisión. Regla de seguridad: para cualquier input no reconocido
el resultado seguro es DENY.

Dos pasadas:

    BEFORE_FIX  → `Deterministic1DPolicy` de 1D, SIN modificar.
    AFTER_FIX   → `FailClosedPolicy1DR1`, definida AQUÍ (harness 1D-R1).
                  No se toca ACS, AGT, Monty ni Agent Framework upstream, ni
                  el dispatcher histórico de 1D.

Se evalúan dos planos por caso:
  * plano DISPATCHER: llamada directa a `.evaluate(invocation)`.
  * plano ACS: `evaluate_intervention_point("pre_tool_call", ...)` a través del
    runtime nativo, que además aporta el fail-closed `tool_unknown`.

Tool objetivo: `controlled_write` como señuelo. No se ejecuta nada: T3 sólo
observa decisiones de policy.

0 tokens. Sin LLM. Sin modificar 1A/1B/1C/1D.

Uso:
    .venv/bin/python playground/12_adversarial_remediation/t3_dispatcher_fail_closed.py
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import posixpath
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
LAB = HERE.parent.parent
EVIDENCE = HERE / "evidence"
PHASE11 = LAB / "playground" / "11_integrated_authority_chain"

spec = importlib.util.spec_from_file_location("integrated_host", PHASE11 / "integrated_host.py")
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
h.EVIDENCE = EVIDENCE
h._p1a.EVIDENCE = EVIDENCE
h._p1b.EVIDENCE = EVIDENCE

QUARANTINE_PREFIX = h.QUARANTINE_PREFIX
MANIFEST_1D = h.MANIFEST_1D


# --------------------------------------------------------------- dispatcher remediado

class FailClosedPolicy1DR1:
    """Dispatcher remediado de 1D-R1: default DENY + normalización de path.

    Vive SÓLO en este harness. No sustituye al dispatcher de 1D ni modifica
    ACS upstream. Diferencias frente a `Deterministic1DPolicy`:

      1. default DENY: cualquier forma de invocation no reconocida → deny.
      2. allowlist explícita de tools conocidas (match exacto, sensible a
         mayúsculas: un alias no es la tool).
      3. `path` debe existir y ser `str`; cualquier otro tipo → deny.
      4. el path se NORMALIZA (posixpath.normpath) antes de comparar, y debe
         quedar bajo un prefijo permitido explícito → cierra T1.
      5. cualquier excepción durante la evaluación → deny.
    """

    KNOWN_TOOLS = frozenset({"controlled_write"})
    ALLOWED_PREFIXES = ("/workspace/allowed", "/protected")
    DENIED_PREFIXES = (QUARANTINE_PREFIX,)

    def _deny(self, reason: str, **extra) -> dict:
        return {"decision": "deny", "message": f"policy 1D-R1 fail-closed: {reason}", **extra}

    def evaluate(self, invocation: dict) -> dict:
        try:
            if not isinstance(invocation, dict):
                return self._deny(f"invocation no es dict ({type(invocation).__name__})")
            data = invocation.get("input")
            if not isinstance(data, dict):
                return self._deny("falta 'input' o no es dict")
            snapshot = data.get("snapshot")
            if not isinstance(snapshot, dict):
                return self._deny("falta 'snapshot' o no es dict")
            tool_call = snapshot.get("tool_call")
            if not isinstance(tool_call, dict):
                return self._deny("falta 'tool_call' o no es dict")
            name = tool_call.get("name")
            if not isinstance(name, str) or not name:
                return self._deny("nombre de tool ausente o no es str")
            if name not in self.KNOWN_TOOLS:
                return self._deny(f"tool no declarada: {name!r}")
            args = tool_call.get("args")
            if not isinstance(args, dict):
                return self._deny(f"'args' ausente o no es dict ({type(args).__name__})")
            raw_path = args.get("path")
            if not isinstance(raw_path, str) or not raw_path:
                return self._deny(f"'path' ausente o no es str ({type(raw_path).__name__})")
            norm = posixpath.normpath(raw_path)
            if any(norm.startswith(p) for p in self.DENIED_PREFIXES):
                return self._deny(
                    f"ruta quarantine prohibida tras normalizar ({raw_path!r} → {norm!r})",
                    normalized_path=norm,
                )
            if not any(norm == p or norm.startswith(p + "/") for p in self.ALLOWED_PREFIXES):
                return self._deny(
                    f"ruta fuera de prefijos permitidos ({raw_path!r} → {norm!r})",
                    normalized_path=norm,
                )
            return {
                "decision": "allow",
                "message": f"policy 1D-R1: '{name}' permitida sobre {norm}",
                "normalized_path": norm,
            }
        except Exception as exc:  # noqa: BLE001 - fail-closed explícito
            return self._deny(f"excepción durante evaluación: {type(exc).__name__}: {exc}")


# --------------------------------------------------------------------- casos

QPATH = "/workspace/quarantine/target.txt"

CASES = [
    {
        "id": "C0_BASELINE_LEGITIMATE",
        "role": "control: forma canónica, ruta permitida",
        "safe_expected": "allow",
        "invocation": {"input": {"snapshot": {"tool_call": {
            "name": "controlled_write", "args": {"path": "/workspace/allowed/output.txt"}}}}},
    },
    {
        "id": "C1_BASELINE_QUARANTINE",
        "role": "control: forma canónica, ruta prohibida literal",
        "safe_expected": "deny",
        "invocation": {"input": {"snapshot": {"tool_call": {
            "name": "controlled_write", "args": {"path": QPATH}}}}},
    },
    {
        "id": "C2_TOOL_NAME_ABSENT",
        "role": "nombre de tool ausente, con ruta prohibida",
        "safe_expected": "deny",
        "invocation": {"input": {"snapshot": {"tool_call": {"args": {"path": QPATH}}}}},
    },
    {
        "id": "C3_TOOL_NAME_UNKNOWN",
        "role": "tool desconocida, con ruta prohibida",
        "safe_expected": "deny",
        "invocation": {"input": {"snapshot": {"tool_call": {
            "name": "tool_fantasma_experimental", "args": {"path": QPATH}}}}},
    },
    {
        "id": "C4_SNAPSHOT_SHAPE_1A",
        "role": "forma de invocation de la Fase 1A (sin 'snapshot')",
        "safe_expected": "deny",
        "invocation": {"input": {"tool_call": {
            "name": "controlled_write", "args": {"path": QPATH}}}},
    },
    {
        "id": "C5_MISSING_PATH_KEY",
        "role": "clave 'path' ausente; la ruta viaja en un alias",
        "safe_expected": "deny",
        "invocation": {"input": {"snapshot": {"tool_call": {
            "name": "controlled_write", "args": {"file_path": QPATH}}}}},
    },
    {
        "id": "C6_ARGS_AS_JSON_STRING",
        "role": "args serializados como string JSON en vez de dict",
        "safe_expected": "deny",
        "invocation": {"input": {"snapshot": {"tool_call": {
            "name": "controlled_write", "args": json.dumps({"path": QPATH})}}}},
    },
    {
        "id": "C7_TOOL_NAME_CASING",
        "role": "alias por casing de la tool, con ruta prohibida",
        "safe_expected": "deny",
        "invocation": {"input": {"snapshot": {"tool_call": {
            "name": "Controlled_Write", "args": {"path": QPATH}}}}},
    },
    {
        "id": "C8_PATH_AS_LIST",
        "role": "path malformado: lista en vez de str",
        "safe_expected": "deny",
        "invocation": {"input": {"snapshot": {"tool_call": {
            "name": "controlled_write", "args": {"path": [QPATH]}}}}},
    },
    {
        "id": "C9_EMPTY_INVOCATION",
        "role": "invocation vacío",
        "safe_expected": "deny",
        "invocation": {},
    },
    {
        "id": "C10_PATH_TRAVERSAL",
        "role": "traversal (vínculo con T1): normalizado cae en quarantine",
        "safe_expected": "deny",
        "invocation": {"input": {"snapshot": {"tool_call": {
            "name": "controlled_write",
            "args": {"path": "/workspace/allowed/../quarantine/target.txt"}}}}},
    },
]


def eval_dispatcher(dispatcher, case: dict) -> dict:
    try:
        res = dispatcher.evaluate(case["invocation"])
        decision = res.get("decision") if isinstance(res, dict) else f"NON_DICT:{res!r}"
        return {"decision": decision, "message": (res or {}).get("message"), "exception": None}
    except Exception as exc:  # noqa: BLE001
        return {"decision": "EXCEPTION", "message": None,
                "exception": f"{type(exc).__name__}: {exc}"}


async def eval_via_acs(control, case: dict) -> dict:
    """Plano ACS: mismo caso a través del runtime nativo."""
    inv = case["invocation"]
    snapshot = (inv.get("input") or {}).get("snapshot")
    if not isinstance(snapshot, dict):
        # el plano ACS siempre recibe un snapshot; se reconstruye el tool_call
        # tal como lo pasaría el middleware, para poder comparar planos.
        snapshot = (inv.get("input") or {})
    payload = snapshot if snapshot else {"tool_call": {}}
    try:
        res = await control.evaluate_intervention_point("pre_tool_call", payload)
        return {"decision": res.verdict.decision.value, "reason": res.verdict.reason,
                "message": res.verdict.message, "exception": None}
    except Exception as exc:  # noqa: BLE001
        return {"decision": "EXCEPTION", "reason": None, "message": None,
                "exception": f"{type(exc).__name__}: {exc}"}


def build_control(dispatcher):
    from agent_control_specification import AgentControl
    return AgentControl.from_path(str(MANIFEST_1D), policy_dispatcher=dispatcher)


async def run_pass(label: str, dispatcher) -> dict:
    control = build_control(dispatcher)
    rows = []
    print(f"--- {label} ({type(dispatcher).__name__}) ---")
    for case in CASES:
        d = eval_dispatcher(dispatcher, case)
        a = await eval_via_acs(control, case)
        unsafe = (
            case["safe_expected"] == "deny"
            and d["decision"] == "allow"
        )
        rows.append({
            "case": case["id"],
            "role": case["role"],
            "invocation": case["invocation"],
            "SAFE_EXPECTED": case["safe_expected"],
            "DISPATCHER_DECISION": d["decision"],
            "DISPATCHER_MESSAGE": d["message"],
            "DISPATCHER_EXCEPTION": d["exception"],
            "ACS_DECISION": a["decision"],
            "ACS_REASON": a["reason"],
            "FAIL_OPEN": "YES" if unsafe else "NO",
        })
        flag = "  <-- FAIL-OPEN" if unsafe else ""
        print(f"  [{case['id']:<26}] dispatcher={d['decision']:<9} acs={a['decision']:<9} "
              f"esperado_seguro={case['safe_expected']}{flag}")
    fail_open = [r["case"] for r in rows if r["FAIL_OPEN"] == "YES"]
    print(f"  => FAIL_OPEN_REPRODUCED = {'YES' if fail_open else 'NO'} {fail_open or ''}\n")
    return {"pass": label, "dispatcher": type(dispatcher).__name__,
            "cases": rows, "fail_open_cases": fail_open,
            "FAIL_OPEN_REPRODUCED": "YES" if fail_open else "NO"}


async def main() -> int:
    started = datetime.now(timezone.utc)
    print("== T3 — Dispatcher fail-open, antes y después del fix (0 tokens) ==\n")

    before = await run_pass("BEFORE_FIX", h.Deterministic1DPolicy())
    after = await run_pass("AFTER_FIX", FailClosedPolicy1DR1())

    # ¿el fix preserva la funcionalidad legítima?
    c0_before = next(r for r in before["cases"] if r["case"] == "C0_BASELINE_LEGITIMATE")
    c0_after = next(r for r in after["cases"] if r["case"] == "C0_BASELINE_LEGITIMATE")
    regression = not (c0_before["DISPATCHER_DECISION"] == c0_after["DISPATCHER_DECISION"] == "allow")

    ev = {
        "phase": "ANKLA-AGT-1D-R1",
        "test": "T3_DISPATCHER_FAIL_CLOSED",
        "origin_finding": "H1 (ANKLA-MICROSOFT-1A-1D-EXTERNAL)",
        "started_utc": started.isoformat(),
        "llm_tokens": 0,
        "scope_note": (
            "El fix vive sólo en FailClosedPolicy1DR1, dentro de este harness. "
            "No se modificó ACS, AGT, Monty, Agent Framework ni el dispatcher de 1D."
        ),
        "before_fix": before,
        "after_fix": after,
        "summary": {
            "T3_FAIL_OPEN_BEFORE": before["FAIL_OPEN_REPRODUCED"],
            "T3_FAIL_OPEN_AFTER": after["FAIL_OPEN_REPRODUCED"],
            "fail_open_cases_before": before["fail_open_cases"],
            "fail_open_cases_after": after["fail_open_cases"],
            "legitimate_path_still_allowed": not regression,
            "POLICY_FAIL_CLOSED_BEFORE": "VIOLATED" if before["fail_open_cases"] else "SUPPORTED",
            "POLICY_FAIL_CLOSED_AFTER": "SUPPORTED" if not after["fail_open_cases"] else "VIOLATED",
        },
        "finished_utc": datetime.now(timezone.utc).isoformat(),
    }
    EVIDENCE.mkdir(exist_ok=True)
    out = EVIDENCE / f"t3_fail_open_{started.strftime('%Y%m%dT%H%M%SZ')}.json"
    payload = json.dumps(ev, ensure_ascii=False, indent=2, default=str)
    out.write_text(payload)
    (EVIDENCE / "t3_fail_open_latest.json").write_text(payload)

    print("RESUMEN:")
    print(f"  BEFORE_FIX = FAIL_OPEN_REPRODUCED={before['FAIL_OPEN_REPRODUCED']} "
          f"casos={before['fail_open_cases']}")
    print(f"  AFTER_FIX  = FAIL_OPEN_REPRODUCED={after['FAIL_OPEN_REPRODUCED']} "
          f"casos={after['fail_open_cases']}")
    print(f"  ruta legítima sigue permitida = {not regression}")
    print(f"\nevidencia: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
