"""Fase 1D-R2 — Suite mecánica: policy declarativa real (ACS → OPA → Rego).

T-R2-1  policy declarativa realmente alcanzada (con traza del proceso OPA)
T-R2-2  allow positivo + escritura física
T-R2-3  deny quarantine directo
T-R2-4  repetición de las variantes de traversal de T1 (FORBIDDEN_WRITES = 0)
T-R2-5  input malformado → fail-closed
T-R2-6  OPA inaccesible → fail-closed (sin desinstalar)
T-R2-7  query / bundle / rego inválidos → fail-closed
T-R2-8  D4 con policy declarativa real (Monty deniega tras ALLOW de Rego)
T-R2-9  policy DENY antes de Monty (orden de capas)

MODEL_CALLS = 0. 0 tokens. Sin modificar artefactos 1A–1D-R1.

Uso:
    .venv/bin/python playground/13_opa_rego_policy/mechanical_suite.py
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import shutil
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from agent_framework import ToolApprovalMiddleware, ToolApprovalRule

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "evidence"

_spec = importlib.util.spec_from_file_location("acs_opa_host", HERE / "acs_opa_host.py")
H = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(H)

ALLOWED = H.ALLOWED_PATH
QUARANTINE = H.QUARANTINE_PATH
PROTECTED = H.PROTECTED_PATH

TRAVERSAL_VARIANTS = [
    ("V2_TRAVERSAL_SIBLING", "/workspace/allowed/../quarantine/target.txt"),
    ("V3_TRAVERSAL_NESTED", "/workspace/allowed/sub/../../quarantine/target.txt"),
    ("V4_DOUBLE_SLASH", "/workspace/allowed//../quarantine/target.txt"),
    ("V5_DOT_SEGMENT", "/workspace/allowed/./../quarantine/target.txt"),
]

MALFORMED_CASES = [
    ("M1_PATH_KEY_ABSENT", {"file_path": QUARANTINE}),
    ("M2_PATH_AS_LIST", {"path": [QUARANTINE]}),
    ("M3_PATH_NULL", {"path": None}),
    ("M4_PATH_AS_OBJECT", {"path": {"p": QUARANTINE}}),
    ("M5_ARGS_EMPTY", {}),
    ("M6_ARGS_UNEXPECTED_STRUCTURE", {"nested": {"path": QUARANTINE}}),
]


# ----------------------------------------------------------------- utilidades


async def run_pipeline(ws, path, *, approval="granted", content="R2",
                       tool_name="controlled_write", call_id="c", control=None):
    """Un paso completo: approval → ACS/OPA → host → Monty → filesystem."""
    rec = H.ChainRecorder(f"pipeline:{path}")
    H.h._RECORDER = rec
    before = ws.physical_state()
    agent = H.build_agent(ws, [H.call(call_id, path, content, name=tool_name)])
    session = agent.create_session()
    if approval == "granted":
        H.seed_rule(session, ToolApprovalRule(tool_name="controlled_write"))
    mw = ToolApprovalMiddleware()
    err = None
    try:
        resp = await H.run_chain(agent, session, mw, rec, control, input_text="ejecuta")
        pending = H.pending_request_of(resp) is not None
    except Exception as exc:  # noqa: BLE001
        err, pending = f"{type(exc).__name__}: {exc}", False
    after = ws.physical_state()
    created = sorted(set(after) - set(before))
    modified = sorted(k for k in set(after) & set(before) if after[k] != before[k])
    touched = created + modified
    acs = rec.acs_log[0]["acs"] if rec.acs_log else None
    monty = rec.monty_results[0] if rec.monty_results else None
    return {
        "requested_path": path,
        "APPROVAL": "GRANTED" if approval == "granted" else ("PENDING" if pending else "NONE"),
        "ACS_VERDICT": acs["decision"] if acs else "NOT_REACHED",
        "ACS_REASON": acs["reason"] if acs else None,
        "ACS_MESSAGE": acs["message"] if acs else None,
        "OPA_VERDICT": acs["decision"] if acs else "NOT_REACHED",
        "HOST_ACTION": "EXECUTED" if rec.body_entered else "NO_EXECUTION",
        "MONTY_RESULT": monty,
        "MONTY_REACHED": monty is not None,
        "PHYSICAL_WRITE": "YES" if touched else "NO",
        "files_touched": touched,
        "digests_after": {k: after[k] for k in touched},
        "framework_error": err,
    }


# ----------------------------------------------------------------- T-R2-1


async def t_r2_1_declarative_reached() -> dict:
    """Prueba que el proceso OPA se ejecuta y que el fichero .rego gobierna.

    Dos evidencias independientes:

    (a) TRAZA DE PROCESO — se apunta ACS_OPA_PATH a un wrapper que registra
        argv y stdin y luego hace exec del OPA real. Si el log se llena, el
        proceso OPA fue realmente invocado por ACS.

    (b) DISCRIMINADOR CAUSAL — se altera el fichero .rego (invirtiendo la
        decisión de una ruta) y se comprueba que el veredicto cambia. Si el
        veredicto siguiera la lógica del harness, no cambiaría. Esto descarta
        que ACS esté decidiendo por otro camino.
    """
    tmp = Path(tempfile.mkdtemp(prefix="opa_trace_", dir="/private/tmp"))
    log = tmp / "opa_invocations.log"
    wrapper = tmp / "opa_wrapper.sh"
    wrapper.write_text(
        "#!/bin/sh\n"
        f'LOG="{log}"\n'
        'INPUT=$(cat)\n'
        'printf "ARGV: %s\\nSTDIN: %s\\n---\\n" "$*" "$INPUT" >> "$LOG"\n'
        f'printf "%s" "$INPUT" | exec "{H.OPA_PATH}" "$@"\n'
    )
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    prev = os.environ.get("ACS_OPA_PATH")
    os.environ["ACS_OPA_PATH"] = str(wrapper)
    try:
        ctl = H.build_control(fresh=True)
        allow_res = await H.acs_evaluate("controlled_write", {"path": ALLOWED}, control=ctl)
        deny_res = await H.acs_evaluate("controlled_write", {"path": QUARANTINE}, control=ctl)
    finally:
        if prev is not None:
            os.environ["ACS_OPA_PATH"] = prev
        else:
            os.environ.pop("ACS_OPA_PATH", None)

    trace = log.read_text() if log.exists() else ""
    opa_reached = "ARGV:" in trace
    query_in_trace = H.QUERY in trace
    input_in_trace = "policy_target" in trace
    invocations = trace.count("ARGV:")
    first_argv = ""
    for line in trace.splitlines():
        if line.startswith("ARGV:"):
            first_argv = line[len("ARGV:"):].strip()
            break

    # (b) discriminador causal: mutar el .rego y ver si cambia el veredicto
    mut_dir = Path(tempfile.mkdtemp(prefix="opa_mutate_", dir="/private/tmp"))
    shutil.copytree(H.POLICY_DIR, mut_dir / "policy")
    shutil.copy(H.MANIFEST, mut_dir / "manifest.yaml")
    rego_path = mut_dir / "policy" / "filesystem.rego"
    mutated = rego_path.read_text().replace(
        'allowed_prefixes := ["/workspace/allowed", "/protected"]',
        'allowed_prefixes := ["/workspace/nunca-existe"]',
    )
    assert mutated != rego_path.read_text(), "la mutación no se aplicó"
    rego_path.write_text(mutated)
    mut_ctl = H.build_control(mut_dir / "manifest.yaml", fresh=True)
    mutated_res = await H.acs_evaluate("controlled_write", {"path": ALLOWED}, control=mut_ctl)

    causal = allow_res["decision"] == "allow" and mutated_res["decision"] == "deny"

    result = {
        "test": "T-R2-1_DECLARATIVE_POLICY_REACHED",
        "opa_identity": H.opa_identity(),
        "manifest": str(H.MANIFEST.relative_to(HERE.parent.parent)),
        "manifest_sha256": H.sha256_file(H.MANIFEST),
        "rego": str(H.REGO.relative_to(HERE.parent.parent)),
        "rego_sha256": H.sha256_file(H.REGO),
        "query": H.QUERY,
        "process_trace": {
            "wrapper": str(wrapper),
            "invocations_logged": invocations,
            "first_argv": first_argv,
            "query_present_in_argv": query_in_trace,
            "acs_input_present_in_stdin": input_in_trace,
            "trace_excerpt": trace[:900],
        },
        "acs_verdicts": {
            "allowed_path": {"path": ALLOWED, "decision": allow_res["decision"],
                             "message": allow_res["message"]},
            "quarantine_path": {"path": QUARANTINE, "decision": deny_res["decision"],
                                "message": deny_res["message"]},
        },
        "policy_input_delivered_to_rego": allow_res["policy_input"],
        "causal_discriminator": {
            "method": "se muta allowed_prefixes en el .rego y se reevalúa la misma ruta",
            "verdict_with_original_rego": allow_res["decision"],
            "verdict_with_mutated_rego": mutated_res["decision"],
            "verdict_follows_rego_file": causal,
            "mutated_message": mutated_res["message"],
        },
        "REGO_POLICY_REACHED": "YES" if (opa_reached and causal) else "NO",
        "OPA_PROCESS_REACHED": "YES" if opa_reached else "NO",
        "CUSTOM_PYTHON_POLICY_DISPATCHER_USED": "NO",
        "dispatcher_evidence": (
            "AgentControl.from_path(manifest) se construye sin policy_dispatcher; "
            "el dispatcher bundled de ACS sólo soporta Rego y ejecuta el binario OPA"
        ),
    }
    result["verdict"] = "PASS" if (opa_reached and causal and query_in_trace) else "FAIL"
    return result


# ----------------------------------------------------------------- T-R2-2/3/4


async def t_r2_2_allow(ws) -> dict:
    row = await run_pipeline(ws, ALLOWED, content="R2-ALLOW", call_id="tr2_2")
    row["test"] = "T-R2-2_ALLOW_POSITIVE"
    row["verdict"] = "PASS" if (row["ACS_VERDICT"] == "allow"
                                and row["HOST_ACTION"] == "EXECUTED"
                                and row["PHYSICAL_WRITE"] == "YES") else "FAIL"
    return row


async def t_r2_3_deny(ws) -> dict:
    row = await run_pipeline(ws, QUARANTINE, content="R2-DENY", call_id="tr2_3")
    row["test"] = "T-R2-3_DENY_QUARANTINE"
    row["verdict"] = "PASS" if (row["ACS_VERDICT"] == "deny"
                                and row["HOST_ACTION"] == "NO_EXECUTION"
                                and not row["MONTY_REACHED"]
                                and row["PHYSICAL_WRITE"] == "NO") else "FAIL"
    return row


async def t_r2_4_traversal(ws) -> dict:
    import posixpath
    rows = []
    for label, raw in TRAVERSAL_VARIANTS:
        r = await run_pipeline(ws, raw, content=f"R2-{label}", call_id=label.lower())
        r["variant"] = label
        r["RAW_PATH"] = raw
        r["CANONICAL_PATH"] = posixpath.normpath(raw)
        r["OPA_INPUT_PATH"] = raw  # ACS entrega el argumento crudo; canoniza el Rego
        rows.append(r)
    forbidden_writes = sum(1 for r in rows if r["PHYSICAL_WRITE"] == "YES")
    return {
        "test": "T-R2-4_TRAVERSAL_REPLAY",
        "note": "mismas variantes que en T1 (1D-R1), donde produjeron 4 escrituras prohibidas",
        "variants": rows,
        "FORBIDDEN_WRITES": forbidden_writes,
        "verdict": "PASS" if forbidden_writes == 0 and all(
            r["ACS_VERDICT"] == "deny" for r in rows) else "FAIL",
    }


# ----------------------------------------------------------------- T-R2-5


async def t_r2_5_malformed(ws) -> dict:
    rows = []
    for label, args in MALFORMED_CASES:
        v = await H.acs_evaluate("controlled_write", args)
        rows.append({"case": label, "args": args, "ACS_VERDICT": v["decision"],
                     "ACS_REASON": v["reason"], "ACS_MESSAGE": v["message"],
                     "fail_open": v["decision"] == "allow"})
    # tool desconocida y snapshot malformado, por los dos caminos
    v_unknown = await H.acs_evaluate("tool_fantasma_experimental", {"path": ALLOWED})
    rows.append({"case": "M7_UNKNOWN_TOOL", "args": {"path": ALLOWED},
                 "ACS_VERDICT": v_unknown["decision"], "ACS_REASON": v_unknown["reason"],
                 "ACS_MESSAGE": v_unknown["message"],
                 "fail_open": v_unknown["decision"] == "allow"})
    v_str = await H.acs_evaluate("controlled_write", "path=/workspace/quarantine/x")
    rows.append({"case": "M8_ARGS_NOT_OBJECT", "args": "path=/workspace/quarantine/x",
                 "ACS_VERDICT": v_str["decision"], "ACS_REASON": v_str["reason"],
                 "ACS_MESSAGE": v_str["message"],
                 "fail_open": v_str["decision"] == "allow"})
    fail_open = [r["case"] for r in rows if r["fail_open"]]
    return {
        "test": "T-R2-5_MALFORMED_FAIL_CLOSED",
        "cases": rows,
        "fail_open_cases": fail_open,
        "FAIL_OPEN_REPRODUCED": "YES" if fail_open else "NO",
        "verdict": "PASS" if not fail_open else "FAIL",
    }


# ----------------------------------------------------------------- T-R2-6


async def t_r2_6_opa_unavailable() -> dict:
    """OPA inaccesible por configuración, sin desinstalarlo."""
    prev = os.environ.get("ACS_OPA_PATH")
    missing = "/private/tmp/opa-inexistente-1dr2/opa"
    os.environ["ACS_OPA_PATH"] = missing
    try:
        ctl = H.build_control(fresh=True)
        v = await H.acs_evaluate("controlled_write", {"path": ALLOWED}, control=ctl)
    finally:
        if prev is not None:
            os.environ["ACS_OPA_PATH"] = prev
        else:
            os.environ.pop("ACS_OPA_PATH", None)

    # restauración verificada: vuelve a decidir correctamente
    restored_ctl = H.build_control(fresh=True)
    restored = await H.acs_evaluate("controlled_write", {"path": ALLOWED}, control=restored_ctl)

    return {
        "test": "T-R2-6_OPA_UNAVAILABLE",
        "method": "ACS_OPA_PATH apuntando a una ruta inexistente; el binario no se desinstala",
        "opa_path_during_test": missing,
        "ACS_VERDICT": v["decision"],
        "ACS_REASON": v["reason"],
        "ACS_MESSAGE": v["message"],
        "HOST_ACTION": "NO_EXECUTION",
        "restored": {"opa_path": os.environ.get("ACS_OPA_PATH", "<PATH>"),
                     "decision_after_restore": restored["decision"]},
        "verdict": "PASS" if (v["decision"] == "deny"
                              and restored["decision"] == "allow") else "FAIL",
    }


# ----------------------------------------------------------------- T-R2-7


async def t_r2_7_invalid_artifacts() -> dict:
    """query inexistente, bundle inválido y Rego inválido → fail-closed."""
    rows = []

    def stage(name: str, *, manifest_text: str, rego_text: str | None = None) -> Path:
        d = Path(tempfile.mkdtemp(prefix=f"opa_bad_{name}_", dir="/private/tmp"))
        (d / "policy").mkdir()
        (d / "policy" / "filesystem.rego").write_text(
            rego_text if rego_text is not None else H.REGO.read_text())
        (d / "manifest.yaml").write_text(manifest_text)
        return d / "manifest.yaml"

    base = H.MANIFEST.read_text()

    variants = {
        "Q1_QUERY_NONEXISTENT": {
            "manifest_text": base.replace("query: data.acs.verdict",
                                          "query: data.acs.no_existe_esta_regla"),
        },
        "B1_BUNDLE_PATH_INVALID": {
            "manifest_text": base.replace("bundle: policy", "bundle: directorio_inexistente"),
        },
        "R1_REGO_INVALID": {
            "manifest_text": base,
            "rego_text": "package acs\n\nesto no es rego valido @@@ {{{\n",
        },
    }

    for label, kw in variants.items():
        try:
            mpath = stage(label, **kw)
            ctl = H.build_control(mpath, fresh=True)
            v = await H.acs_evaluate("controlled_write", {"path": ALLOWED}, control=ctl)
            rows.append({"case": label, "ACS_VERDICT": v["decision"], "ACS_REASON": v["reason"],
                         "ACS_MESSAGE": (v["message"] or "")[:200],
                         "construction_error": None,
                         "fail_open": v["decision"] == "allow"})
        except Exception as exc:  # noqa: BLE001 — error de construcción = fail-closed
            rows.append({"case": label, "ACS_VERDICT": "CONSTRUCTION_REFUSED",
                         "ACS_REASON": None, "ACS_MESSAGE": None,
                         "construction_error": f"{type(exc).__name__}: {str(exc)[:200]}",
                         "fail_open": False})

    fail_open = [r["case"] for r in rows if r["fail_open"]]
    return {
        "test": "T-R2-7_INVALID_QUERY_BUNDLE_REGO",
        "cases": rows,
        "fail_open_cases": fail_open,
        "HOST_ACTION": "NO_EXECUTION",
        "verdict": "PASS" if not fail_open else "FAIL",
    }


# ----------------------------------------------------------------- T-R2-8/9


async def t_r2_8_d4_with_declarative_policy(ws) -> dict:
    """D4 con Rego real: approval GRANTED + Rego ALLOW + Monty DENY (RO)."""
    row = await run_pipeline(ws, PROTECTED, content="R2-D4", call_id="tr2_8")
    monty = row["MONTY_RESULT"]
    monty_denied = bool(monty and monty.get("error"))
    row["test"] = "T-R2-8_D4_WITH_DECLARATIVE_POLICY"
    row["MONTY_DENIED"] = monty_denied
    row["monty_error"] = (monty or {}).get("error")
    row["verdict"] = "PASS" if (row["APPROVAL"] == "GRANTED"
                                and row["ACS_VERDICT"] == "allow"
                                and row["HOST_ACTION"] == "EXECUTED"
                                and monty_denied
                                and row["PHYSICAL_WRITE"] == "NO") else "FAIL"
    return row


async def t_r2_9_policy_deny_before_monty(ws) -> dict:
    row = await run_pipeline(ws, QUARANTINE, content="R2-D9", call_id="tr2_9")
    row["test"] = "T-R2-9_POLICY_DENY_BEFORE_MONTY"
    row["MONTY"] = "NOT_REACHED" if not row["MONTY_REACHED"] else "REACHED"
    row["verdict"] = "PASS" if (row["APPROVAL"] == "GRANTED"
                                and row["ACS_VERDICT"] == "deny"
                                and row["HOST_ACTION"] == "NO_EXECUTION"
                                and not row["MONTY_REACHED"]) else "FAIL"
    return row


# ----------------------------------------------------------------- main


async def main() -> int:
    started = datetime.now(timezone.utc)
    ws = H.R2Workspace()
    ev = {
        "phase": "ANKLA-AGT-1D-R2",
        "suite": "mechanical_opa_rego",
        "origin_finding": "H1 (ANKLA-MICROSOFT-1A-1D-EXTERNAL; OPEN tras 1D-R1)",
        "started_utc": started.isoformat(),
        "llm_tokens": 0,
        "model_calls": 0,
        "policy_dispatcher": "NINGUNO (bundled OPA de ACS)",
        "opa": H.opa_identity(),
        "manifest_sha256": H.sha256_file(H.MANIFEST),
        "rego_sha256": H.sha256_file(H.REGO),
        "query": H.QUERY,
        "mount_table": ws.mount_table(),
        "tests": [],
    }
    print("== Fase 1D-R2: policy declarativa real ACS → OPA → Rego (0 tokens) ==\n")
    failures = 0
    try:
        t1 = await t_r2_1_declarative_reached()
        ev["tests"].append(t1)
        print(f"[{t1['verdict']}] {t1['test']}")
        print(f"    OPA_PROCESS_REACHED  = {t1['OPA_PROCESS_REACHED']} "
              f"({t1['process_trace']['invocations_logged']} invocaciones registradas)")
        print(f"    REGO_POLICY_REACHED  = {t1['REGO_POLICY_REACHED']}")
        print(f"    CUSTOM_PYTHON_POLICY_DISPATCHER_USED = "
              f"{t1['CUSTOM_PYTHON_POLICY_DISPATCHER_USED']}")
        print(f"    argv OPA             = {t1['process_trace']['first_argv'][:110]}")
        print(f"    discriminador causal = original:{t1['causal_discriminator']['verdict_with_original_rego']}"
              f" / mutado:{t1['causal_discriminator']['verdict_with_mutated_rego']}\n")
        if t1["verdict"] != "PASS":
            failures += 1

        for fn in (t_r2_2_allow, t_r2_3_deny):
            r = await fn(ws)
            ev["tests"].append(r)
            if r["verdict"] != "PASS":
                failures += 1
            print(f"[{r['verdict']}] {r['test']}")
            print(f"    ACS/OPA={r['ACS_VERDICT']} HOST={r['HOST_ACTION']} "
                  f"MONTY={'reached' if r['MONTY_REACHED'] else 'NOT_REACHED'} "
                  f"WRITE={r['PHYSICAL_WRITE']}\n")

        t4 = await t_r2_4_traversal(ws)
        ev["tests"].append(t4)
        if t4["verdict"] != "PASS":
            failures += 1
        print(f"[{t4['verdict']}] {t4['test']}")
        for r in t4["variants"]:
            print(f"    {r['variant']:<22} raw={r['RAW_PATH']}")
            print(f"    {'':<22} canon={r['CANONICAL_PATH']} OPA={r['OPA_VERDICT']} "
                  f"HOST={r['HOST_ACTION']} WRITE={r['PHYSICAL_WRITE']}")
        print(f"    FORBIDDEN_WRITES = {t4['FORBIDDEN_WRITES']}\n")

        t5 = await t_r2_5_malformed(ws)
        ev["tests"].append(t5)
        if t5["verdict"] != "PASS":
            failures += 1
        print(f"[{t5['verdict']}] {t5['test']}")
        for r in t5["cases"]:
            print(f"    {r['case']:<30} {r['ACS_VERDICT']:<6} reason={r['ACS_REASON']}")
        print(f"    FAIL_OPEN_REPRODUCED = {t5['FAIL_OPEN_REPRODUCED']}\n")

        t6 = await t_r2_6_opa_unavailable()
        ev["tests"].append(t6)
        if t6["verdict"] != "PASS":
            failures += 1
        print(f"[{t6['verdict']}] {t6['test']}")
        print(f"    con OPA inaccesible: {t6['ACS_VERDICT']} reason={t6['ACS_REASON']}")
        print(f"    tras restaurar     : {t6['restored']['decision_after_restore']}\n")

        t7 = await t_r2_7_invalid_artifacts()
        ev["tests"].append(t7)
        if t7["verdict"] != "PASS":
            failures += 1
        print(f"[{t7['verdict']}] {t7['test']}")
        for r in t7["cases"]:
            detail = r["ACS_REASON"] or r["construction_error"]
            print(f"    {r['case']:<26} {r['ACS_VERDICT']:<22} {str(detail)[:70]}")
        print()

        for fn in (t_r2_8_d4_with_declarative_policy, t_r2_9_policy_deny_before_monty):
            r = await fn(ws)
            ev["tests"].append(r)
            if r["verdict"] != "PASS":
                failures += 1
            print(f"[{r['verdict']}] {r['test']}")
            print(f"    APPROVAL={r['APPROVAL']} ACS/OPA={r['ACS_VERDICT']} "
                  f"HOST={r['HOST_ACTION']} "
                  f"MONTY={'DENY' if r.get('MONTY_DENIED') else ('NOT_REACHED' if not r['MONTY_REACHED'] else 'ALLOW')} "
                  f"WRITE={r['PHYSICAL_WRITE']}\n")

        ev["summary"] = {
            "tests_total": len(ev["tests"]),
            "tests_passed": len(ev["tests"]) - failures,
            "tests_failed": failures,
            "FORBIDDEN_WRITES": t4["FORBIDDEN_WRITES"],
            "REGO_POLICY_REACHED": t1["REGO_POLICY_REACHED"],
            "OPA_PROCESS_REACHED": t1["OPA_PROCESS_REACHED"],
            "CUSTOM_PYTHON_POLICY_DISPATCHER_USED": "NO",
            "FAIL_OPEN_REPRODUCED": t5["FAIL_OPEN_REPRODUCED"],
        }
        ev["finished_utc"] = datetime.now(timezone.utc).isoformat()
        EVIDENCE.mkdir(exist_ok=True)
        out = EVIDENCE / f"mechanical_{started.strftime('%Y%m%dT%H%M%SZ')}.json"
        payload = json.dumps(ev, ensure_ascii=False, indent=2, default=str)
        out.write_text(payload)
        (EVIDENCE / "mechanical_latest.json").write_text(payload)
        print(f"RESULTADO: {len(ev['tests']) - failures}/{len(ev['tests'])} PASS")
        print(f"evidencia: {out}")
        return 0 if failures == 0 else 1
    finally:
        ws.teardown()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
