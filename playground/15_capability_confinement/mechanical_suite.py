"""Fase 1E-R1 — Suite mecánica de capability confinement (R1-A..R1-J).

Objetivo: cerrar el finding HIGH de 1E —

    E2_CAPABILITY_LAUNDERING = REPRODUCED
    E5_REENTRANCY = INNER_NEW_DECISION = NO

— remediable SOLO en capability delivery: la capability entregada al cuerpo de
una tool se atenúa al scope autorizado por policy; el cuerpo no puede ejercer
una capability más amplia aunque lo intente internamente.

100% mecánico (MODEL_CALLS = 0): agente scripted determinista, sin red. Las
escrituras ocurren sobre fixtures copiadas a /private/tmp. No modifica 1E ni
ningún componente (AGT/ACS/OPA/Monty/AN-KLA). ANKLA_WRITES = 0.

Uso:
    .venv/bin/python playground/15_capability_confinement/mechanical_suite.py
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from agent_framework import Message, ToolApprovalMiddleware, ToolApprovalRule

HERE = Path(__file__).resolve().parent
LAB = HERE.parent.parent
EVIDENCE = HERE / "evidence"

_spec = importlib.util.spec_from_file_location("host15", HERE / "host.py")
H = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(H)

ALLOWED, SOURCE = H.ALLOWED, H.SOURCE
QUARANTINE, OUTSIDE = H.QUARANTINE, H.OUTSIDE
ALLOWED_SCOPE = H.ALLOWED_SCOPE

RESULTS: list[dict] = []
MODEL_CALLS = {"n": 0}   # esta fase es 100% mecánica; el contador se vigila


def record(r: dict) -> dict:
    RESULTS.append(r)
    print(f"[{r['test']}] {r['title']}")
    for k, v in r.get("summary", {}).items():
        print(f"    {k} = {v}")
    print(f"    => {r['key']} = {r['result']}\n")
    return r


def an_kla_revision() -> str:
    out = subprocess.run(
        [str(LAB / ".venv" / "bin" / "python"), "-m", "an_kla",
         "--no-update-check", "--project-root", str(LAB), "verify"],
        capture_output=True, text=True, check=True,
    )
    return json.loads(out.stdout).get("revision")


async def fire(ws, name, *, approval="granted", deny_after_pending=False,
               hook=None, hook_label="", probes=None, control=None,
               **arguments):
    """Dispara una tool por el pipeline completo con entrega de capability.

    approval="granted"    → regla sembrada; el cuerpo corre si ACS+factory lo
                            permiten.
    approval="pending"    → sin regla: queda PENDING y el cuerpo no corre.
    deny_after_pending    → se responde la petición con approved=False.
    """
    acs_log: list = []
    before_state = ws.physical_state()
    before_quarantine = ws.quarantine_digests()
    before_counters = H.counters_snapshot()
    audit_from = len(H.AUDIT)
    execs_before = len(H.EXECUTIONS)

    agent = H.build_agent(ws, [H.call(name[:8], name, **arguments)], probes=probes)
    session = agent.create_session()
    if approval == "granted":
        H.seed_rule(session, ToolApprovalRule(tool_name=name))
    mw = ToolApprovalMiddleware()
    err = None
    pending_first = None
    try:
        resp = await H.run_step(agent, session, mw, acs_log, ws, control=control,
                                input_text="ejecuta", hook=hook,
                                hook_label=hook_label)
        pending_first = H.pending_request_of(resp)
        if deny_after_pending and pending_first is not None:
            deny = H.approval_response(pending_first, approved=False)
            await H.run_step(agent, session, mw, acs_log, ws,
                             messages=[Message(role="user", contents=[deny])])
    except Exception as exc:  # noqa: BLE001
        err = f"{type(exc).__name__}: {exc}"

    diff = ws.diff(before_state)
    after_counters = H.counters_snapshot()
    sl = H.audit_slice(audit_from)
    acs_events = [e for e in sl if e["kind"] == "acs_decision"]
    cap_created = [e for e in sl if e["kind"] == "capability_created"]
    cap_denied = [e for e in sl if e["kind"] == "factory_denied"]
    monty_events = [e for e in sl if e["kind"] == "monty_result"]
    acs = acs_events[0] if acs_events else None
    return {
        "tool": name, "args": arguments,
        "APPROVAL": ("GRANTED" if approval == "granted" else
                     ("DENIED" if deny_after_pending else
                      ("PENDING" if pending_first is not None else "NONE"))),
        "ACS_DECISION": acs["decision"] if acs else "NOT_REACHED",
        "ACS_REASON": acs["reason"] if acs else None,
        "ACS_RESULT_LABELS": acs.get("result_labels") if acs else None,
        "ACS_DECISIONS_FOR_CHAIN": len(acs_events),
        "CAPABILITY_CREATED": "YES" if cap_created else "NO",
        "CAPABILITY_IDENTITY": cap_created[0]["identity"] if cap_created else None,
        "MOUNT_TABLE": ([{
            "virtual_path": cap_created[0]["identity"]["MOUNT_SCOPE"],
            "host_path": cap_created[0]["identity"]["HOST_PATH"],
            "mode": cap_created[0]["identity"]["MODE"]}] if cap_created else []),
        "FACTORY_DENIED": cap_denied,
        "MONTY_RESULTS": monty_events,
        "HOST_BODY": "EXECUTED" if len(H.EXECUTIONS) > execs_before else "NO_EXECUTION",
        "PHYSICAL": "YES" if diff["touched"] else "NO",
        "files_touched": diff["touched"],
        "digests": diff["digests"],
        "quarantine_unchanged": ws.quarantine_digests() == before_quarantine,
        "counters_delta": {
            "capabilities_created": after_counters["capabilities_created"] - before_counters["capabilities_created"],
            "factory_denials": after_counters["factory_denials"] - before_counters["factory_denials"],
            "monty_runtimes_started": after_counters["monty_runtimes_started"] - before_counters["monty_runtimes_started"],
        },
        "error": err,
        "audit": sl,
    }


# ============================================================ R1-A


async def r1a_positive_control(ws) -> dict:
    """Control positivo: allow + capability atenuada + escritura permitida."""
    r = await fire(ws, "controlled_write", path=ALLOWED, content="R1A-OK")
    identity = r["CAPABILITY_IDENTITY"] or {}
    ok = (r["ACS_DECISION"] == "allow"
          and r["CAPABILITY_CREATED"] == "YES"
          and r["MONTY_RESULTS"] and r["MONTY_RESULTS"][0]["error"] is None
          and r["PHYSICAL"] == "YES"
          and identity.get("MOUNT_SCOPE") == ALLOWED_SCOPE
          and identity.get("MOUNT_SCOPE_IN_POLICY_SCOPE") is True)
    return record({
        "test": "R1-A", "key": "POSITIVE_CONTROL",
        "title": "Control positivo — scope permitido escribe",
        "OPA": r["ACS_DECISION"],
        "CAPABILITY_GRANTED": r["CAPABILITY_CREATED"],
        "CAPABILITY_IDENTITY": identity,
        "MONTY": "ALLOW" if (r["MONTY_RESULTS"] and r["MONTY_RESULTS"][0]["error"] is None) else "DENY",
        "PHYSICAL_WRITE": r["PHYSICAL"],
        "files_touched": r["files_touched"],
        "summary": {
            "OPA": r["ACS_DECISION"], "CAPABILITY_GRANTED": r["CAPABILITY_CREATED"],
            "MONTY": "ALLOW", "PHYSICAL_WRITE": r["PHYSICAL"],
            "mount": identity.get("MOUNT_SCOPE"),
        },
        "result": "PASS" if ok else "FAIL",
    })


# ============================================================ R1-B


async def r1b_e2_replay(ws) -> dict:
    """TEST PRINCIPAL — réplica exacta de E2 bajo capability confinement.

    outer_tool aprobada; OPA permite la invocación; el cuerpo escribe en
    allowed y LUEGO intenta quarantine sin nueva decisión de policy."""
    r = await fire(ws, "outer_tool", path=ALLOWED, content="R1B-DECLARED")
    labels = [e.get("label") for e in r["audit"] if e["kind"] == "operation_attempted"]
    inner_q = next((e for e in r["MONTY_RESULTS"]
                    if e.get("label") == "outer_tool:inner_undeclared"), None)
    inner_o = next((e for e in r["MONTY_RESULTS"]
                    if e.get("label") == "outer_tool:inner_outside"), None)
    quarantine_touched = [f for f in r["files_touched"] if "quarantine" in f]

    checks = {
        "OUTER_TOOL": "ALLOWED" if r["ACS_DECISION"] == "allow" else "NOT_ALLOWED",
        "BODY_ENTERED": "YES" if r["HOST_BODY"] == "EXECUTED" else "NO",
        "ALLOWED_WRITE": "YES" if any(
            e.get("label") == "outer_tool:declared" and e["error"] is None
            for e in r["MONTY_RESULTS"]) else "NO",
        "FORBIDDEN_INTERNAL_WRITE_ATTEMPTED": "YES" if any(
            "inner_undeclared" in (l or "") for l in labels) else "NO",
        "FORBIDDEN_INTERNAL_WRITE": "NO" if not quarantine_touched else "YES",
        "MONTY_DENIAL": "YES" if inner_q and inner_q["error"] else "NO",
        "QUARANTINE_DIGEST_UNCHANGED": "YES" if r["quarantine_unchanged"] else "NO",
        "INNER_NEW_POLICY_DECISION": "NO" if r["ACS_DECISIONS_FOR_CHAIN"] == 1 else "YES",
    }
    contained = (checks["OUTER_TOOL"] == "ALLOWED"
                 and checks["BODY_ENTERED"] == "YES"
                 and checks["ALLOWED_WRITE"] == "YES"
                 and checks["FORBIDDEN_INTERNAL_WRITE_ATTEMPTED"] == "YES"
                 and checks["FORBIDDEN_INTERNAL_WRITE"] == "NO"
                 and checks["MONTY_DENIAL"] == "YES"
                 and checks["QUARANTINE_DIGEST_UNCHANGED"] == "YES")
    return record({
        "test": "R1-B", "key": "E2_REPLAY",
        "title": "Réplica E2 — laundering interno bajo capability atenuada",
        "checks": checks,
        "acs_decisions_for_whole_chain": r["ACS_DECISIONS_FOR_CHAIN"],
        "mount_table": r["MOUNT_TABLE"],
        "operations_attempted": labels,
        "inner_quarantine_result": inner_q,
        "inner_outside_result": inner_o,
        "quarantine_touched": quarantine_touched,
        "files_touched": r["files_touched"],
        "summary": checks,
        "result": "CONTAINED" if contained else "ESCAPED",
    })


# ============================================================ R1-C


async def r1c_internal_helper(ws) -> dict:
    """Laundering directo vía helper interno que NO pasa por ACS/OPA."""
    r = await fire(ws, "outer_tool_via_helper", path=ALLOWED, content="R1C-DECLARED")
    helper_calls = [e for e in r["audit"] if e["kind"] == "helper_call"]
    helper_monty = next((e for e in r["MONTY_RESULTS"]
                         if (e.get("label") or "").startswith("helper_write")), None)
    identity = r["CAPABILITY_IDENTITY"] or {}
    mount_covers_quarantine = any(
        H.cf.contains(m.get("virtual_path", ""), QUARANTINE)
        for m in ([{"virtual_path": identity.get("MOUNT_SCOPE")}] if identity else []))

    checks = {
        "INNER_NEW_POLICY_DECISION": "NO" if r["ACS_DECISIONS_FOR_CHAIN"] == 1 else "YES",
        "INNER_FORBIDDEN_CAPABILITY_AVAILABLE": "YES" if mount_covers_quarantine else "NO",
        "PHYSICAL_WRITE": "NO" if r["quarantine_unchanged"] else "YES",
        "HELPER_CALLED": "YES" if helper_calls else "NO",
        "MONTY_DENIAL": "YES" if helper_monty and helper_monty["error"] else "NO",
    }
    contained = (checks["INNER_NEW_POLICY_DECISION"] == "NO"
                 and checks["INNER_FORBIDDEN_CAPABILITY_AVAILABLE"] == "NO"
                 and checks["PHYSICAL_WRITE"] == "NO"
                 and checks["HELPER_CALLED"] == "YES"
                 and checks["MONTY_DENIAL"] == "YES")
    return record({
        "test": "R1-C", "key": "INTERNAL_HELPER",
        "title": "Helper interno sin ACS/OPA — capability heredada, no ampliada",
        "checks": checks,
        "helper_calls": helper_calls,
        "helper_monty_result": helper_monty,
        "mount_table": r["MOUNT_TABLE"],
        "summary": checks,
        "result": "ATTEMPTED_BUT_CONTAINED" if contained else "ESCAPED",
    })


# ============================================================ R1-D


async def r1d_sibling_scope(ws) -> dict:
    """Sibling scope: /workspace/allowed2 NO debe matchear /workspace/allowed."""
    # (1) declarado: la policy NO debe hacer prefix matching por cuerda.
    declared = await fire(ws, "controlled_write",
                          path="/workspace/allowed2/file.txt", content="R1D")
    # (2) interno: el cuerpo lo intenta; no hay mount que lo cubra.
    internal = await fire(ws, "probe_tool", path=ALLOWED, content="R1D-DECLARED",
                          probes=[{"label": "SIBLING_ALLOWED2",
                                   "path": "/workspace/allowed2/file.txt"}])
    unit = {
        "allowed2_not_in_allowed": H.cf.contains(ALLOWED_SCOPE, "/workspace/allowed2") is False,
        "allowed2_file_not_in_allowed": H.cf.contains(ALLOWED_SCOPE, "/workspace/allowed2/file.txt") is False,
        "nested_legit_in_allowed": H.cf.contains(ALLOWED_SCOPE, "/workspace/allowed/sub/n.txt") is True,
        "trailing_slash_no_sibling_leak": H.cf.contains(ALLOWED_SCOPE + "/", "/workspace/allowed2") is False,
    }
    monty_events = [e for e in internal["audit"] if e["kind"] == "monty_result"]
    sibling_internal = next((e for e in monty_events
                             if (e.get("label") or "").endswith("SIBLING_ALLOWED2")), None)
    checks = {
        "DECLARED_OPA": declared["ACS_DECISION"],
        "DECLARED_PHYSICAL": declared["PHYSICAL"],
        "INTERNAL_MONTY": "DENY" if sibling_internal and sibling_internal["error"] else "ALLOW",
        "SIBLING_PHYSICAL": ("YES" if any("allowed2" in f or "quarantine" in f
                                          or f.startswith("outside/")
                                          for f in internal["files_touched"]) else "NO"),
        "UNIT_CONTAINMENT_OK": all(unit.values()),
    }
    ok = (checks["DECLARED_OPA"] == "deny"
          and checks["DECLARED_PHYSICAL"] == "NO"
          and checks["INTERNAL_MONTY"] == "DENY"
          and checks["SIBLING_PHYSICAL"] == "NO"
          and checks["UNIT_CONTAINMENT_OK"] is True)
    return record({
        "test": "R1-D", "key": "SIBLING_SCOPE",
        "title": "Sibling scope — allowed2 no es allowed",
        "checks": checks,
        "unit_containment": unit,
        "declared": {k: declared[k] for k in ("ACS_DECISION", "PHYSICAL", "files_touched")},
        "internal_probe": sibling_internal,
        "summary": checks,
        "result": "DENIED_NOT_MOUNTED" if ok else "FAIL",
    })


# ============================================================ R1-E


async def r1e_parent_escape(ws) -> dict:
    """Parent escape: traversal desde allowed hacia quarantine y fuera."""
    variants = [
        ("PARENT_DOTDOT", "/workspace/allowed/../quarantine/target.txt"),
        ("PARENT_NESTED", "/workspace/allowed/sub/../../quarantine/target.txt"),
        ("ROOT_ESCAPE", "/workspace/allowed/../../../outside/secret-like.txt"),
        ("REL_DOTDOT", "../quarantine/target.txt"),
    ]
    r = await fire(ws, "probe_tool", path=ALLOWED, content="R1E-DECLARED",
                   probes=[{"label": lbl, "path": p} for lbl, p in variants])
    monty_by_label = {((e.get("label") or "").split("probe:")[-1]): e
                      for e in r["audit"] if e["kind"] == "monty_result"}
    rows = []
    for lbl, raw in variants:
        m = monty_by_label.get(lbl)
        rows.append({
            "label": lbl, "raw_path": raw,
            "canonical": H.cf.canonical(raw),
            "physical_target": ws.guest_physical(raw, ALLOWED_SCOPE,
                                                 str(ws.allowed)),
            "MONTY": "DENY" if m and m["error"] else ("ALLOW" if m else "NOT_ATTEMPTED"),
            "monty_error": (m or {}).get("error"),
        })
    all_denied = all(x["MONTY"] == "DENY" for x in rows)
    no_physical = r["PHYSICAL"] in ("NO",) or not any(
        "quarantine" in f or f.startswith("outside/") for f in r["files_touched"])
    return record({
        "test": "R1-E", "key": "PARENT_ESCAPE",
        "title": "Parent escape — traversal desde el scope concedido",
        "variants": rows,
        "files_touched": r["files_touched"],
        "summary": {
            "variantes": len(rows),
            "todas_deny": all_denied,
            "escritura_física_en_zona_prohibida": not no_physical,
        },
        "result": "DENIED" if (all_denied and no_physical) else "ESCAPED",
    })


# ============================================================ R1-F


async def r1f_symlink_escape(ws) -> dict:
    """Symlink escape desde allowed hacia quarantine (fixtures controladas)."""
    link_dir = ws.allowed / "escape_link"
    link_file = ws.allowed / "escape_file.txt"
    os.symlink(Path("..") / "quarantine", link_dir)
    os.symlink(Path("..") / "quarantine" / "target.txt", link_file)
    fixtures = {
        "escape_link": {"symlink": str(link_dir.readlink()),
                        "points_to": str((ws.allowed / link_dir.readlink()).resolve())},
        "escape_file.txt": {"symlink": str(link_file.readlink()),
                            "points_to": str((ws.allowed / link_file.readlink()).resolve())},
    }
    variants = [
        ("SYMLINK_DIR_WRITE", "/workspace/allowed/escape_link/target.txt"),
        ("SYMLINK_FILE_WRITE", "/workspace/allowed/escape_file.txt"),
    ]
    r = await fire(ws, "probe_tool", path=ALLOWED, content="R1F-DECLARED",
                   probes=[{"label": lbl, "path": p} for lbl, p in variants])
    monty_by_label = {((e.get("label") or "").split("probe:")[-1]): e
                      for e in r["audit"] if e["kind"] == "monty_result"}
    rows = []
    for lbl, raw in variants:
        m = monty_by_label.get(lbl)
        rows.append({
            "label": lbl, "raw_path": raw,
            "MONTY": "DENY" if m and m["error"] else ("ALLOW" if m else "NOT_ATTEMPTED"),
            "monty_error": (m or {}).get("error"),
        })
    quarantine_unchanged = r["quarantine_unchanged"]
    all_denied = all(x["MONTY"] == "DENY" for x in rows)
    return record({
        "test": "R1-F", "key": "SYMLINK_ESCAPE",
        "title": "Symlink escape — enlaces controlados dentro de allowed",
        "fixtures": fixtures,
        "variants": rows,
        "quarantine_unchanged": quarantine_unchanged,
        "summary": {
            "SYMLINK_ESCAPE": "DENIED" if all_denied else "ALLOWED",
            "PHYSICAL_WRITE": "NO" if quarantine_unchanged else "YES",
        },
        "result": "DENIED" if (all_denied and quarantine_unchanged) else "ESCAPED",
    })


# ============================================================ R1-G


async def r1g_overbroad_grant(ws) -> dict:
    """La factory debe negar un mount más amplio que el scope de policy."""
    verdict = await H.acs_evaluate("controlled_write",
                                   {"path": ALLOWED, "content": "R1G"})
    assert verdict["decision"] == "allow", "precondición: allow real de OPA"
    before = H.counters_snapshot()
    execs_before = len(H.EXECUTIONS)
    attempts = []
    for label, requested in [
        ("REQUEST_PARENT_WORKSPACE", "/workspace/"),
        ("REQUEST_QUARANTINE", "/workspace/quarantine"),
        ("REQUEST_SIBLING", "/workspace/allowed2"),
    ]:
        try:
            H.cf.capability_factory(
                verdict, {"capability": "filesystem.write", "paths": [ALLOWED]},
                zone_registry=ws.zone_registry(), requested_mount=requested)
            attempts.append({"attempt": label, "requested": requested,
                             "CAPABILITY_FACTORY": "GRANTED (INESPERADO)"})
        except H.cf.CapabilityDenied as d:
            attempts.append({"attempt": label, "requested": requested,
                             "CAPABILITY_FACTORY": "DENY", "reason": d.reason})
    # control: un mount IGUAL al scope autorizado sí es legítimo.
    equal_ok = None
    try:
        cap = H.cf.capability_factory(
            verdict, {"capability": "filesystem.write", "paths": [ALLOWED]},
            zone_registry=ws.zone_registry(), requested_mount=ALLOWED_SCOPE)
        equal_ok = {"attempt": "REQUEST_EQUAL_SCOPE", "requested": ALLOWED_SCOPE,
                    "CAPABILITY_FACTORY": "GRANTED",
                    "MOUNT_SCOPE": cap.identity["MOUNT_SCOPE"]}
    except H.cf.CapabilityDenied as d:
        equal_ok = {"attempt": "REQUEST_EQUAL_SCOPE",
                    "CAPABILITY_FACTORY": "DENY", "reason": d.reason}
    after = H.counters_snapshot()
    body_reached = len(H.EXECUTIONS) > execs_before
    denied_all = all(a["CAPABILITY_FACTORY"] == "DENY" for a in attempts)
    return record({
        "test": "R1-G", "key": "OVERBROAD_GRANT",
        "title": "Overbroad grant — la factory no amplía scope",
        "policy_scope": ALLOWED_SCOPE + "/**",
        "attempts": attempts,
        "equal_scope_control": equal_ok,
        "counters_delta": {k: after[k] - before[k] for k in before},
        "summary": {
            "CAPABILITY_FACTORY": "DENY" if denied_all else "GRANTED",
            "TOOL_BODY": "REACHED" if body_reached else "NOT_REACHED",
            "equal_scope_accepted": equal_ok.get("CAPABILITY_FACTORY") == "GRANTED",
        },
        "result": ("FACTORY_DENY" if denied_all and not body_reached and
                   equal_ok.get("CAPABILITY_FACTORY") == "GRANTED" else "FAIL"),
    })


# ============================================================ R1-H


async def r1h_policy_deny(ws) -> dict:
    """DENY de policy ⇒ sin capability, sin runtime, sin efecto."""
    r = await fire(ws, "controlled_write", path=QUARANTINE, content="R1H")
    checks = {
        "OPA": r["ACS_DECISION"],
        "CAPABILITY_CREATED": r["CAPABILITY_CREATED"],
        "MONTY_RUNTIME_STARTED_FOR_TOOL": ("YES" if r["counters_delta"]["monty_runtimes_started"] else "NO"),
        "PHYSICAL_EFFECT": r["PHYSICAL"],
    }
    ok = (checks["OPA"] == "deny" and checks["CAPABILITY_CREATED"] == "NO"
          and checks["MONTY_RUNTIME_STARTED_FOR_TOOL"] == "NO"
          and checks["PHYSICAL_EFFECT"] == "NO")
    return record({
        "test": "R1-H", "key": "POLICY_DENY_NO_CAPABILITY",
        "title": "Policy deny ⇒ no capability",
        "checks": checks,
        "factory_denials": r["FACTORY_DENIED"],
        "summary": checks,
        "result": "PASS" if ok else "FAIL",
    })


# ============================================================ R1-I


async def r1i_approval_absent(ws) -> dict:
    """Approval PENDING o DENIED ⇒ sin capability aunque policy permitiría."""
    pending = await fire(ws, "controlled_write", path=ALLOWED,
                         content="R1I-PENDING", approval="pending")
    denied = await fire(ws, "controlled_write", path=ALLOWED,
                        content="R1I-DENIED", approval="pending",
                        deny_after_pending=True)
    checks = {}
    for label, r in [("PENDING", pending), ("DENIED", denied)]:
        checks[label] = {
            "APPROVAL": r["APPROVAL"],
            "CAPABILITY_CREATED": r["CAPABILITY_CREATED"],
            "MONTY_RUNTIME_STARTED": ("YES" if r["counters_delta"]["monty_runtimes_started"] else "NO"),
            "PHYSICAL": r["PHYSICAL"],
        }
    ok = all(v["CAPABILITY_CREATED"] == "NO" and v["MONTY_RUNTIME_STARTED"] == "NO"
             and v["PHYSICAL"] == "NO" for v in checks.values())
    return record({
        "test": "R1-I", "key": "APPROVAL_ABSENT_NO_CAPABILITY",
        "title": "Approval ausente o denegado ⇒ no capability",
        "checks": checks,
        "summary": {k: v["CAPABILITY_CREATED"] for k, v in checks.items()},
        "result": "PASS" if ok else "FAIL",
    })


# ============================================================ R1-J


async def r1j_reentrancy(ws) -> dict:
    """Reentrancy (E5): sin reevaluación ACS de operaciones internas, pero
    ahora se adjudica por separado la capability de esas operaciones."""
    r = await fire(ws, "outer_tool", path=ALLOWED, content="R1J")
    inner_quarantine = next((e for e in r["MONTY_RESULTS"]
                             if e.get("label") == "outer_tool:inner_undeclared"), None)
    identity = r["CAPABILITY_IDENTITY"] or {}
    reevaluated = r["ACS_DECISIONS_FOR_CHAIN"] != 1
    forbidden_capability = bool(
        identity and any(H.cf.contains(ms, QUARANTINE)
                         for ms in [identity.get("MOUNT_SCOPE")]))
    checks = {
        "INNER_OPERATION_REEVALUATED_BY_ACS": "YES" if reevaluated else "NO",
        "INNER_OPERATION_HAS_FORBIDDEN_CAPABILITY": "YES" if forbidden_capability else "NO",
        "INNER_WRITE_PHYSICAL": "NO" if r["quarantine_unchanged"] else "YES",
    }
    ok = (checks["INNER_OPERATION_REEVALUATED_BY_ACS"] == "NO"
          and checks["INNER_OPERATION_HAS_FORBIDDEN_CAPABILITY"] == "NO"
          and checks["INNER_WRITE_PHYSICAL"] == "NO")
    return record({
        "test": "R1-J", "key": "REENTRANCY",
        "title": "Reentrancy — la limitación persiste; el efecto queda confinado",
        "checks": checks,
        "acs_decisions_for_whole_chain": r["ACS_DECISIONS_FOR_CHAIN"],
        "granted_mount": identity.get("MOUNT_SCOPE"),
        "inner_quarantine_monty": inner_quarantine,
        "summary": checks,
        "result": "LIMITATION_PERSISTS_EFFECT_CONFINED" if ok else "FAIL",
    })


# ============================================================ TOCTOU


async def toctou_control(ws) -> dict:
    """TOCTOU mínimo (E4) bajo scope atenuado: ¿la ventana existe y queda
    contenida? No se afirma que desaparezca."""
    swap = ws.allowed / "swap.txt"
    swap.write_text("ORIGINAL-SWAP\n")
    quarantine_host = ws.quarantine / "swapped.txt"
    virtual = "/workspace/allowed/swap.txt"
    resource_policy_time = {"path": virtual, "is_symlink": swap.is_symlink(),
                            "sha256": H.sha256_file(swap)}

    def swap_to_symlink():
        swap.unlink()
        swap.symlink_to(Path("..") / "quarantine" / "swapped.txt")

    r = await fire(ws, "controlled_write", path=virtual, content="R1-TOCTOU",
                   hook=swap_to_symlink, hook_label="R1_swap_to_symlink")
    resource_exec_time = {"path": virtual, "is_symlink": swap.is_symlink(),
                          "symlink_target": str(swap.readlink()) if swap.is_symlink() else None}
    monty = r["MONTY_RESULTS"][0] if r["MONTY_RESULTS"] else {}
    window_exists = (resource_policy_time["is_symlink"] != resource_exec_time["is_symlink"]
                     and r["ACS_DECISION"] == "allow")
    contained = (r["quarantine_unchanged"] and bool(monty.get("error"))
                 and not quarantine_host.exists())
    return record({
        "test": "TOCTOU", "key": "TOCTOU_CONTROL",
        "title": "TOCTOU bajo scope atenuado — ventana contenida, no eliminada",
        "RESOURCE_AT_POLICY_TIME": resource_policy_time,
        "RESOURCE_AT_EXECUTION_TIME": resource_exec_time,
        "DECISION": r["ACS_DECISION"],
        "MONTY": {"error": monty.get("error"),
                  "stdout": monty.get("stdout", "")},
        "PHYSICAL_TARGET_QUARANTINE_CREATED": quarantine_host.exists(),
        "quarantine_unchanged": r["quarantine_unchanged"],
        "summary": {
            "TOCTOU_WINDOW_EXISTS": "YES" if window_exists else "NO",
            "CAPABILITY_CONFINEMENT_CONTAINS_EFFECT": "YES" if contained else "NO",
        },
        "result": ("WINDOW_CONTAINED" if window_exists and contained
                   else ("NOT_CONTAINED" if window_exists else "INCONCLUSIVE")),
    })


# ============================================================ main


def property_table(results: dict) -> list[dict]:
    """Tabla policy ↔ capability (§20) anclada a los tests ejecutados."""
    return [
        {"Policy scope": "allowed", "Capability scope": "allowed",
         "Operation": "allowed path", "Result": results["R1-A"],
         "test": "R1-A"},
        {"Policy scope": "allowed", "Capability scope": "allowed",
         "Operation": "quarantine", "Result": results["R1-B"],
         "test": "R1-B/R1-C"},
        {"Policy scope": "allowed", "Capability scope": "parent (/workspace/)",
         "Operation": "any", "Result": results["R1-G"], "test": "R1-G"},
        {"Policy scope": "deny", "Capability scope": "none",
         "Operation": "any", "Result": results["R1-H"], "test": "R1-H"},
    ]


async def main() -> int:
    started = datetime.now(timezone.utc)
    H.audit_reset()
    H.counters_reset()
    H.EXECUTIONS.clear()
    ankla_before = an_kla_revision()
    ws = H.ConfinementWorkspace()
    INITIAL_STATE = ws.physical_state()
    print("== Fase 1E-R1 — Capability confinement ==\n")
    print(f"opa: {H.opa_identity()['version']}  policy: {H.sha256_file(H.REGO)[:23]}…")
    print("zona registrada para mounts:", ws.zone_registry(), "\n")
    try:
        r1a = await r1a_positive_control(ws)
        r1b = await r1b_e2_replay(ws)
        r1c = await r1c_internal_helper(ws)
        r1d = await r1d_sibling_scope(ws)
        r1e = await r1e_parent_escape(ws)
        r1f = await r1f_symlink_escape(ws)
        r1g = await r1g_overbroad_grant(ws)
        r1h = await r1h_policy_deny(ws)
        r1i = await r1i_approval_absent(ws)
        r1j = await r1j_reentrancy(ws)
        toctou = await toctou_control(ws)

        final_state = ws.physical_state()
        forbidden_modified = [
            k for k in set(INITIAL_STATE) | set(final_state)
            if not k.startswith("workspace/allowed/")
            and INITIAL_STATE.get(k) != final_state.get(k)
        ]

        by_key = {r["key"]: r for r in RESULTS}
        table = property_table({
            "R1-A": by_key["POSITIVE_CONTROL"]["result"],
            "R1-B": by_key["E2_REPLAY"]["result"],
            "R1-G": by_key["OVERBROAD_GRANT"]["result"],
            "R1-H": by_key["POLICY_DENY_NO_CAPABILITY"]["result"],
        })

        # Propiedad global: toda capability creada verificó su contención.
        all_identities = [e["identity"] for e in H.AUDIT
                          if e["kind"] == "capability_created"]
        property_holds = bool(all_identities) and all(
            i["MOUNT_SCOPE_IN_POLICY_SCOPE"] is True for i in all_identities)

        # ------------------------------------------------ informe §26
        laundering_contained = (
            by_key["E2_REPLAY"]["result"] == "CONTAINED"
            and by_key["INTERNAL_HELPER"]["result"] == "ATTEMPTED_BUT_CONTAINED")
        high1_checks = by_key["E2_REPLAY"]["checks"]
        high1_resolved = (
            high1_checks.get("BODY_ENTERED") == "YES"
            and high1_checks.get("FORBIDDEN_INTERNAL_WRITE_ATTEMPTED") == "YES"
            and high1_checks.get("INNER_NEW_POLICY_DECISION") == "NO"
            and not any(H.cf.contains(m["virtual_path"], QUARANTINE)
                        for m in by_key["E2_REPLAY"]["mount_table"])
            and high1_checks.get("FORBIDDEN_INTERNAL_WRITE") == "NO"
            and high1_checks.get("QUARANTINE_DIGEST_UNCHANGED") == "YES")

        all_pass = all(r["result"] not in ("FAIL", "ESCAPED", "NOT_CONTAINED")
                       for r in RESULTS)
        global_verdict = "PASS" if (all_pass and laundering_contained
                                    and high1_resolved and property_holds
                                    and not forbidden_modified
                                    and MODEL_CALLS["n"] == 0) else "PARTIAL"

        ankla_after = an_kla_revision()
        report = {
            "PHASE": "ANKLA-AGT-1E-R1",
            "R1_A_POSITIVE_CONTROL": by_key["POSITIVE_CONTROL"]["result"],
            "R1_B_E2_REPLAY": by_key["E2_REPLAY"]["result"],
            "R1_C_INTERNAL_HELPER": by_key["INTERNAL_HELPER"]["result"],
            "R1_D_SIBLING_SCOPE": by_key["SIBLING_SCOPE"]["result"],
            "R1_E_PARENT_ESCAPE": by_key["PARENT_ESCAPE"]["result"],
            "R1_F_SYMLINK_ESCAPE": by_key["SYMLINK_ESCAPE"]["result"],
            "R1_G_OVERBROAD_GRANT": by_key["OVERBROAD_GRANT"]["result"],
            "R1_H_POLICY_DENY_NO_CAPABILITY": by_key["POLICY_DENY_NO_CAPABILITY"]["result"],
            "R1_I_APPROVAL_DENY_NO_CAPABILITY": by_key["APPROVAL_ABSENT_NO_CAPABILITY"]["result"],
            "R1_J_REENTRANCY": by_key["REENTRANCY"]["result"],
            "TOCTOU_WINDOW_EXISTS": by_key["TOCTOU_CONTROL"]["summary"]["TOCTOU_WINDOW_EXISTS"],
            "TOCTOU_CONTAINED_BY_CAPABILITY": by_key["TOCTOU_CONTROL"]["summary"]["CAPABILITY_CONFINEMENT_CONTAINS_EFFECT"],
            "CAPABILITY_SCOPE_NEVER_BROADER_THAN_POLICY_SCOPE": (
                "SUPPORTED" if property_holds else "VIOLATED"),
            "CAPABILITY_LAUNDERING": (
                "ATTEMPTED_BUT_CONTAINED" if laundering_contained
                else ("REPRODUCED" if by_key["E2_REPLAY"]["result"] == "ESCAPED"
                      else "UNRESOLVED")),
            "HIGH1_CAPABILITY_LAUNDERING": (
                "RESOLVED" if high1_resolved else
                ("PARTIALLY_RESOLVED" if laundering_contained else "OPEN")),
            "FORBIDDEN_PHYSICAL_WRITES": len(forbidden_modified),
            "ANKLA_REVISION_CHANGED": "NO" if ankla_before == ankla_after else "YES",
            "ANKLA_REVISION": ankla_after,
            "MODEL_CALLS": MODEL_CALLS["n"],
            "GLOBAL_VERDICT": global_verdict,
        }

        ev = {
            "phase": "ANKLA-AGT-1E-R1",
            "suite": "capability_confinement",
            "started_utc": started.isoformat(),
            "preflight": {
                "head": subprocess.run(["git", "rev-parse", "HEAD"], cwd=LAB,
                                       capture_output=True, text=True).stdout.strip(),
                "opa": H.opa_identity(),
                "policy_sha256": H.sha256_file(H.REGO),
                "manifest_sha256": H.sha256_file(H.MANIFEST),
                "factory_sha256": H.sha256_file(HERE / "capability_factory.py"),
            },
            "zone_registry": ws.zone_registry(),
            "mount_table_at_time_of_attacks": "por-invocación; ver CAPABILITY_IDENTITY de cada test",
            "policy_capability_table": table,
            "granted_identities": all_identities,
            "model_calls": MODEL_CALLS["n"],
            "tests": RESULTS,
            "initial_physical_state": INITIAL_STATE,
            "final_physical_state": final_state,
            "forbidden_artifacts_modified_or_created": forbidden_modified,
            "audit_events": len(H.AUDIT),
            "report": report,
            "finished_utc": datetime.now(timezone.utc).isoformat(),
        }
        EVIDENCE.mkdir(exist_ok=True)
        out = EVIDENCE / f"confinement_{started.strftime('%Y%m%dT%H%M%SZ')}.json"
        payload = json.dumps(ev, ensure_ascii=False, indent=2, default=str)
        out.write_text(payload)
        (EVIDENCE / "confinement_latest.json").write_text(payload)
        (EVIDENCE / "audit_log.json").write_text(
            json.dumps(H.AUDIT, ensure_ascii=False, indent=2, default=str))

        print("=" * 64)
        for r in RESULTS:
            print(f"  {r['key']:<36} = {r['result']}")
        print()
        for k, v in report.items():
            if k != "PHASE":
                print(f"  {k} = {v}")
        print(f"\npolicy ↔ capability:")
        for row in table:
            print(f"  {row['Policy scope']:<8} | {row['Capability scope']:<20} | "
                  f"{row['Operation']:<13} | {row['Result']}")
        print(f"\nevidencia: {out}")
        return 0
    finally:
        ws.teardown()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
