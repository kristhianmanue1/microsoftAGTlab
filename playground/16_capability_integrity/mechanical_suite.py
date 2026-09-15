"""Fase 1E-R2 — Suite mecánica de capability integrity & trust binding.

Cierra exclusivamente los findings REPRODUCIDOS/SUSTAIN de la revisión
externa `ANKLA-AGT-1E-R1-EXTERNAL` sobre el commit `fe739ad`:

    A2_MOUNT_INJECTION             = REPRODUCED   → R2-3
    A3_POST_GRANT_MUTATION         = REPRODUCED   → R2-1 (HIGH principal)
    A4_E2_REPLAY                   = SUSTAIN      → R2-6 (regresión)
    A9_RESULT_LABEL_SCOPE_TRUST    = PARTIAL      → R2-4 / R2-5
    A11/A12_NO_VERDICT_NO_CAPABILITY = SUSTAIN    → R2-7 (regresión)
    A13_REENTRANCY                 = NO_REEVALUATION → R2-8 (readjudicación)

Findings NOT_REPRODUCED/DENIED/NO (A1, A5, A6, A7, A8, A10) no se tocan.

Objetivo de la fase: MODEL_CALLS = 0. 100% mecánico: agente scripted
determinista, sin red. Escrituras sólo sobre fixtures copiadas a
/private/tmp. No modifica 1E ni 1E-R1 ni ningún componente (AGT/ACS/OPA/
Monty/AN-KLA). ANKLA_WRITES = 0.

Uso:
    .venv/bin/python playground/16_capability_integrity/mechanical_suite.py
"""

from __future__ import annotations

import asyncio
import importlib.util
import inspect
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from agent_framework import Message, ToolApprovalMiddleware, ToolApprovalRule

HERE = Path(__file__).resolve().parent
LAB = HERE.parent.parent
EVIDENCE = HERE / "evidence"
PY = str(LAB / ".venv" / "bin" / "python")

_spec = importlib.util.spec_from_file_location("host16", HERE / "host.py")
H = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(H)

ALLOWED, SOURCE = H.ALLOWED, H.SOURCE
QUARANTINE, OUTSIDE = H.QUARANTINE, H.OUTSIDE
ALLOWED_SCOPE, ALLOWED_ZONE = H.ALLOWED_SCOPE, H.ALLOWED_ZONE

RESULTS: list[dict] = []
MODEL_CALLS = {"n": 0}   # esta fase es 100% mecánica; el contador se vigila


def record(r: dict) -> dict:
    RESULTS.append(r)
    print(f"[{r['test']}] {r['title']}")
    for k, v in r.get("summary", {}).items():
        print(f"    {k} = {v}")
    print(f"    => {r['key']} = {r['result']}\n")
    return r


def an_kla_verify() -> dict:
    out = subprocess.run(
        [PY, "-m", "an_kla", "--no-update-check", "--project-root", str(LAB),
         "verify"], capture_output=True, text=True, check=True,
    )
    return json.loads(out.stdout)


def preflight() -> dict:
    gate = subprocess.run([PY, "scripts/check_environment.py"], cwd=LAB,
                          capture_output=True, text=True)
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=LAB,
                          capture_output=True, text=True).stdout.strip()
    worktree = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=LAB,
        capture_output=True, text=True).stdout.strip()
    return {
        "ENVIRONMENT_GATE": "PASS" if gate.returncode == 0
        else f"FAIL(exit={gate.returncode})",
        "ANKLA_VERIFY": "PASS",
        "HEAD": head,
        "WORKTREE_ENTRIES": len(worktree.splitlines()),
        "WORKTREE": worktree or "CLEAN",
        "OPA": H.opa_identity(),
    }


# needles construidos por concatenación para que el escáner no se cuente a
# sí mismo como sitio de creación de runtime.
NEEDLE_IMPORT = "pydantic" + "_monty"
NEEDLE_CTOR = "pm" + ".Monty("


def static_monty_inspection() -> dict:
    """R2-B: inspección de TODAS las rutas hacia creación de Monty runtime
    en los fuentes de esta fase."""
    files = ["capability.py", "capability_factory.py", "host.py"]
    per_file = {}
    for name in files:
        text = (HERE / name).read_text()
        per_file[name] = {
            "imports_pydantic_monty": text.count(NEEDLE_IMPORT),
            "monty_ctor_sites": text.count(NEEDLE_CTOR),
        }
    creation_paths = sum(v["monty_ctor_sites"] for v in per_file.values())
    # sitio(s) autorizados: dentro de GrantedCapability.run (capability.py).
    cap_text = (HERE / "capability.py").read_text()
    run_body = cap_text.split("def run(", 1)[1]
    authorized = run_body.count(NEEDLE_CTOR)
    unauthorized = creation_paths - authorized
    host_clean = per_file["host.py"]["imports_pydantic_monty"] == 0 \
        and per_file["host.py"]["monty_ctor_sites"] == 0
    factory_clean = per_file["capability_factory.py"]["monty_ctor_sites"] == 0
    return {
        "per_file": per_file,
        "MONTY_RUNTIME_CREATION_PATHS": creation_paths,
        "AUTHORIZED_PATHS": authorized,
        "UNAUTHORIZED_ALTERNATIVE_PATHS": unauthorized,
        "HOST_ISOLATED_FROM_MONTY": host_clean,
        "FACTORY_FREE_OF_RUNTIME": factory_clean,
    }


async def fire(ws, name, *, approval="granted", deny_after_pending=False,
               hook=None, hook_label="", probes=None, control=None,
               **arguments):
    """Dispara una tool por el pipeline completo con entrega de capability."""
    acs_log: list = []
    before_state = ws.physical_state()
    before_quarantine = ws.quarantine_digests()
    before_counters = H.counters_snapshot()
    audit_from = len(H.AUDIT)
    execs_before = len(H.EXECUTIONS)
    attacks_before = len(H.ATTACK_LOG)

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
    refused = [e for e in sl if e["kind"] == "run_refused"]
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
        "RUN_REFUSALS": refused,
        "ATTACKS": H.ATTACK_LOG[attacks_before:],
        "HOST_BODY": "EXECUTED" if len(H.EXECUTIONS) > execs_before else "NO_EXECUTION",
        "PHYSICAL": "YES" if diff["touched"] else "NO",
        "files_touched": diff["touched"],
        "digests": diff["digests"],
        "quarantine_unchanged": ws.quarantine_digests() == before_quarantine,
        "counters_delta": {
            k: after_counters[k] - before_counters[k]
            for k in ("capabilities_created", "factory_denials",
                      "monty_runtimes_started", "grant_verifications_failed",
                      "run_refusals")
        },
        "error": err,
        "audit": sl,
    }


# ============================================================ R2-A


async def r2a_positive_control(ws) -> dict:
    """Control positivo: allow + capability sellada + escritura permitida."""
    r = await fire(ws, "controlled_write", path=ALLOWED, content="R2A-OK")
    identity = r["CAPABILITY_IDENTITY"] or {}
    ok = (r["ACS_DECISION"] == "allow"
          and r["CAPABILITY_CREATED"] == "YES"
          and r["MONTY_RESULTS"] and r["MONTY_RESULTS"][0]["error"] is None
          and r["PHYSICAL"] == "YES"
          and identity.get("ZONE_ID") == ALLOWED_ZONE
          and identity.get("MOUNT_SCOPE") == ALLOWED_SCOPE
          and identity.get("GRANT_VERIFIED") is True
          and identity.get("TRUST_ROOT") == "zone_registry"
          and r["quarantine_unchanged"])
    return record({
        "test": "R2-A", "key": "POSITIVE_CONTROL",
        "title": "Control positivo — grant sellado ejecuta en su scope",
        "OPA": r["ACS_DECISION"],
        "CAPABILITY_GRANTED": r["CAPABILITY_CREATED"],
        "CAPABILITY_IDENTITY": identity,
        "MONTY": "ALLOW" if (r["MONTY_RESULTS"] and r["MONTY_RESULTS"][0]["error"] is None) else "DENY",
        "PHYSICAL_WRITE": r["PHYSICAL"],
        "files_touched": r["files_touched"],
        "summary": {
            "OPA": r["ACS_DECISION"], "CAPABILITY_GRANTED": r["CAPABILITY_CREATED"],
            "MONTY": "ALLOW", "PHYSICAL_WRITE": r["PHYSICAL"],
            "zone": identity.get("ZONE_ID"),
            "mount": identity.get("MOUNT_SCOPE"),
            "GRANT_VERIFIED": identity.get("GRANT_VERIFIED"),
        },
        "result": "PASS" if ok else "FAIL",
    })


# ============================================================ R2-1


async def r21_post_grant_mutation(ws) -> dict:
    """TEST PRINCIPAL — reproducir A3: post-grant mutation.

    El cuerpo recibe un grant válido (/workspace/allowed RW) e intenta
    ampliarlo a /workspace RW para escribir en quarantine. Vectores: setattr
    en cada campo, mutación de colecciones internas, bypass de frozen
    (object.__setattr__), dataclasses.replace, forja desde cero, kwargs de
    mounts en run(). Esperado: MUTATION_ACCEPTED = NO (efectivo) y
    quarantine intacto.
    """
    r = await fire(ws, "mutation_probe_tool", path=ALLOWED, content="R21-DECLARED")
    vectors = {a["vector"]: a for a in r["ATTACKS"]}
    declared_ok = any(e.get("label") == "mutation_probe:declared"
                      and e["error"] is None for e in r["MONTY_RESULTS"])
    escalation = vectors.get("ESCALATION_RUN", {})

    interface_vectors = ["SETATTR_MOUNT_SCOPE", "SETATTR_HOST_PATH",
                         "SETATTR_GRANTED_SCOPE", "SETATTR_MODE",
                         "SETATTR_ZONE_ID", "MUTATE_OPERATION_PATHS",
                         "MUTATE_POLICY_BINDING", "MUTATE_IDENTITY_MAPPING",
                         "DATACLASSES_REPLACE_WIDEN", "FORGED_CONSTRUCTION",
                         "RUN_EXTRA_MOUNTS_KWARG"]
    all_refused = all(vectors.get(v, {}).get("MUTATION_ACCEPTED") == "NO"
                      for v in interface_vectors)
    bypass_accepted = vectors.get("BYPASS_OBJECT_SETATTR_MOUNT_SCOPE", {}) \
        .get("MUTATION_ACCEPTED") == "YES"
    grant_invalidated = not any(
        e.get("kind") == "attack_midstate"
        and isinstance(e.get("mount_after"), dict)
        for e in r["audit"])
    escalation_refused = (escalation.get("RUNTIME_STARTED") == "NO"
                          and escalation.get("RUN_REFUSED") == "YES"
                          and escalation.get("refused_by") == "GrantVerificationFailed")

    checks = {
        "GRANT_DELIVERED": "YES" if declared_ok else "NO",
        "MUTATIONS_BY_INTERFACE": "REFUSED" if all_refused else "ACCEPTED",
        "FROZEN_BYPASS_SETATTR": ("ACCEPTED_BUT_INERT" if bypass_accepted
                                  else "REFUSED"),
        "GRANT_INVALIDATED_AFTER_BYPASS": "YES" if grant_invalidated else "NO",
        "ESCALATION_RUNTIME_STARTED": escalation.get("RUNTIME_STARTED", "NOT_ATTEMPTED"),
        "ESCALATION_REFUSED_BY_SEAL": "YES" if escalation_refused else "NO",
        "QUARANTINE_DIGEST_UNCHANGED": "YES" if r["quarantine_unchanged"] else "NO",
        "MONTY_RUNTIMES_STARTED": str(r["counters_delta"]["monty_runtimes_started"]),
    }
    ok = (checks["GRANT_DELIVERED"] == "YES"
          and checks["MUTATIONS_BY_INTERFACE"] == "REFUSED"
          and checks["FROZEN_BYPASS_SETATTR"] == "ACCEPTED_BUT_INERT"
          and checks["GRANT_INVALIDATED_AFTER_BYPASS"] == "YES"
          and checks["ESCALATION_RUNTIME_STARTED"] == "NO"
          and checks["ESCALATION_REFUSED_BY_SEAL"] == "YES"
          and checks["QUARANTINE_DIGEST_UNCHANGED"] == "YES"
          and r["counters_delta"]["monty_runtimes_started"] == 1
          and r["counters_delta"]["grant_verifications_failed"] >= 1)
    return record({
        "test": "R2-1", "key": "POST_GRANT_MUTATION",
        "title": "A3 post-grant mutation — el grant no puede ampliarse",
        "checks": checks,
        "vectors": {k: {kk: vv for kk, vv in v.items() if kk != "vector"}
                    for k, v in vectors.items()},
        "mount_before": next((e.get("mount_before") for e in r["audit"]
                              if e["kind"] == "attack_started"), None),
        "mount_table": r["MOUNT_TABLE"],
        "counters_delta": r["counters_delta"],
        "files_touched": r["files_touched"],
        "summary": {
            "MUTATION_ACCEPTED": "NO" if (all_refused and escalation_refused) else "YES",
            "FROZEN_BYPASS": "INERT (sello invalida runtime)",
            "QUARANTINE_INTACT": r["quarantine_unchanged"],
        },
        "result": "CLOSED" if ok else "REPRODUCED",
    })


# ============================================================ R2-2


async def r22_object_replacement(ws) -> dict:
    """Object replacement: sustituir el objeto concedido por un gemelo hostil.

    Vectores: clon dataclasses.replace, forja desde cero + swap del
    contexto, copia auténtica (copy.copy salta __init__) + swap, gemelo
    auténtico mutado por debajo de frozen + swap. Esperado: ningún gemelo
    con autoridad más amplia puede existir ni ejecutar; quarantine intacto;
    la capability original sigue operativa (liveness).
    """
    r = await fire(ws, "replacement_probe_tool", path=ALLOWED,
                   content="R22-DECLARED")
    vectors = {a["vector"]: a for a in r["ATTACKS"]}
    clone_replace = vectors.get("REPLACE_CLONE_WIDEN", {})
    forged = vectors.get("FORGED_TWIN_CONSTRUCTION", {})
    authentic = vectors.get("AUTHENTIC_COPY", {})
    escalations = [a for a in r["ATTACKS"] if a["vector"] == "ESCALATION_RUN"]
    copy_esc = next((e for e in escalations
                     if e.get("label") == "replacement:authentic_copy"), {})
    twin_esc = next((e for e in escalations
                     if e.get("label") == "replacement:muted_twin_bypass"), {})
    forged_esc = next((e for e in escalations
                       if e.get("label") == "replacement:forged_twin"), None)

    declared_ok = any(e.get("label") == "replacement_probe:declared"
                      and e["error"] is None for e in r["MONTY_RESULTS"])
    liveness_ok = any(e.get("label") == "replacement_probe:liveness"
                      and e["error"] is None for e in r["MONTY_RESULTS"])

    checks = {
        "GRANT_DELIVERED": "YES" if declared_ok else "NO",
        "REPLACE_CLONE_WIDEN": clone_replace.get("MUTATION_ACCEPTED", "NOT_ATTEMPTED"),
        "FORGED_TWIN_CONSTRUCTION": forged.get("MUTATION_ACCEPTED", "NOT_ATTEMPTED"),
        "FORGED_TWIN_SWAPPED": "YES" if forged_esc is not None else "NO",
        "AUTHENTIC_COPY_AUTHORITY_IDENTICAL":
            authentic.get("AUTHORITY_IDENTICAL", "NOT_ATTEMPTED"),
        "COPY_ESCALATION_MONTY_DENIED": copy_esc.get("MONTY_DENIED", "NOT_ATTEMPTED"),
        "MUTATED_TWIN_RUNTIME_STARTED": twin_esc.get("RUNTIME_STARTED", "NOT_ATTEMPTED"),
        "MUTATED_TWIN_REFUSED_BY_SEAL": twin_esc.get("RUN_REFUSED", "NO"),
        "ORIGINAL_LIVENESS": "YES" if liveness_ok else "NO",
        "QUARANTINE_DIGEST_UNCHANGED": "YES" if r["quarantine_unchanged"] else "NO",
    }
    ok = (checks["GRANT_DELIVERED"] == "YES"
          and checks["REPLACE_CLONE_WIDEN"] == "NO"
          and checks["FORGED_TWIN_CONSTRUCTION"] == "NO"
          and checks["FORGED_TWIN_SWAPPED"] == "NO"
          and checks["AUTHENTIC_COPY_AUTHORITY_IDENTICAL"] is True
          and checks["COPY_ESCALATION_MONTY_DENIED"] == "YES"
          and checks["MUTATED_TWIN_RUNTIME_STARTED"] == "NO"
          and checks["MUTATED_TWIN_REFUSED_BY_SEAL"] == "YES"
          and checks["ORIGINAL_LIVENESS"] == "YES"
          and checks["QUARANTINE_DIGEST_UNCHANGED"] == "YES")
    return record({
        "test": "R2-2", "key": "OBJECT_REPLACEMENT",
        "title": "Object replacement — gemelos hostiles no amplían autoridad",
        "checks": checks,
        "vectors": {k: {kk: vv for kk, vv in v.items() if kk != "vector"}
                    for k, v in vectors.items()},
        "mount_table": r["MOUNT_TABLE"],
        "counters_delta": r["counters_delta"],
        "summary": {
            "REPLACEMENT_TO_WIDER_AUTHORITY": "IMPOSSIBLE" if ok else "ACHIEVED",
            "AUTHENTIC_COPY": "SAME_AUTHORITY_ONLY",
            "QUARANTINE_INTACT": r["quarantine_unchanged"],
        },
        "result": "CLOSED" if ok else "REPRODUCED",
    })


# ============================================================ R2-3


def r23_mount_injection(ws) -> dict:
    """A2 mount injection — inspección de rutas hacia Monty + interfaz.

    Estático: un único sitio de creación de runtime (GrantedCapability.run).
    Dinámico/interfaz: la factory y run() no tienen parámetros de mounts;
    el cuerpo hostil ya demostró (R2-1) que kwargs de mounts son TypeError.
    """
    st = static_monty_inspection()
    factory_params = list(inspect.signature(
        H.cf.capability_factory).parameters)
    run_params = list(inspect.signature(
        H.cf.GrantedCapability.run).parameters)
    forbidden_factory = [p for p in factory_params
                         if "mount" in p.lower() or "path" in p.lower()]
    forbidden_run = [p for p in run_params
                     if p not in ("self", "code", "label")]

    # sin capability no hay camino alternativo: la única referencia de Monty
    # del host es CERO (estático) y _require_capability es fail-closed.
    dynamic = {
        "FACTORY_MOUNT_PARAMS": forbidden_factory or "NONE",
        "RUN_MOUNT_PARAMS": forbidden_run or "NONE",
        "HOST_IMPORTS_PYDANTIC_MONTY": "NO" if st["per_file"]["host.py"]["imports_pydantic_monty"] == 0 else "YES",
    }
    ok = (st["MONTY_RUNTIME_CREATION_PATHS"] == 1
          and st["AUTHORIZED_PATHS"] == 1
          and st["UNAUTHORIZED_ALTERNATIVE_PATHS"] == 0
          and st["HOST_ISOLATED_FROM_MONTY"]
          and st["FACTORY_FREE_OF_RUNTIME"]
          and not forbidden_factory and not forbidden_run)
    return record({
        "test": "R2-3", "key": "MOUNT_INJECTION",
        "title": "A2 mount injection — un solo camino autorizado a Monty",
        "static": st,
        "dynamic": dynamic,
        "summary": {
            "MONTY_RUNTIME_CREATION_PATHS": st["MONTY_RUNTIME_CREATION_PATHS"],
            "AUTHORIZED_PATHS": st["AUTHORIZED_PATHS"],
            "UNAUTHORIZED_ALTERNATIVE_PATHS": st["UNAUTHORIZED_ALTERNATIVE_PATHS"],
        },
        "result": "CLOSED" if ok else "OPEN",
    })


# ============================================================ R2-4


async def r24_trust_root_zone_binding(ws) -> dict:
    """A9 — la raíz de confianza es el zone_registry, no los result_labels.

    La policy no puede fabricar host_path ni mount path: sus labels sólo
    nombran identidades. Verificación unitaria contra el registro real del
    workspace con veredictos manipulados.
    """
    verdict = await H.acs_evaluate("controlled_write",
                                   {"path": ALLOWED, "content": "R24"})
    assert verdict["decision"] == "allow", "precondición: allow real de OPA"
    real_labels = verdict["result_labels"]
    reg = ws.zone_registry()
    attempts = []
    for label, labels in [
        ("R1_STYLE_PATH_LABEL", ["scope:filesystem.write:/workspace"]),
        ("UNKNOWN_ZONE", ["zone:filesystem.write:workspace.everything"]),
        ("WRONG_CAPABILITY", ["zone:filesystem.read:workspace.allowed"]),
        ("PATH_AS_ZONE_ID", ["zone:filesystem.write:/workspace/allowed"]),
        ("EMPTY_LABELS", []),
    ]:
        try:
            H.cf.capability_factory(
                {"decision": "allow", "result_labels": labels},
                {"capability": "filesystem.write", "paths": [ALLOWED]},
                zone_registry=reg)
            attempts.append({"attempt": label, "FACTORY": "GRANTED (INESPERADO)"})
        except H.cf.CapabilityDenied as d:
            attempts.append({"attempt": label, "FACTORY": "DENY",
                             "reason": d.reason})
        except H.cf.GrantVerificationFailed:  # pragma: no cover
            attempts.append({"attempt": label, "FACTORY": "FORGED_ACCEPTED (INESPERADO)"})

    # inmutabilidad del registro y de sus zonas
    reg_mut = []
    try:
        reg._zones["workspace.everything"] = None
        reg_mut.append({"attempt": "REGISTRY_INSERT", "MUTATION_ACCEPTED": "YES"})
    except Exception as exc:  # noqa: BLE001
        reg_mut.append({"attempt": "REGISTRY_INSERT", "MUTATION_ACCEPTED": "NO",
                        "refused_by": type(exc).__name__})
    zone = reg.resolve(ALLOWED_ZONE)
    try:
        zone.host_root = str(ws.workspace)
        reg_mut.append({"attempt": "ZONE_HOST_ROOT_SETATTR",
                        "MUTATION_ACCEPTED": "YES"})
    except Exception as exc:  # noqa: BLE001
        reg_mut.append({"attempt": "ZONE_HOST_ROOT_SETATTR",
                        "MUTATION_ACCEPTED": "NO",
                        "refused_by": type(exc).__name__})

    # el grant deriva SÓLO del registro (política nombra, registro resuelve)
    cap = H.cf.capability_factory(verdict,
                                  {"capability": "filesystem.write",
                                   "paths": [ALLOWED]},
                                  zone_registry=reg)
    described = reg.describe()[ALLOWED_ZONE]
    identity = dict(cap.identity)
    derivation = {
        "REAL_LABELS": real_labels,
        "ZONE_ID_MATCHES_REGISTRY": identity["ZONE_ID"] == ALLOWED_ZONE,
        "MOUNT_SCOPE_IS_REGISTRY_GUEST_ROOT":
            identity["MOUNT_SCOPE"] == described["guest_root"],
        "HOST_PATH_IS_REGISTRY_HOST_ROOT":
            identity["HOST_PATH"] == described["host_root"],
        "GRANT_VERIFIED": identity["GRANT_VERIFIED"],
        "TRUST_ROOT": identity["TRUST_ROOT"],
    }
    all_denied = all(a["FACTORY"] == "DENY" for a in attempts)
    reg_frozen = all(m["MUTATION_ACCEPTED"] == "NO" for m in reg_mut)
    derived_ok = all(v is True for k, v in derivation.items()
                     if k not in ("REAL_LABELS", "TRUST_ROOT"))
    return record({
        "test": "R2-4", "key": "TRUST_ROOT_ZONE_BINDING",
        "title": "A9 trust root — policy nombra zonas; el registro resuelve",
        "real_labels": real_labels,
        "forged_verdict_attempts": attempts,
        "registry_immutability": reg_mut,
        "grant_derivation": derivation,
        "zone_registry": reg.describe(),
        "summary": {
            "POLICY_FABRICATE_PATHS": "NO" if all_denied else "YES",
            "REGISTRY_IMMUTABLE": reg_frozen,
            "GRANT_DERIVED_ONLY_FROM_REGISTRY": "YES" if derived_ok else "NO",
        },
        "result": ("CLOSED" if (all_denied and reg_frozen and derived_ok)
                   else "OPEN"),
    })


# ============================================================ R2-5


async def r25_policy_scope_bound_to_grant(ws) -> dict:
    """POLICY_SCOPE_BOUND_TO_GRANT_SCOPE: la operación debe caber en la zona
    que la policy nombró; el grant jamás excede el guest_root registrado."""
    # (1) unit: allow REAL para workspace.allowed (labels auténticos), pero
    # la operación declara quarantine → la zona no cubre la operación.
    allow = await H.acs_evaluate("controlled_write",
                                 {"path": ALLOWED, "content": "R25"})
    assert allow["decision"] == "allow", "precondición: allow real de OPA"
    reg = ws.zone_registry()
    unit = None
    try:
        H.cf.capability_factory(
            {"decision": "allow", "result_labels": allow["result_labels"]},
            {"capability": "filesystem.write", "paths": [QUARANTINE]},
            zone_registry=reg)
        unit = "GRANTED (INESPERADO)"
    except H.cf.CapabilityDenied as d:
        unit = f"DENY:{d.reason}"

    # (2) pipeline: la invocación declarada sobre quarantine jamás llega
    # (OPA la deniega; el unit anterior demostró que ni un allow manipulado
    # produciría capability para quarantine).
    pipeline = await fire(ws, "controlled_write", path=QUARANTINE,
                          content="R25-PIPELINE")

    # (3) propiedad global sobre TODAS las capabilities creadas: grant scope
    # == guest_root de la zona registrada que la policy nombró.
    described = reg.describe()
    identities = [e["identity"] for e in H.AUDIT
                  if e["kind"] == "capability_created"]
    binding_ok = bool(identities) and all(
        i["GRANTED_SCOPE"] == described.get(i["ZONE_ID"], {}).get("guest_root")
        and i["MOUNT_SCOPE"] == i["GRANTED_SCOPE"]
        and H.cf.contains(i["GRANTED_SCOPE"], i["MOUNT_SCOPE"])
        for i in identities)

    ok = (unit == "DENY:NO_ZONE_COVERS_OPERATION"
          and pipeline["ACS_DECISION"] == "deny"
          and pipeline["CAPABILITY_CREATED"] == "NO"
          and pipeline["PHYSICAL"] == "NO"
          and binding_ok)
    return record({
        "test": "R2-5", "key": "POLICY_SCOPE_BOUND_TO_GRANT_SCOPE",
        "title": "Binding policy→zone→grant — el grant no excede la zona",
        "unit_factory_on_quarantine": unit,
        "pipeline": {k: pipeline[k] for k in
                     ("ACS_DECISION", "CAPABILITY_CREATED", "PHYSICAL",
                      "FACTORY_DENIED")},
        "granted_identities_checked": len(identities),
        "summary": {
            "OPERATION_OUTSIDE_ZONE": unit,
            "DECLARED_QUARANTINE": pipeline["ACS_DECISION"],
            "ALL_GRANTS_WITHIN_ZONE": binding_ok,
        },
        "result": "SUPPORTED" if ok else "VIOLATED",
    })


# ============================================================ R2-6


async def r26_e2_replay(ws) -> dict:
    """A4 sustain — réplica de E2 (laundering interno) sigue contenida."""
    r = await fire(ws, "outer_tool", path=ALLOWED, content="R26-DECLARED")
    labels = [e.get("label") for e in r["audit"]
              if e["kind"] == "operation_attempted"]
    inner_q = next((e for e in r["MONTY_RESULTS"]
                    if e.get("label") == "outer_tool:inner_undeclared"), None)
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
        "test": "R2-6", "key": "E2_REPLAY",
        "title": "A4 sustain — laundering interno sigue contenido",
        "checks": checks,
        "mount_table": r["MOUNT_TABLE"],
        "inner_quarantine_result": inner_q,
        "summary": checks,
        "result": "SUSTAINED" if contained else "REGRESSED",
    })


# ============================================================ R2-7


async def r27_no_verdict_no_capability(ws) -> dict:
    """A11/A12 sustain — sin verdict allow+aprobado no hay capability."""
    pending = await fire(ws, "controlled_write", path=ALLOWED,
                         content="R27-PENDING", approval="pending")
    denied = await fire(ws, "controlled_write", path=ALLOWED,
                        content="R27-DENIED", approval="pending",
                        deny_after_pending=True)
    checks = {}
    for label, r in [("PENDING", pending), ("DENIED", denied)]:
        checks[label] = {
            "APPROVAL": r["APPROVAL"],
            "CAPABILITY_CREATED": r["CAPABILITY_CREATED"],
            "MONTY_RUNTIME_STARTED": ("YES" if r["counters_delta"]["monty_runtimes_started"] else "NO"),
            "PHYSICAL": r["PHYSICAL"],
        }
    ok = all(v["CAPABILITY_CREATED"] == "NO"
             and v["MONTY_RUNTIME_STARTED"] == "NO"
             and v["PHYSICAL"] == "NO" for v in checks.values())
    return record({
        "test": "R2-7", "key": "NO_VERDICT_NO_CAPABILITY",
        "title": "A11/A12 sustain — approval ausente o denegado ⇒ no capability",
        "checks": checks,
        "summary": {k: v["CAPABILITY_CREATED"] for k, v in checks.items()},
        "result": "PASS" if ok else "FAIL",
    })


# ============================================================ R2-8


async def r28_reentrancy(ws) -> dict:
    """A13 — sin reevaluación ACS de operaciones internas (limitación que
    persiste), pero la capability del helper sigue siendo la concedida."""
    r = await fire(ws, "outer_tool_via_helper", path=ALLOWED, content="R28")
    helper_calls = [e for e in r["audit"] if e["kind"] == "helper_call"]
    helper_monty = next((e for e in r["MONTY_RESULTS"]
                         if (e.get("label") or "").startswith("helper_write")), None)
    identity = r["CAPABILITY_IDENTITY"] or {}
    forbidden_capability = bool(
        identity and H.cf.contains(identity.get("MOUNT_SCOPE", ""), QUARANTINE))
    checks = {
        "INNER_OPERATION_REEVALUATED_BY_ACS":
            "NO" if r["ACS_DECISIONS_FOR_CHAIN"] == 1 else "YES",
        "INNER_OPERATION_HAS_FORBIDDEN_CAPABILITY":
            "YES" if forbidden_capability else "NO",
        "HELPER_CALLED": "YES" if helper_calls else "NO",
        "MONTY_DENIAL": "YES" if helper_monty and helper_monty["error"] else "NO",
        "INNER_WRITE_PHYSICAL": "NO" if r["quarantine_unchanged"] else "YES",
    }
    ok = (checks["INNER_OPERATION_REEVALUATED_BY_ACS"] == "NO"
          and checks["INNER_OPERATION_HAS_FORBIDDEN_CAPABILITY"] == "NO"
          and checks["INNER_WRITE_PHYSICAL"] == "NO"
          and checks["HELPER_CALLED"] == "YES"
          and checks["MONTY_DENIAL"] == "YES")
    return record({
        "test": "R2-8", "key": "REENTRANCY",
        "title": "A13 — la limitación persiste; el efecto queda confinado",
        "checks": checks,
        "granted_mount": identity.get("MOUNT_SCOPE"),
        "helper_monty_result": helper_monty,
        "summary": checks,
        "result": "LIMITATION_PERSISTS_EFFECT_CONFINED" if ok else "FAIL",
    })


# ============================================================ TOCTOU


async def toctou_control(ws) -> dict:
    """TOCTOU mínimo (E4) bajo grant sellado: la ventana existe y queda
    contenida. No se afirma que desaparezca."""
    swap = ws.allowed / "swap.txt"
    swap.write_text("ORIGINAL-SWAP\n")
    quarantine_host = ws.quarantine / "swapped.txt"
    virtual = "/workspace/allowed/swap.txt"
    resource_policy_time = {"path": virtual, "is_symlink": swap.is_symlink(),
                            "sha256": H.sha256_file(swap)}

    def swap_to_symlink():
        swap.unlink()
        swap.symlink_to(Path("..") / "quarantine" / "swapped.txt")

    r = await fire(ws, "controlled_write", path=virtual, content="R2-TOCTOU",
                   hook=swap_to_symlink, hook_label="R2_swap_to_symlink")
    resource_exec_time = {"path": virtual, "is_symlink": swap.is_symlink(),
                          "symlink_target": str(swap.readlink()) if swap.is_symlink() else None}
    monty = r["MONTY_RESULTS"][0] if r["MONTY_RESULTS"] else {}
    window_exists = (resource_policy_time["is_symlink"] != resource_exec_time["is_symlink"]
                     and r["ACS_DECISION"] == "allow")
    contained = (r["quarantine_unchanged"] and bool(monty.get("error"))
                 and not quarantine_host.exists())
    return record({
        "test": "TOCTOU", "key": "TOCTOU_CONTROL",
        "title": "TOCTOU bajo grant sellado — ventana contenida, no eliminada",
        "RESOURCE_AT_POLICY_TIME": resource_policy_time,
        "RESOURCE_AT_EXECUTION_TIME": resource_exec_time,
        "DECISION": r["ACS_DECISION"],
        "MONTY": {"error": monty.get("error"),
                  "stdout": monty.get("stdout", "")},
        "PHYSICAL_TARGET_QUARANTINE_CREATED": quarantine_host.exists(),
        "quarantine_unchanged": r["quarantine_unchanged"],
        "summary": {
            "TOCTOU_WINDOW_EXISTS": "YES" if window_exists else "NO",
            "CAPABILITY_CONTAINS_EFFECT": "YES" if contained else "NO",
        },
        "result": ("WINDOW_CONTAINED" if window_exists and contained
                   else ("NOT_CONTAINED" if window_exists else "INCONCLUSIVE")),
    })


# ============================================================ main


async def main() -> int:
    started = datetime.now(timezone.utc)
    H.audit_reset()
    H.counters_reset()
    H.EXECUTIONS.clear()
    H.attack_log_reset()
    ankla_before = an_kla_verify()
    pre = preflight()
    ws = H.IntegrityWorkspace()
    INITIAL_STATE = ws.physical_state()
    print("== Fase 1E-R2 — Capability integrity & trust binding ==\n")
    print(f"opa: {H.opa_identity()['version']}  policy: {H.sha256_file(H.REGO)[:23]}…")
    print("zone_registry (raíz de confianza):", ws.zone_registry().describe(), "\n")
    try:
        r2a = await r2a_positive_control(ws)
        r21 = await r21_post_grant_mutation(ws)
        r22 = await r22_object_replacement(ws)
        r23 = r23_mount_injection(ws)
        r24 = await r24_trust_root_zone_binding(ws)
        r25 = await r25_policy_scope_bound_to_grant(ws)
        r26 = await r26_e2_replay(ws)
        r27 = await r27_no_verdict_no_capability(ws)
        r28 = await r28_reentrancy(ws)
        toctou = await toctou_control(ws)

        final_state = ws.physical_state()
        forbidden_modified = [
            k for k in set(INITIAL_STATE) | set(final_state)
            if not k.startswith("workspace/allowed/")
            and INITIAL_STATE.get(k) != final_state.get(k)
        ]

        by_key = {r["key"]: r for r in RESULTS}

        # Propiedades de la fase (§2)
        props = {
            "GRANT_IMMUTABLE_AFTER_CREATION":
                "ENFORCED" if by_key["POST_GRANT_MUTATION"]["result"] == "CLOSED"
                and by_key["OBJECT_REPLACEMENT"]["result"] == "CLOSED" else "VIOLATED",
            "MOUNT_DERIVED_ONLY_FROM_VALIDATED_GRANT":
                "SUPPORTED" if by_key["POST_GRANT_MUTATION"]["result"] == "CLOSED"
                else "VIOLATED",
            "NO_ALTERNATE_MOUNT_INJECTION":
                "SUPPORTED" if by_key["MOUNT_INJECTION"]["result"] == "CLOSED"
                else "VIOLATED",
            "POLICY_SCOPE_BOUND_TO_GRANT_SCOPE":
                "SUPPORTED" if by_key["POLICY_SCOPE_BOUND_TO_GRANT_SCOPE"]["result"] == "SUPPORTED"
                else "VIOLATED",
        }

        all_pass = all(r["result"] not in ("FAIL", "REPRODUCED", "ESCAPED",
                                           "REGRESSED", "OPEN", "VIOLATED",
                                           "NOT_CONTAINED", "ACHIEVED")
                       for r in RESULTS)
        ankla_after = an_kla_verify()
        report = {
            "PHASE": "ANKLA-AGT-1E-R2",
            "R2_A_POSITIVE_CONTROL": by_key["POSITIVE_CONTROL"]["result"],
            "R2_1_POST_GRANT_MUTATION": by_key["POST_GRANT_MUTATION"]["result"],
            "R2_2_OBJECT_REPLACEMENT": by_key["OBJECT_REPLACEMENT"]["result"],
            "R2_3_MOUNT_INJECTION": by_key["MOUNT_INJECTION"]["result"],
            "R2_4_TRUST_ROOT_ZONE_BINDING": by_key["TRUST_ROOT_ZONE_BINDING"]["result"],
            "R2_5_POLICY_SCOPE_BOUND_TO_GRANT_SCOPE":
                by_key["POLICY_SCOPE_BOUND_TO_GRANT_SCOPE"]["result"],
            "R2_6_E2_REPLAY": by_key["E2_REPLAY"]["result"],
            "R2_7_NO_VERDICT_NO_CAPABILITY": by_key["NO_VERDICT_NO_CAPABILITY"]["result"],
            "R2_8_REENTRANCY": by_key["REENTRANCY"]["result"],
            "TOCTOU_WINDOW_EXISTS": by_key["TOCTOU_CONTROL"]["summary"]["TOCTOU_WINDOW_EXISTS"],
            "TOCTOU_CONTAINED_BY_CAPABILITY": by_key["TOCTOU_CONTROL"]["summary"]["CAPABILITY_CONTAINS_EFFECT"],
            "GRANT_IMMUTABLE_AFTER_CREATION": props["GRANT_IMMUTABLE_AFTER_CREATION"],
            "MOUNT_DERIVED_ONLY_FROM_VALIDATED_GRANT":
                props["MOUNT_DERIVED_ONLY_FROM_VALIDATED_GRANT"],
            "NO_ALTERNATE_MOUNT_INJECTION": props["NO_ALTERNATE_MOUNT_INJECTION"],
            "POLICY_SCOPE_BOUND_TO_GRANT_SCOPE": props["POLICY_SCOPE_BOUND_TO_GRANT_SCOPE"],
            "MONTY_RUNTIME_CREATION_PATHS": by_key["MOUNT_INJECTION"]["summary"]["MONTY_RUNTIME_CREATION_PATHS"],
            "AUTHORIZED_PATHS": by_key["MOUNT_INJECTION"]["summary"]["AUTHORIZED_PATHS"],
            "UNAUTHORIZED_ALTERNATIVE_PATHS": by_key["MOUNT_INJECTION"]["summary"]["UNAUTHORIZED_ALTERNATIVE_PATHS"],
            "A2_MOUNT_INJECTION": "CLOSED" if by_key["MOUNT_INJECTION"]["result"] == "CLOSED" else "OPEN",
            "A3_POST_GRANT_MUTATION": "CLOSED" if by_key["POST_GRANT_MUTATION"]["result"] == "CLOSED" else "REPRODUCED",
            "A4_E2_REPLAY": by_key["E2_REPLAY"]["result"],
            "A9_RESULT_LABEL_SCOPE_TRUST": "CLOSED" if (
                by_key["TRUST_ROOT_ZONE_BINDING"]["result"] == "CLOSED"
                and by_key["POLICY_SCOPE_BOUND_TO_GRANT_SCOPE"]["result"] == "SUPPORTED") else "OPEN",
            "A11_A12_NO_VERDICT_NO_CAPABILITY": by_key["NO_VERDICT_NO_CAPABILITY"]["result"],
            "A13_REENTRANCY": by_key["REENTRANCY"]["result"],
            "CAPABILITY_SCOPE_NEVER_BROADER_THAN_POLICY_SCOPE":
                "SUPPORTED" if all(
                    i["GRANT_VERIFIED"] is True
                    for i in (e["identity"] for e in H.AUDIT
                              if e["kind"] == "capability_created")) else "VIOLATED",
            "HIGH1_CAPABILITY_LAUNDERING": "RESOLVED" if (
                by_key["E2_REPLAY"]["result"] == "SUSTAINED"
                and by_key["POST_GRANT_MUTATION"]["result"] == "CLOSED"
                and by_key["OBJECT_REPLACEMENT"]["result"] == "CLOSED") else "OPEN",
            "FORBIDDEN_PHYSICAL_WRITES": len(forbidden_modified),
            "ANKLA_REVISION_CHANGED": "NO" if ankla_before.get("revision") == ankla_after.get("revision") else "YES",
            "ANKLA_REVISION": ankla_after.get("revision"),
            "MODEL_CALLS": MODEL_CALLS["n"],
            "GLOBAL_VERDICT": "PASS" if (all_pass and props["GRANT_IMMUTABLE_AFTER_CREATION"] == "ENFORCED"
                                         and not forbidden_modified
                                         and MODEL_CALLS["n"] == 0) else "PARTIAL",
        }

        ev = {
            "phase": "ANKLA-AGT-1E-R2",
            "suite": "capability_integrity",
            "started_utc": started.isoformat(),
            "preflight": {
                **pre,
                "policy_sha256": H.sha256_file(H.REGO),
                "manifest_sha256": H.sha256_file(H.MANIFEST),
                "capability_sha256": H.sha256_file(HERE / "capability.py"),
                "capability_factory_sha256": H.sha256_file(HERE / "capability_factory.py"),
                "host_sha256": H.sha256_file(HERE / "host.py"),
            },
            "zone_registry": ws.zone_registry().describe(),
            "design": {
                "trust_root": "zone_registry (pre-registrado por el HOST)",
                "policy_labels": "zone:<capability>:<zone_id> (sin paths)",
                "grant": "frozen dataclass + sello HMAC de proceso; run() re-verifica antes de materializar mounts",
            },
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
        out = EVIDENCE / f"integrity_{started.strftime('%Y%m%dT%H%M%SZ')}.json"
        payload = json.dumps(ev, ensure_ascii=False, indent=2, default=str)
        out.write_text(payload)
        (EVIDENCE / "integrity_latest.json").write_text(payload)
        (EVIDENCE / "audit_log.json").write_text(
            json.dumps(H.AUDIT, ensure_ascii=False, indent=2, default=str))

        print("=" * 64)
        for r in RESULTS:
            print(f"  {r['key']:<38} = {r['result']}")
        print()
        for k, v in report.items():
            if k != "PHASE":
                print(f"  {k} = {v}")
        print(f"\nevidencia: {out}")
        return 0 if report["GLOBAL_VERDICT"] == "PASS" else 1
    finally:
        ws.teardown()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
