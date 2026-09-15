"""Verificación aislada de OPA + Rego, ANTES de involucrar a ACS (Fase 1D-R2).

Origen: H1 de la revisión adversarial externa ANKLA-MICROSOFT-1A-1D-EXTERNAL,
reafirmado como OPEN por la Fase 1D-R1.

Este script NO usa ACS. Ejecuta `opa eval` directamente sobre
`policy/filesystem.rego` para establecer una línea base independiente: si la
policy es correcta aquí y luego falla vía ACS, el problema es de integración,
no de la policy. Y viceversa.

Requisito de diseño: la policy es **fail-closed** (`default verdict` = deny).
Nunca `default allow := true`.

0 tokens. Sin LLM.

Uso:
    .venv/bin/python playground/13_opa_rego_policy/opa_direct_smoke.py
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "evidence"
POLICY_DIR = HERE / "policy"
REGO = POLICY_DIR / "filesystem.rego"
QUERY = "data.acs.verdict"


def opa_executable() -> str:
    explicit = os.environ.get("ACS_OPA_PATH")
    if explicit and Path(explicit).exists():
        return explicit
    found = shutil.which("opa")
    if found:
        return found
    local = Path.home() / ".local" / "bin" / "opa"
    if local.exists():
        return str(local)
    print("ERROR: no se encontró el ejecutable opa", file=sys.stderr)
    sys.exit(2)


def sha256_file(p: Path) -> str:
    return "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest()


def opa_version(exe: str) -> dict:
    out = subprocess.run([exe, "version"], capture_output=True, text=True, check=True).stdout
    info = {}
    for line in out.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            info[k.strip()] = v.strip()
    return info


def opa_eval(exe: str, input_obj: dict) -> dict:
    """Invoca `opa eval` igual que lo hace el dispatcher bundled de ACS."""
    proc = subprocess.run(
        [exe, "eval", "--format=json", "--stdin-input", "--data", str(REGO), QUERY],
        input=json.dumps(input_obj), capture_output=True, text=True,
    )
    if proc.returncode != 0:
        return {"error": proc.stderr.strip()[:400], "decision": None}
    data = json.loads(proc.stdout)
    results = data.get("result") or []
    if not results:
        return {"error": "OPA no devolvió resultado", "decision": None}
    value = results[0]["expressions"][0]["value"]
    return {"decision": value.get("decision"), "message": value.get("message"), "error": None}


# El input aquí imita el shape REAL que ACS entrega (verificado empíricamente):
# policy_target.value contiene el tool_call.
def acs_shaped(tool_call) -> dict:
    return {
        "intervention_point": "pre_tool_call",
        "policy_target": {"kind": None, "path": "$.tool_call", "value": tool_call},
        "snapshot": {"tool_call": tool_call},
        "annotations": {},
        "tool": tool_call if isinstance(tool_call, dict) else {},
    }


CASES = [
    ("known_allowed", "allow", {"name": "controlled_write", "args": {"path": "/workspace/allowed/output.txt"}}),
    ("known_allowed_nested", "allow", {"name": "controlled_write", "args": {"path": "/workspace/allowed/sub/nested.txt"}}),
    ("known_denied_quarantine", "deny", {"name": "controlled_write", "args": {"path": "/workspace/quarantine/target.txt"}}),
    ("traversal_sibling", "deny", {"name": "controlled_write", "args": {"path": "/workspace/allowed/../quarantine/target.txt"}}),
    ("traversal_nested", "deny", {"name": "controlled_write", "args": {"path": "/workspace/allowed/sub/../../quarantine/target.txt"}}),
    ("traversal_double_slash", "deny", {"name": "controlled_write", "args": {"path": "/workspace/allowed//../quarantine/target.txt"}}),
    ("traversal_dot_segment", "deny", {"name": "controlled_write", "args": {"path": "/workspace/allowed/./../quarantine/target.txt"}}),
    ("escape_above_root", "deny", {"name": "controlled_write", "args": {"path": "/workspace/../../etc/passwd"}}),
    ("outside_allowed_scope", "deny", {"name": "controlled_write", "args": {"path": "/workspace/other/x.txt"}}),
    ("malformed_path_missing", "deny", {"name": "controlled_write", "args": {}}),
    ("malformed_path_list", "deny", {"name": "controlled_write", "args": {"path": ["/workspace/allowed/x"]}}),
    ("malformed_path_null", "deny", {"name": "controlled_write", "args": {"path": None}}),
    ("malformed_path_object", "deny", {"name": "controlled_write", "args": {"path": {"p": "/workspace/allowed/x"}}}),
    ("malformed_args_string", "deny", {"name": "controlled_write", "args": "path=/workspace/allowed/x"}),
    ("unknown_tool", "deny", {"name": "tool_fantasma_experimental", "args": {"path": "/workspace/allowed/output.txt"}}),
    ("tool_name_casing", "deny", {"name": "Controlled_Write", "args": {"path": "/workspace/allowed/output.txt"}}),
    ("tool_name_absent", "deny", {"args": {"path": "/workspace/allowed/output.txt"}}),
    ("empty_target", "deny", {}),
]


def main() -> int:
    started = datetime.now(timezone.utc)
    exe = opa_executable()
    ver = opa_version(exe)
    print("== Verificación aislada OPA + Rego (sin ACS) ==\n")
    print(f"opa        : {exe}")
    print(f"version    : {ver.get('Version')}  rego={ver.get('Rego Version')}  platform={ver.get('Platform')}")
    print(f"policy     : {REGO.relative_to(HERE)}  {sha256_file(REGO)}")
    print(f"query      : {QUERY}\n")

    # comprobación de sintaxis por el propio OPA
    chk = subprocess.run([exe, "check", str(REGO)], capture_output=True, text=True)
    print(f"opa check  : {'OK' if chk.returncode == 0 else 'FAIL ' + chk.stderr[:200]}\n")

    rows, failures = [], 0
    for name, expected, tool_call in CASES:
        res = opa_eval(exe, acs_shaped(tool_call))
        ok = res["decision"] == expected
        if not ok:
            failures += 1
        rows.append({
            "case": name, "expected": expected, "tool_call": tool_call,
            "opa_decision": res["decision"], "opa_message": res.get("message"),
            "opa_error": res.get("error"), "pass": ok,
        })
        flag = "" if ok else "   <-- INESPERADO"
        print(f"  [{'ok' if ok else 'FAIL'}] {name:<24} esperado={expected:<5} obtenido={res['decision']}{flag}")

    # Comprobación explícita de que la policy es fail-closed por defecto.
    # Se ignoran las líneas de comentario: el encabezado de la policy MENCIONA
    # `default allow := true` para prohibirlo, y una comprobación textual
    # ingenua lo confundiría con una declaración real.
    text = REGO.read_text()
    code = "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )
    default_deny = (
        "default verdict := {" in code
        and '"decision": "deny"' in code.split("default verdict := {")[1][:200]
    )
    no_default_allow = "default allow := true" not in code

    ev = {
        "phase": "ANKLA-AGT-1D-R2",
        "test": "OPA_DIRECT_SMOKE",
        "origin_finding": "H1 (ANKLA-MICROSOFT-1A-1D-EXTERNAL; OPEN tras 1D-R1)",
        "started_utc": started.isoformat(),
        "llm_tokens": 0,
        "acs_involved": False,
        "opa": {
            "executable": exe,
            "version": ver.get("Version"),
            "rego_version": ver.get("Rego Version"),
            "platform": ver.get("Platform"),
            "build_commit": ver.get("Build Commit"),
        },
        "policy_file": str(REGO.relative_to(HERE.parent.parent)),
        "policy_sha256": sha256_file(REGO),
        "query": QUERY,
        "opa_check_ok": chk.returncode == 0,
        "fail_closed_by_default": default_deny,
        "no_default_allow_true": no_default_allow,
        "cases": rows,
        "summary": {"total": len(rows), "passed": len(rows) - failures, "failed": failures},
        "finished_utc": datetime.now(timezone.utc).isoformat(),
    }
    EVIDENCE.mkdir(exist_ok=True)
    out = EVIDENCE / f"opa_direct_smoke_{started.strftime('%Y%m%dT%H%M%SZ')}.json"
    payload = json.dumps(ev, ensure_ascii=False, indent=2, default=str)
    out.write_text(payload)
    (EVIDENCE / "opa_direct_smoke_latest.json").write_text(payload)

    print(f"\n  fail_closed_by_default = {default_deny}   sin 'default allow := true' = {no_default_allow}")
    print(f"  RESULTADO: {len(rows) - failures}/{len(rows)} casos como se esperaba")
    print(f"\nevidencia: {out}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
