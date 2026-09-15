"""§19 — Tabla comparativa de los tres decisores de policy (Fase 1D-R2).

Compara, para los mismos casos, qué decidió:

  * el dispatcher Python original de la Fase 1D  (`Deterministic1DPolicy`);
  * el dispatcher Python remediado de 1D-R1      (`FailClosedPolicy1DR1`);
  * la policy declarativa Rego ejecutada por OPA (Fase 1D-R2).

La tabla se DERIVA de la evidencia ya publicada, no se escribe a mano:

  * `playground/12_adversarial_remediation/evidence/t3_fail_open_latest.json`
    (before_fix = dispatcher 1D, after_fix = dispatcher 1D-R1)
  * `playground/13_opa_rego_policy/evidence/mechanical_latest.json`

Además atribuye cada garantía a su capa: ACS, implementación de policy, o
enforcement del host.

0 tokens. Sin LLM.

Uso:
    .venv/bin/python playground/13_opa_rego_policy/comparison_table.py
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
LAB = HERE.parent.parent
EVIDENCE = HERE / "evidence"
T3 = LAB / "playground" / "12_adversarial_remediation" / "evidence" / "t3_fail_open_latest.json"
R2 = EVIDENCE / "mechanical_latest.json"

# caso canónico -> (id en T3 de 1D-R1, cómo obtenerlo de la evidencia 1D-R2)
CASES = [
    ("valid allow", "C0_BASELINE_LEGITIMATE", ("test", "T-R2-2_ALLOW_POSITIVE")),
    ("valid deny", "C1_BASELINE_QUARANTINE", ("test", "T-R2-3_DENY_QUARANTINE")),
    ("traversal", "C10_PATH_TRAVERSAL", ("traversal", "V2_TRAVERSAL_SIBLING")),
    ("missing path", "C5_MISSING_PATH_KEY", ("malformed", "M1_PATH_KEY_ABSENT")),
    ("list path", "C8_PATH_AS_LIST", ("malformed", "M2_PATH_AS_LIST")),
    ("unknown tool", "C3_TOOL_NAME_UNKNOWN", ("malformed", "M7_UNKNOWN_TOOL")),
]


def t3_decision(t3: dict, phase_key: str, case_id: str) -> str:
    for row in t3[phase_key]["cases"]:
        if row["case"] == case_id:
            return row["DISPATCHER_DECISION"]
    return "n/a"


def r2_decision(r2: dict, kind: str, key: str) -> str:
    tests = {t.get("test"): t for t in r2["tests"]}
    if kind == "test":
        return tests[key]["ACS_VERDICT"]
    if kind == "traversal":
        for v in tests["T-R2-4_TRAVERSAL_REPLAY"]["variants"]:
            if v["variant"] == key:
                return v["ACS_VERDICT"]
    if kind == "malformed":
        for c in tests["T-R2-5_MALFORMED_FAIL_CLOSED"]["cases"]:
            if c["case"] == key:
                return c["ACS_VERDICT"]
    return "n/a"


ATTRIBUTION = [
    ("tool no declarada en el manifest → deny",
     "ACS (núcleo nativo)", "runtime_error:tool_unknown",
     "independiente del decisor de policy: presente en 1D, 1D-R1 y 1D-R2"),
    ("argumentos malformados → deny",
     "implementación de policy", "T3 C5/C8 vs T-R2-5 M1/M2",
     "ACS no inspecciona argumentos; en 1D el dispatcher permitía"),
    ("traversal / canonicalización → deny",
     "implementación de policy", "T1 vs T-R2-4",
     "en 1D-R2 la canonicalización vive en el propio Rego"),
    ("motor de policy ausente o inválido → deny",
     "ACS (normalización de errores)", "runtime_error:policy_invocation_failed",
     "T-R2-6 y T-R2-7: el fallo del motor no se convierte en allow"),
    ("veredicto deny impide ejecución del cuerpo",
     "enforcement del host", "AcsOpaMiddleware → MiddlewareTermination",
     "el host debe respetar el verdict; ACS no ejecuta la tool"),
    ("escritura fuera del mount → denegada físicamente",
     "Monty (capability)", "T-R2-8, EROFS",
     "independiente de policy: 1D-R1 T2 lo estableció como causal"),
]


def main() -> int:
    for p in (T3, R2):
        if not p.exists():
            print(f"ERROR: falta evidencia {p}", file=sys.stderr)
            return 1
    t3 = json.loads(T3.read_text())
    r2 = json.loads(R2.read_text())

    rows = []
    for label, t3_id, (kind, key) in CASES:
        rows.append({
            "case": label,
            "dispatcher_1D_original": t3_decision(t3, "before_fix", t3_id),
            "dispatcher_1D_R1": t3_decision(t3, "after_fix", t3_id),
            "opa_rego_1D_R2": r2_decision(r2, kind, key),
            "t3_case_id": t3_id,
            "r2_case_id": key,
        })

    hdr = f"{'Caso':<16} {'Dispatcher 1D orig.':<21} {'Dispatcher 1D-R1':<18} {'OPA/Rego 1D-R2':<15}"
    print("== §19 Comparación de decisores de policy ==\n")
    print(hdr)
    print("-" * len(hdr))
    for r in rows:
        mark = "  <-- fail-open en 1D" if (
            r["dispatcher_1D_original"] == "allow" and r["opa_rego_1D_R2"] == "deny") else ""
        print(f"{r['case']:<16} {r['dispatcher_1D_original']:<21} "
              f"{r['dispatcher_1D_R1']:<18} {r['opa_rego_1D_R2']:<15}{mark}")

    print("\n== Atribución de garantías por capa ==\n")
    for guarantee, layer, ev, note in ATTRIBUTION:
        print(f"  {guarantee}")
        print(f"      capa      : {layer}")
        print(f"      evidencia : {ev}")
        print(f"      nota      : {note}")

    regressions = [r["case"] for r in rows
                   if r["dispatcher_1D_R1"] != r["opa_rego_1D_R2"]]
    fixed_by_opa = [r["case"] for r in rows
                    if r["dispatcher_1D_original"] == "allow" and r["opa_rego_1D_R2"] == "deny"]

    ev_out = {
        "phase": "ANKLA-AGT-1D-R2",
        "test": "COMPARISON_TABLE",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "sources": {
            "t3_1d_r1": str(T3.relative_to(LAB)),
            "mechanical_1d_r2": str(R2.relative_to(LAB)),
        },
        "rows": rows,
        "guarantee_attribution": [
            {"guarantee": g, "layer": l, "evidence": e, "note": n}
            for g, l, e, n in ATTRIBUTION
        ],
        "cases_fixed_by_declarative_policy": fixed_by_opa,
        "divergences_r1_vs_r2": regressions,
    }
    EVIDENCE.mkdir(exist_ok=True)
    out = EVIDENCE / "comparison_table.json"
    out.write_text(json.dumps(ev_out, ensure_ascii=False, indent=2))
    print(f"\n  casos que 1D permitía y la policy declarativa deniega: {fixed_by_opa}")
    print(f"  divergencias 1D-R1 vs 1D-R2: {regressions or 'ninguna'}")
    print(f"\nevidencia: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
