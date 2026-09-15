"""T2 — Control negativo causal de D4 (Fase 1D-R1).

Origen: finding M2 de la revisión adversarial externa
ANKLA-MICROSOFT-1A-1D-EXTERNAL.

D4 (Fase 1D) observó `PermissionError [Errno 30] Read-only file system` y
concluyó que Monty negó la escritura. Observar EROFS demuestra QUÉ error
ocurrió, no que Monty fuera la CAUSA: nunca se comprobó que la escritura fuese
posible de otro modo.

Diseño pareado. Tres condiciones sobre EL MISMO archivo host, con el MISMO
request, approval, decisión ACS, código de host y payload. Lo único que cambia
es la capability concedida por Monty:

    T2-A  mount /protected mode="read-only"   → esperado WRITE = NO
    T2-B  mount /protected mode="read-write"  → esperado WRITE = YES
    T2-C  escritura directa del host, fuera de Monty, con restauración por
          digest → esperado WRITE = YES (demuestra que el SO/FS lo permitía)

Sólo si A=blocked y B=executed (y C confirma que el FS no era el obstáculo)
puede afirmarse MONTY_CAUSAL_FOR_D4 = SUPPORTED.

0 tokens. Sin LLM. Sin modificar 1A/1B/1C/1D.

Uso:
    .venv/bin/python playground/12_adversarial_remediation/t2_monty_negative_control.py
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import json
import os
import shutil
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from agent_framework import Content, ToolApprovalMiddleware, ToolApprovalRule

import pydantic_monty as pm

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

TARGET_VIRTUAL = "/protected/forbidden.txt"
PAYLOAD = "T2-TRASLADO"


def sha256_file(p: Path) -> str:
    return "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest()


class PairedWorkspace:
    """Workspace cuyo mount /protected cambia de modo entre condiciones.

    El directorio host y su contenido son idénticos en A y B; sólo varía
    `MountDir.mode`. Duck-typing compatible con `integrated_host.Workspace`.
    """

    def __init__(self, protected_mode: str) -> None:
        self.protected_mode = protected_mode
        self.root = Path(tempfile.mkdtemp(prefix=f"t2_{protected_mode}_", dir="/private/tmp"))
        self.rw = self.root / "workspace"
        self.ro = self.root / "protected"
        shutil.copytree(HERE / "fixtures" / "workspace", self.rw)
        shutil.copytree(HERE / "fixtures" / "protected", self.ro)

    @property
    def target_host_path(self) -> Path:
        return self.ro / "forbidden.txt"

    def mounts(self) -> list[pm.MountDir]:
        return [
            pm.MountDir(virtual_path="/workspace", host_path=str(self.rw), mode="read-write"),
            pm.MountDir(virtual_path="/protected", host_path=str(self.ro), mode=self.protected_mode),
        ]

    def mount_table(self) -> list[dict]:
        return [
            {"virtual_path": m.virtual_path, "host_path": m.host_path, "mode": m.mode}
            for m in self.mounts()
        ]

    def physical_state(self) -> dict:
        state = {}
        for base in (self.rw, self.ro):
            for p in sorted(base.rglob("*")):
                if p.is_file() and not p.is_symlink():
                    state[str(p.relative_to(self.root))] = {
                        "bytes": p.stat().st_size,
                        "sha256": sha256_file(p),
                    }
        return state

    def host_perms(self) -> dict:
        st = self.target_host_path.stat()
        return {
            "mode_octal": oct(stat.S_IMODE(st.st_mode)),
            "uid": st.st_uid,
            "host_writable_by_process": os.access(self.target_host_path, os.W_OK),
        }

    def teardown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


async def run_condition(label: str, protected_mode: str) -> dict:
    """Ejecuta la operación de D4 con el pipeline real y el modo de mount dado."""
    ws = PairedWorkspace(protected_mode)
    rec = h.ChainRecorder(f"T2_{label}")
    h._RECORDER = rec
    try:
        before = ws.physical_state()
        digest_before = sha256_file(ws.target_host_path)
        perms = ws.host_perms()

        client = h.ScriptedChatClient([
            Content.from_function_call(
                call_id=label.lower(), name="controlled_write",
                arguments={"path": TARGET_VIRTUAL, "content": PAYLOAD},
            )
        ])
        agent = h.Agent(
            client=client, name="SynthT2",
            instructions="Ejecutor determinista de T2 (1D-R1).",
            tools=[h.make_controlled_write_tool(ws)],
        )
        session = agent.create_session()
        h.seed_rule(session, ToolApprovalRule(tool_name="controlled_write"))
        mw = ToolApprovalMiddleware()
        await h.run_chain_step(agent, session, mw, rec, input_text="escribe en protected")

        after = ws.physical_state()
        digest_after = sha256_file(ws.target_host_path)
        monty = rec.monty_results[0] if rec.monty_results else None
        written = digest_after != digest_before
        content_now = ws.target_host_path.read_text()

        return {
            "condition": label,
            "MOUNT_MODE_PROTECTED": protected_mode,
            "mount_table": ws.mount_table(),
            "REQUEST": {"tool": "controlled_write", "path": TARGET_VIRTUAL, "content": PAYLOAD},
            "APPROVAL": {"mode": "standing_rule", "state": "GRANTED",
                         "rules": len(h.state_of(session).rules)},
            "ACS_DECISION": rec.acs_log[0]["acs"]["decision"] if rec.acs_log else "NOT_REACHED",
            "HOST_BODY_ENTERED": len(rec.body_entered) > 0,
            "MONTY_RESULT": monty,
            "HOST_FS_PERMISSIONS": perms,
            "DIGEST_BEFORE": digest_before,
            "DIGEST_AFTER": digest_after,
            "PHYSICAL_WRITE": "YES" if written else "NO",
            "content_after": content_now if written else None,
            "physical_state_changed": after != before,
        }
    finally:
        ws.teardown()


def run_host_direct_control() -> dict:
    """T2-C: ¿permitía el SO/filesystem la escritura, fuera de Monty?

    Escribe directamente con el intérprete del host sobre una copia temporal
    y restaura el contenido original verificando el digest.
    """
    ws = PairedWorkspace("read-only")  # el modo del mount es irrelevante fuera de Monty
    try:
        target = ws.target_host_path
        original = target.read_bytes()
        digest_before = sha256_file(target)
        perms = ws.host_perms()
        error = None
        wrote = False
        try:
            with target.open("a", encoding="utf-8") as f:
                f.write(PAYLOAD + "\n")
            wrote = True
        except Exception as exc:  # noqa: BLE001
            error = f"{type(exc).__name__}: {exc}"
        digest_mid = sha256_file(target)
        # restauración verificada
        target.write_bytes(original)
        digest_restored = sha256_file(target)
        return {
            "condition": "T2-C_HOST_DIRECT_NO_MONTY",
            "executor": "host python interpreter (fuera de Monty)",
            "HOST_FS_PERMISSIONS": perms,
            "DIGEST_BEFORE": digest_before,
            "DIGEST_AFTER_WRITE": digest_mid,
            "DIGEST_AFTER_RESTORE": digest_restored,
            "restored_ok": digest_restored == digest_before,
            "error": error,
            "PHYSICAL_WRITE": "YES" if wrote and digest_mid != digest_before else "NO",
        }
    finally:
        ws.teardown()


async def main() -> int:
    started = datetime.now(timezone.utc)
    print("== T2 — Control negativo causal de D4 (0 tokens) ==\n")

    a = await run_condition("A_MONTY_READONLY", "read-only")
    b = await run_condition("B_MONTY_READWRITE", "read-write")
    c = run_host_direct_control()

    for row in (a, b):
        print(f"[{row['condition']}] mount /protected = {row['MOUNT_MODE_PROTECTED']}")
        print(f"    APPROVAL       = {row['APPROVAL']['state']}")
        print(f"    ACS_DECISION   = {row['ACS_DECISION']}")
        print(f"    HOST_BODY      = {'ENTERED' if row['HOST_BODY_ENTERED'] else 'NOT_REACHED'}")
        mr = row["MONTY_RESULT"]
        print(f"    MONTY_RESULT   = {(mr['error']['message'] if mr and mr['error'] else 'ok')}")
        print(f"    PHYSICAL_WRITE = {row['PHYSICAL_WRITE']}")
        print(f"    host_writable  = {row['HOST_FS_PERMISSIONS']['host_writable_by_process']} "
              f"mode={row['HOST_FS_PERMISSIONS']['mode_octal']}\n")
    print(f"[{c['condition']}]")
    print(f"    PHYSICAL_WRITE = {c['PHYSICAL_WRITE']}  (restaurado: {c['restored_ok']})")
    print(f"    error          = {c['error']}\n")

    # Invariantes del diseño pareado: todo idéntico salvo la capability Monty.
    paired_identical = {
        "same_request": a["REQUEST"] == b["REQUEST"],
        "same_approval_state": a["APPROVAL"]["state"] == b["APPROVAL"]["state"],
        "same_acs_decision": a["ACS_DECISION"] == b["ACS_DECISION"],
        "same_host_body_entered": a["HOST_BODY_ENTERED"] == b["HOST_BODY_ENTERED"],
        "same_target_digest_before": a["DIGEST_BEFORE"] == b["DIGEST_BEFORE"],
        "only_mount_mode_differs": a["MOUNT_MODE_PROTECTED"] != b["MOUNT_MODE_PROTECTED"],
    }
    causal = (
        a["PHYSICAL_WRITE"] == "NO"
        and b["PHYSICAL_WRITE"] == "YES"
        and all(paired_identical.values())
    )
    fs_permitted = c["PHYSICAL_WRITE"] == "YES"

    ev = {
        "phase": "ANKLA-AGT-1D-R1",
        "test": "T2_MONTY_NEGATIVE_CONTROL",
        "origin_finding": "M2 (ANKLA-MICROSOFT-1A-1D-EXTERNAL)",
        "started_utc": started.isoformat(),
        "llm_tokens": 0,
        "design": "pareado: mismo request/approval/ACS/host/payload; sólo varía MountDir.mode",
        "conditions": [a, b, c],
        "paired_invariants": paired_identical,
        "summary": {
            "T2_A_PHYSICAL_WRITE": a["PHYSICAL_WRITE"],
            "T2_B_PHYSICAL_WRITE": b["PHYSICAL_WRITE"],
            "T2_C_HOST_FS_PERMITTED_WRITE": c["PHYSICAL_WRITE"],
            "T2_MONTY_CAUSAL_CONTROL": "PASS" if causal else "FAIL",
            "MONTY_CAUSAL_FOR_D4": "SUPPORTED" if (causal and fs_permitted) else "NOT_SUPPORTED",
        },
        "finished_utc": datetime.now(timezone.utc).isoformat(),
    }
    EVIDENCE.mkdir(exist_ok=True)
    out = EVIDENCE / f"t2_monty_causal_{started.strftime('%Y%m%dT%H%M%SZ')}.json"
    payload = json.dumps(ev, ensure_ascii=False, indent=2, default=str)
    out.write_text(payload)
    (EVIDENCE / "t2_monty_causal_latest.json").write_text(payload)

    print("RESUMEN:")
    print(f"  T2-A (RO)  PHYSICAL_WRITE = {a['PHYSICAL_WRITE']}")
    print(f"  T2-B (RW)  PHYSICAL_WRITE = {b['PHYSICAL_WRITE']}")
    print(f"  T2-C (host) PHYSICAL_WRITE = {c['PHYSICAL_WRITE']}")
    print(f"  invariantes pareadas      = {all(paired_identical.values())} {paired_identical}")
    print(f"  T2_MONTY_CAUSAL_CONTROL   = {ev['summary']['T2_MONTY_CAUSAL_CONTROL']}")
    print(f"  MONTY_CAUSAL_FOR_D4       = {ev['summary']['MONTY_CAUSAL_FOR_D4']}")
    print(f"\nevidencia: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
