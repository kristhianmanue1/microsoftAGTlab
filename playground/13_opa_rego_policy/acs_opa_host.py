"""Host Fase 1D-R2 — cadena con policy declarativa real (ACS → OPA → Rego).

Origen: H1 de la revisión adversarial externa ANKLA-MICROSOFT-1A-1D-EXTERNAL,
reafirmado OPEN por la Fase 1D-R1.

Diferencia esencial con 1A/1D/1D-R1:

    `AgentControl.from_path(manifest)` se construye **SIN** `policy_dispatcher`.

Sin ese argumento, ACS usa su dispatcher bundled, que sólo soporta policies
Rego y ejecuta el binario OPA. Ninguna decisión de policy de esta fase proviene
de código Python del laboratorio.

Contrato de ACS 0.3.1b1 verificado empíricamente (§3 de la fase; no copiado de
otra versión):

  * `policies.<id>.type: rego` + `policies.<id>.bundle: <DIRECTORIO relativo>`
    — el bundle es una ruta de directorio resuelta contra el manifest. Una ruta
    a fichero concreto o absoluta produce `runtime_error:policy_invocation_failed`.
  * la `query` vive en `intervention_points.<ip>.policy.query`, no en la policy.
  * el ejecutable OPA se localiza por `ACS_OPA_PATH`, si no por `opa` en PATH.
  * timeout configurable por `ACS_OPA_TIMEOUT_MS`.
  * shape del input entregado a Rego:
        {intervention_point, policy_target:{kind,path,value}, snapshot,
         annotations, tool}

Nota sobre el manifest de la Fase 1D: declaraba `rego: |` con texto inline y
NINGUNA clave `bundle`. Bajo este contrato ese bloque nunca se estaciona ni se
evalúa — confirmación estructural de H1, independiente de la inferencia hecha
por la revisión externa. Además usaba sintaxis Rego v0, que OPA 1.20 ni
siquiera compila.

Reutiliza la ejecución en Monty de 1D (`controlled_write_impl`) sin modificar
1D. La capa de approval es la real del framework.

0 tokens. Sin LLM.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pydantic_monty as pm
from agent_framework import (
    Content,
    FunctionInvocationContext,
    FunctionMiddleware,
    MiddlewareTermination,
    ToolApprovalMiddleware,
    ToolApprovalRule,
)

HERE = Path(__file__).resolve().parent
LAB = HERE.parent.parent
EVIDENCE = HERE / "evidence"
MANIFEST = HERE / "manifest.yaml"
POLICY_DIR = HERE / "policy"
REGO = POLICY_DIR / "filesystem.rego"
QUERY = "data.acs.verdict"

# El binario OPA se localiza una sola vez y se publica en el entorno para que
# el dispatcher bundled de ACS lo encuentre.
def resolve_opa() -> str:
    explicit = os.environ.get("ACS_OPA_PATH")
    if explicit and Path(explicit).exists():
        return explicit
    found = shutil.which("opa")
    if found:
        return found
    local = Path.home() / ".local" / "bin" / "opa"
    if local.exists():
        return str(local)
    raise RuntimeError("no se encontró el ejecutable opa")


OPA_PATH = resolve_opa()
os.environ["ACS_OPA_PATH"] = OPA_PATH

# 1D se importa para reutilizar Monty, el cliente scripted y helpers de approval.
# Su EVIDENCE se redirige: 1D-R2 nunca escribe dentro de 1D.
_spec = importlib.util.spec_from_file_location(
    "integrated_host", LAB / "playground" / "11_integrated_authority_chain" / "integrated_host.py"
)
h = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(h)
h.EVIDENCE = EVIDENCE
h._p1a.EVIDENCE = EVIDENCE
h._p1b.EVIDENCE = EVIDENCE

ScriptedChatClient = h.ScriptedChatClient
ChainRecorder = h.ChainRecorder
seed_rule = h.seed_rule
state_of = h.state_of
pending_request_of = h.pending_request_of
approval_response = h.approval_response

ALLOWED_PATH = "/workspace/allowed/output.txt"
QUARANTINE_PATH = "/workspace/quarantine/target.txt"
PROTECTED_PATH = "/protected/forbidden.txt"


def sha256_file(p: Path) -> str:
    return "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest()


def opa_identity() -> dict:
    out = subprocess.run([OPA_PATH, "version"], capture_output=True, text=True, check=True).stdout
    info = {}
    for line in out.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            info[k.strip()] = v.strip()
    return {
        "executable": OPA_PATH,
        "version": info.get("Version"),
        "rego_version": info.get("Rego Version"),
        "platform": info.get("Platform"),
        "build_commit": info.get("Build Commit"),
        "executable_sha256": sha256_file(Path(OPA_PATH)),
    }


# --------------------------------------------------------------- ACS sin dispatcher

_CONTROL_CACHE: dict[str, object] = {}


def build_control(manifest_path: Path | None = None, *, fresh: bool = False):
    """AgentControl SIN policy_dispatcher → dispatcher bundled OPA de ACS."""
    from agent_control_specification import AgentControl

    key = str(manifest_path or MANIFEST)
    if fresh or key not in _CONTROL_CACHE:
        _CONTROL_CACHE[key] = AgentControl.from_path(key)  # <-- sin policy_dispatcher
    return _CONTROL_CACHE[key]


async def acs_evaluate(tool_name: str, args, *, manifest_path: Path | None = None,
                       control=None) -> dict:
    """Evalúa pre_tool_call. La decisión la produce OPA, no este proceso."""
    ctl = control or build_control(manifest_path)
    t0 = time.time()
    try:
        res = await ctl.evaluate_intervention_point(
            "pre_tool_call", {"tool_call": {"name": tool_name, "args": args}}
        )
    except Exception as exc:  # noqa: BLE001 — se registra, nunca se convierte en allow
        return {
            "decision": "deny",
            "reason": f"exception:{type(exc).__name__}",
            "message": str(exc)[:300],
            "elapsed_ms": round((time.time() - t0) * 1000, 1),
            "policy_input": None,
            "raised": True,
        }
    return {
        "decision": res.verdict.decision.value,
        "reason": res.verdict.reason,
        "message": res.verdict.message,
        "elapsed_ms": round((time.time() - t0) * 1000, 1),
        "policy_input": res.policy_input,
        "raised": False,
    }


class AcsOpaMiddleware(FunctionMiddleware):
    """L4: el veredicto de OPA/Rego gobierna si el cuerpo de la tool se ejecuta."""

    def __init__(self, acs_log: list, control=None) -> None:
        self.acs_log = acs_log
        self.control = control

    async def process(self, context: FunctionInvocationContext, call_next) -> None:
        name = context.function.name
        raw = context.arguments
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except json.JSONDecodeError:
                raw = {"_raw": raw}
        args = raw if isinstance(raw, dict) else {}
        verdict = await acs_evaluate(name, args, control=self.control)
        self.acs_log.append({"ts": time.time(), "tool": name, "args": args, "acs": verdict})
        if verdict["decision"] != "allow":
            context.result = {
                "error": "ACS policy DENY (OPA/Rego)",
                "tool": name,
                "reason": verdict["reason"] or verdict["message"],
            }
            raise MiddlewareTermination(f"ACS/OPA denied tool {name}")
        await call_next()


# --------------------------------------------------------------- workspace / Monty


class R2Workspace:
    """/workspace RW (allowed/, allowed/sub/, quarantine/) y /protected RO."""

    def __init__(self, protected_mode: str = "read-only") -> None:
        self.protected_mode = protected_mode
        self.root = Path(tempfile.mkdtemp(prefix="opa_r2_", dir="/private/tmp"))
        self.rw = self.root / "workspace"
        self.ro = self.root / "protected"
        shutil.copytree(HERE / "fixtures" / "workspace", self.rw)
        shutil.copytree(HERE / "fixtures" / "protected", self.ro)

    def mounts(self) -> list[pm.MountDir]:
        return [
            pm.MountDir(virtual_path="/workspace", host_path=str(self.rw), mode="read-write"),
            pm.MountDir(virtual_path="/protected", host_path=str(self.ro), mode=self.protected_mode),
        ]

    def mount_table(self) -> list[dict]:
        return [{"virtual_path": m.virtual_path, "host_path": m.host_path, "mode": m.mode}
                for m in self.mounts()]

    def physical_state(self) -> dict:
        state = {}
        for base in (self.rw, self.ro):
            for p in sorted(base.rglob("*")):
                if p.is_file() and not p.is_symlink():
                    state[str(p.relative_to(self.root))] = {
                        "bytes": p.stat().st_size, "sha256": sha256_file(p)}
        return state

    def teardown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


def make_tool(ws: R2Workspace):
    """Tool `controlled_write` con approval real; el cuerpo ejecuta en Monty (1D)."""
    from agent_framework import tool as tool_dec

    @tool_dec(name="controlled_write", approval_mode="always_require")
    async def _impl(path: str, content: str) -> dict:
        return await h.controlled_write_impl(path, content, ws)

    return _impl


def build_agent(ws: R2Workspace, steps: list[Content]):
    return h.Agent(
        client=ScriptedChatClient(steps),
        name="SynthR2",
        instructions="Ejecutor determinista del experimento 1D-R2.",
        tools=[make_tool(ws)],
    )


async def run_chain(agent, session, mw, rec, control=None, *, input_text=None, messages=None):
    """Approval (L3) → ACS/OPA (L4) → host (L5) → Monty (L6)."""
    return await agent.run(
        messages if messages is not None else input_text,
        session=session,
        middleware=[mw, AcsOpaMiddleware(rec.acs_log, control)],
    )


def call(call_id: str, path: str, content: str = "R2", name: str = "controlled_write") -> Content:
    return Content.from_function_call(
        call_id=call_id, name=name, arguments={"path": path, "content": content}
    )
