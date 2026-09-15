"""Capability factory experimental — Fase 1E-R1 (capability confinement).

Única responsabilidad: convertir un grant autorizado en mounts efectivos de
Monty, atenuados al scope autorizado por la policy.

    policy result (ACS verdict, result_labels "scope:<capability>:<path>")
        ↓
    authorized scope
        ↓
    capability_factory
        ↓
    Monty mounts (MountDir guest=scope, host=zona registrada)

Propiedad under test:

    policy scope >= granted capability scope >= effective operation scope

forma estricta:

    granted capability scope ⊆ policy-authorized scope

Reglas fail-closed (cualquier incapacidad de demostrar la propiedad ⇒ no hay
capability y no se ejecuta tool):

  * decision != "allow"            → sin capability.
  * labels de scope ausentes o malformados → sin capability.
  * requested_mount no ⊆ policy scope → DENY (anti-ampliación, R1-G).
  * ningún scope cubre la operación canónica → sin capability.
  * mount scope sin binding a zona host registrada → sin capability.
  * MOUNT_SCOPE ⊆ POLICY_SCOPE no demostrable → sin capability.

La capability concedida es el ÚNICO camino hacia Monty del cuerpo de la tool:
el cuerpo no recibe el workspace ni rutas de host, sólo este objeto. Ningún
componente de AGT/ACS/OPA/Monty/AN-KLA se modifica: esto es un harness nuevo.
"""

from __future__ import annotations

import posixpath
import time
from dataclasses import dataclass, field

import pydantic_monty as pm

# ----------------------------------------------------------------- auditoría

AUDIT: list[dict] = []

COUNTERS = {"capabilities_created": 0, "factory_denials": 0, "monty_runtimes_started": 0}


def audit(kind: str, **fields) -> None:
    AUDIT.append({"ts": time.time(), "kind": kind, **fields})


def audit_reset() -> None:
    AUDIT.clear()


def audit_slice(since: int) -> list[dict]:
    return AUDIT[since:]


# ------------------------------------------------------------- geometría de scope


class CapabilityDenied(Exception):
    """La factory se niega a crear capability. `reason` es un código estable."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


def canonical(path: str) -> str | None:
    """Canoniza un path virtual. None si no es absoluto o queda '..' residual.

    Espejo en Python de la canonicalización de la policy (fold de segmentos):
    un path que la policy no puede canonizar jamás obtiene capability.
    """
    if not isinstance(path, str) or not path.startswith("/"):
        return None
    norm = posixpath.normpath(path)
    if norm == ".":
        return None
    parts = [s for s in norm.split("/") if s not in ("", ".")]
    if ".." in parts:
        return None
    return "/" + "/".join(parts)


def contains(scope: str, path: str) -> bool:
    """¿Está `path` dentro de `scope` con frontera de segmento?

    contains("/workspace/allowed", "/workspace/allowed2") == False — evita el
    bug clásico de prefix matching por cuerda.
    """
    s, p = canonical(scope), canonical(path)
    if s is None or p is None:
        return False
    return p == s or p.startswith(s + "/")


# ------------------------------------------------------------- parseo de labels


def parse_scope_labels(result_labels) -> list[dict]:
    """Extrae scopes autorizados de result_labels del veredicto.

    Formato: "scope:<capability>:<path>" (el path puede contener ':').
    Cualquier label "scope:" malformado es fail-closed (excepción del caller).
    """
    scopes = []
    for label in result_labels or ():
        text = str(label)
        if not text.startswith("scope:"):
            continue
        rest = text[len("scope:"):]
        capability, sep, path = rest.partition(":")
        if not sep or not capability or not path.startswith("/"):
            raise CapabilityDenied("MALFORMED_SCOPE_LABEL", text)
        if canonical(path) is None:
            raise CapabilityDenied("MALFORMED_SCOPE_LABEL", text)
        scopes.append({"capability": capability, "path": canonical(path)})
    return scopes


# ----------------------------------------------------------------- capability


@dataclass
class GrantedCapability:
    """Capability atenuada: el único acceso del cuerpo de la tool a Monty."""

    capability_type: str
    policy_scopes: list[dict]          # tal como la policy las autorizó
    granted_scope: str                 # scope atenuado entregado
    mount_scope: str                   = ""
    host_path: str                     = ""
    mode: str                          = "read-write"
    operation_paths: list[str]         = field(default_factory=list)
    identity: dict                     = field(default_factory=dict)

    @property
    def mounts(self) -> list[pm.MountDir]:
        return [pm.MountDir(virtual_path=self.mount_scope,
                            host_path=self.host_path, mode=self.mode)]

    def mount_table(self) -> list[dict]:
        return [{"virtual_path": m.virtual_path, "host_path": m.host_path,
                 "mode": m.mode} for m in self.mounts]

    def run(self, code: str, *, label: str = "") -> dict:
        """Ejecuta código en Monty con EXACTAMENTE los mounts de esta capability.

        No acepta mounts externos: el consumidor no puede ampliar la capability.
        """
        COUNTERS["monty_runtimes_started"] += 1
        audit("monty_runtime_started", label=label,
              mounts=self.mount_table())
        chunks: list[str] = []
        try:
            with pm.Monty() as pool:
                with pool.checkout(script_name="r1_capability.py") as session:
                    session.feed_run(
                        code, print_callback=lambda _s, t: chunks.append(t),
                        mount=self.mounts)
        except Exception as exc:  # noqa: BLE001 — el error de Monty es dato
            return {"stdout": "".join(chunks),
                    "error": {"type": type(exc).__name__, "message": str(exc)}}
        return {"stdout": "".join(chunks), "error": None}


# ------------------------------------------------------------------- factory


def capability_factory(
    policy_verdict: dict,
    operation: dict,
    *,
    zone_registry: dict[str, str],
    requested_mount: str | None = None,
) -> GrantedCapability:
    """Deriva una capability atenuada a partir de un veredicto de policy.

    policy_verdict: {"decision": ..., "result_labels": [...]} — salida ACS.
    operation:      {"capability": "filesystem.write", "paths": [..]} — lo que
                    la invocación declara hacer (argumentos canónicos).
    zone_registry:  {scope_path: host_path} — zonas físicas registradas por el
                    host. Sin binding exacto no hay mount.
    requested_mount: si un caller pide un mount concreto, debe estar CONTENIDO
                    en el scope de policy; pedir más ancho es DENY (R1-G).
    """
    decision = policy_verdict.get("decision")
    if decision != "allow":
        COUNTERS["factory_denials"] += 1
        audit("factory_denied", reason="POLICY_NOT_ALLOW", decision=decision)
        raise CapabilityDenied("POLICY_NOT_ALLOW", f"decision={decision}")

    try:
        scopes = parse_scope_labels(policy_verdict.get("result_labels"))
    except CapabilityDenied as denied:
        COUNTERS["factory_denials"] += 1
        audit("factory_denied", reason=denied.reason, detail=denied.detail)
        raise

    wanted = operation.get("capability", "filesystem.write")
    policy_scopes = [s for s in scopes if s["capability"] == wanted]
    if not policy_scopes:
        COUNTERS["factory_denials"] += 1
        audit("factory_denied", reason="NO_AUTHORIZED_SCOPE", capability=wanted)
        raise CapabilityDenied("NO_AUTHORIZED_SCOPE", f"capability={wanted}")

    # Operación canónica: cualquier argumento no canonizable → fail-closed.
    op_paths = []
    for raw in operation.get("paths", []):
        c = canonical(raw)
        if c is None:
            COUNTERS["factory_denials"] += 1
            audit("factory_denied", reason="OPERATION_PATH_NOT_CANONICAL", path=raw)
            raise CapabilityDenied("OPERATION_PATH_NOT_CANONICAL", str(raw))
        op_paths.append(c)

    if requested_mount is not None:
        req = canonical(requested_mount)
        if req is None:
            COUNTERS["factory_denials"] += 1
            audit("factory_denied", reason="MOUNT_REQUEST_NOT_CANONICAL",
                  requested=requested_mount)
            raise CapabilityDenied("MOUNT_REQUEST_NOT_CANONICAL", str(requested_mount))
        covering = [s for s in policy_scopes if contains(s["path"], req)]
        if not covering:
            # Anti-ampliación: el mount pedido excede el scope autorizado.
            COUNTERS["factory_denials"] += 1
            audit("factory_denied", reason="OVERBROAD_MOUNT_REQUEST",
                  requested=req,
                  policy_scopes=[s["path"] for s in policy_scopes])
            raise CapabilityDenied("OVERBROAD_MOUNT_REQUEST",
                                   f"requested={req} policy={[s['path'] for s in policy_scopes]}")
        mount_scope = req
        authorizing = covering[0]
    else:
        covering = [s for s in policy_scopes
                    if all(contains(s["path"], p) for p in op_paths)]
        if not covering:
            COUNTERS["factory_denials"] += 1
            audit("factory_denied", reason="NO_SCOPE_COVERS_OPERATION",
                  operation_paths=op_paths,
                  policy_scopes=[s["path"] for s in policy_scopes])
            raise CapabilityDenied("NO_SCOPE_COVERS_OPERATION", f"paths={op_paths}")
        # La atenuación toma el scope MÁS ESPECÍFICO (más largo) que cubre la
        # operación: nunca un ancestro común más amplio.
        authorizing = max(covering, key=lambda s: len(s["path"]))
        mount_scope = authorizing["path"]

    host_path = zone_registry.get(mount_scope)
    if host_path is None:
        COUNTERS["factory_denials"] += 1
        audit("factory_denied", reason="UNBOUND_MOUNT_SCOPE", mount_scope=mount_scope)
        raise CapabilityDenied("UNBOUND_MOUNT_SCOPE", mount_scope)

    # Verificación mecánica de la propiedad under test. Si no puede
    # demostrarse, fail-closed: sin capability, sin ejecución.
    verified = contains(authorizing["path"], mount_scope)
    audit("capability_scope_verification",
          policy_scope=authorizing["path"], mount_scope=mount_scope,
          contains=verified)
    if not verified:
        COUNTERS["factory_denials"] += 1
        audit("factory_denied", reason="SCOPE_CONTAINMENT_UNPROVABLE",
              policy_scope=authorizing["path"], mount_scope=mount_scope)
        raise CapabilityDenied("SCOPE_CONTAINMENT_UNPROVABLE",
                               f"{mount_scope} ⊄ {authorizing['path']}")

    mode = {"filesystem.write": "read-write", "filesystem.read": "read-only"}[wanted]
    cap = GrantedCapability(
        capability_type=wanted,
        policy_scopes=policy_scopes,
        granted_scope=mount_scope,
        mount_scope=mount_scope,
        host_path=host_path,
        mode=mode,
        operation_paths=op_paths,
    )
    cap.identity = {
        "CAPABILITY_TYPE": wanted,
        "POLICY_SCOPE": [s["path"] for s in policy_scopes],
        "GRANTED_SCOPE": cap.granted_scope,
        "MOUNT_SCOPE": cap.mount_scope,
        "MOUNT_SCOPE_IN_POLICY_SCOPE": verified,
        "MODE": mode,
        "HOST_PATH": host_path,
        "OPERATION_PATHS": op_paths,
        "REQUESTED_MOUNT": requested_mount,
    }
    COUNTERS["capabilities_created"] += 1
    audit("capability_created", identity=cap.identity)
    return cap
