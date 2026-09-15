"""Capability factory con binding policy→zone — Fase 1E-R2.

Remediación de A9 (result_label scope trust, PARTIAL) y del cierre de A2
(alternate mount injection) de la revisión `ANKLA-AGT-1E-R1-EXTERNAL`:

    R1 validaba mount ⊆ label pero no demostraba que
    label == scope realmente autorizado por policy. Los result_labels no
    son por sí mismos raíz de confianza.

Cambio arquitectónico (regla de trust, §11 de la fase):

    R1:  OPA label lleva PATH → host confía en el path → mount creado.
    R2:  OPA elige una ZONA LÓGICA autorizada (sólo identidad)
         ↓
         zone_registry (raíz de confianza, pre-registrada por el HOST)
         resuelve la zona: capability, guest_root, host_root
         ↓
         la factory verifica la operación contra la zona
         ↓
         capability inmutable (sello HMAC) emitida.

La policy NO puede fabricar host_path ni mount path: sus labels sólo
seleccionan una identidad registrada. Un zone_id desconocido, malformado o
de otra capability es fail-closed (sin capability, sin runtime).

Camino único a Monty (registro mecánico, ver mechanical_suite R2-3):

    MONTY_RUNTIME_CREATION_PATHS    = 1   (GrantedCapability.run, capability.py)
    AUTHORIZED_PATHS                = 1
    UNAUTHORIZED_ALTERNATIVE_PATHS  = 0

La firma de la factory NO acepta mounts: `requested_mount` de R1 fue
eliminado — ningún caller/tool puede pedir mounts, host paths ni workspace
roots alternativos.
"""

from __future__ import annotations

import re
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from capability import (
    AUDIT,
    COUNTERS,
    GrantVerificationFailed,
    GrantedCapability,
    audit,
    audit_reset,
    audit_slice,
    canonical,
    contains,
    issue_grant_stamp,
)

# ----------------------------------------------------------------- constantes

KNOWN_CAPABILITIES = ("filesystem.write", "filesystem.read")

MODE_FOR = {"filesystem.write": "read-write", "filesystem.read": "read-only"}

ZONE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")

TRUST_ROOT = "zone_registry"


class CapabilityDenied(Exception):
    """La factory se niega a crear capability. `reason` es un código estable."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


# ------------------------------------------------------------ zone registry


@dataclass(frozen=True)
class Zone:
    """Zona lógica pre-registrada por el HOST (raíz de confianza).

    Inmutable: identidad, capability y RAÍCES físicas fijadas en el
    registro; ni policy ni caller pueden alterarlas después.
    """

    zone_id: str
    capability: str
    guest_root: str
    host_root: str


class ZoneRegistry:
    """Registro trusted de zonas: la única fuente de host/guest roots.

    Construido una vez por el host con zonas validadas; inmutable después
    (MappingProxyType + Zone frozen). Sin entrada no hay mount posible.
    """

    def __init__(self, zones: Iterable[Zone]) -> None:
        table: dict[str, Zone] = {}
        for zone in zones:
            if not isinstance(zone, Zone):
                raise CapabilityDenied("ZONE_INVALID", "no es una Zone")
            if not ZONE_ID_RE.match(zone.zone_id):
                raise CapabilityDenied("ZONE_ID_MALFORMED", zone.zone_id)
            if zone.capability not in KNOWN_CAPABILITIES:
                raise CapabilityDenied("ZONE_CAPABILITY_UNKNOWN", zone.capability)
            if canonical(zone.guest_root) != zone.guest_root:
                raise CapabilityDenied("ZONE_GUEST_ROOT_NOT_CANONICAL",
                                       zone.guest_root)
            host = Path(zone.host_root)
            if not host.is_absolute() or not host.is_dir():
                raise CapabilityDenied("ZONE_HOST_ROOT_INVALID", zone.host_root)
            if zone.zone_id in table:
                raise CapabilityDenied("ZONE_ID_DUPLICATED", zone.zone_id)
            table[zone.zone_id] = zone
        if not table:
            raise CapabilityDenied("ZONE_REGISTRY_EMPTY", "sin zonas")
        self._zones: Mapping[str, Zone] = MappingProxyType(table)

    def resolve(self, zone_id: str) -> Zone | None:
        return self._zones.get(zone_id)

    def zone_ids(self) -> tuple[str, ...]:
        return tuple(self._zones)

    def describe(self) -> dict:
        return {zid: {"capability": z.capability, "guest_root": z.guest_root,
                      "host_root": z.host_root}
                for zid, z in self._zones.items()}


# ------------------------------------------------------------ parseo de labels


def parse_zone_labels(result_labels) -> list[dict]:
    """Extrae identidades de zona de result_labels del veredicto.

    Formato: "zone:<capability>:<zone_id>". La policy nunca transporta
    paths: un label con forma antigua ("scope:...") o malformado es
    fail-closed (excepción del caller).
    """
    zones = []
    for label in result_labels or ():
        text = str(label)
        if not text.startswith("zone:"):
            raise CapabilityDenied("MALFORMED_ZONE_LABEL", text)
        rest = text[len("zone:"):]
        capability, sep, zone_id = rest.partition(":")
        if not sep or not capability or not zone_id:
            raise CapabilityDenied("MALFORMED_ZONE_LABEL", text)
        if capability not in KNOWN_CAPABILITIES:
            raise CapabilityDenied("MALFORMED_ZONE_LABEL", text)
        if not ZONE_ID_RE.match(zone_id):
            raise CapabilityDenied("MALFORMED_ZONE_LABEL", text)
        zones.append({"capability": capability, "zone_id": zone_id})
    return zones


# ------------------------------------------------------------------- factory


def capability_factory(
    policy_verdict: dict,
    operation: dict,
    *,
    zone_registry: ZoneRegistry,
):
    """Deriva una capability inmutable a partir de un veredicto de policy.

    policy_verdict: {"decision": ..., "result_labels": [...]} — salida ACS.
                    Los labels sólo NOMBRAN zonas lógicas autorizadas.
    operation:      {"capability": ..., "paths": [...]} — lo que la
                    invocación declara hacer (argumentos canónicos).
    zone_registry:  ZoneRegistry del HOST — raíz de confianza que resuelve
                    zona → capability/guest_root/host_root.

    Fail-closed: decision ≠ allow, labels ausentes/malformados, zona no
    registrada, operación no cubierta por la zona, invariantes rotas ⇒ sin
    capability y sin runtime.
    """
    decision = policy_verdict.get("decision")
    if decision != "allow":
        COUNTERS["factory_denials"] += 1
        audit("factory_denied", reason="POLICY_NOT_ALLOW", decision=decision)
        raise CapabilityDenied("POLICY_NOT_ALLOW", f"decision={decision}")

    try:
        labeled = parse_zone_labels(policy_verdict.get("result_labels"))
    except CapabilityDenied as denied:
        COUNTERS["factory_denials"] += 1
        audit("factory_denied", reason=denied.reason, detail=denied.detail)
        raise
    if not labeled:
        COUNTERS["factory_denials"] += 1
        audit("factory_denied", reason="NO_ZONE_LABELS")
        raise CapabilityDenied("NO_ZONE_LABELS", "verdict sin labels de zona")

    wanted = operation.get("capability", "filesystem.write")
    if wanted not in KNOWN_CAPABILITIES:
        COUNTERS["factory_denials"] += 1
        audit("factory_denied", reason="CAPABILITY_UNKNOWN", capability=wanted)
        raise CapabilityDenied("CAPABILITY_UNKNOWN", str(wanted))
    candidates = [z for z in labeled if z["capability"] == wanted]
    if not candidates:
        COUNTERS["factory_denials"] += 1
        audit("factory_denied", reason="NO_ZONE_FOR_CAPABILITY",
              capability=wanted,
              labeled=[z["zone_id"] for z in labeled])
        raise CapabilityDenied("NO_ZONE_FOR_CAPABILITY",
                               f"capability={wanted}")

    # Resolución TRUSTED: la policy nombra; el registro resuelve. Un
    # zone_id que el host no registró es fail-closed.
    resolved: list[Zone] = []
    for cand in candidates:
        zone = zone_registry.resolve(cand["zone_id"])
        if zone is None:
            COUNTERS["factory_denials"] += 1
            audit("factory_denied", reason="UNBOUND_ZONE_ID",
                  zone_id=cand["zone_id"])
            raise CapabilityDenied("UNBOUND_ZONE_ID", cand["zone_id"])
        resolved.append(zone)

    # Operación canónica: cualquier argumento no canonizable → fail-closed.
    op_paths = []
    for raw in operation.get("paths", []):
        c = canonical(raw)
        if c is None:
            COUNTERS["factory_denials"] += 1
            audit("factory_denied", reason="OPERATION_PATH_NOT_CANONICAL",
                  path=raw)
            raise CapabilityDenied("OPERATION_PATH_NOT_CANONICAL", str(raw))
        op_paths.append(c)

    covering = [z for z in resolved
                if all(contains(z.guest_root, p) for p in op_paths)]
    if not covering:
        COUNTERS["factory_denials"] += 1
        audit("factory_denied", reason="NO_ZONE_COVERS_OPERATION",
              operation_paths=op_paths,
              zones=[z.guest_root for z in resolved])
        raise CapabilityDenied("NO_ZONE_COVERS_OPERATION", f"paths={op_paths}")
    # La zona más específica (guest_root más largo) que cubre la operación.
    zone = max(covering, key=lambda z: len(z.guest_root))

    # Re-verificación de invariantes del registro (defensa en profundidad).
    if canonical(zone.guest_root) != zone.guest_root or \
            not contains(zone.guest_root, zone.guest_root):
        COUNTERS["factory_denials"] += 1
        audit("factory_denied", reason="ZONE_INVARIANT_BROKEN",
              zone_id=zone.zone_id)
        raise CapabilityDenied("ZONE_INVARIANT_BROKEN", zone.zone_id)

    # Verificación mecánica del binding: GRANT_SCOPE ⊆ ZONE_SCOPE (aquí
    # igualdad por construcción) para toda operación. Si no puede
    # demostrarse, fail-closed.
    verified = all(contains(zone.guest_root, p) for p in op_paths) \
        and contains(zone.guest_root, zone.guest_root)
    audit("zone_binding_verification",
          trust_root=TRUST_ROOT, zone_id=zone.zone_id,
          zone_guest_root=zone.guest_root, zone_host_root=zone.host_root,
          operation_paths=op_paths, binding_verified=verified)
    if not verified:
        COUNTERS["factory_denials"] += 1
        audit("factory_denied", reason="GRANT_CONTAINMENT_UNPROVABLE",
              zone_id=zone.zone_id)
        raise CapabilityDenied("GRANT_CONTAINMENT_UNPROVABLE", zone.zone_id)

    mode = MODE_FOR[wanted]

    granted_at = time.time()
    binding = tuple((z.capability, z.guest_root, z.zone_id) for z in resolved)
    payload = {
        "capability_type": wanted,
        "zone_id": zone.zone_id,
        "granted_scope": zone.guest_root,
        "mount_scope": zone.guest_root,
        "host_path": zone.host_root,
        "mode": mode,
        "operation_paths": op_paths,
        "policy_binding": [list(b) for b in binding],
        "granted_at": granted_at,
    }
    # El constructor verifica el sello en __post_init__: si el payload y los
    # campos no coinciden (bug o manipulación), el objeto NO LLEGA A EXISTIR.
    cap = GrantedCapability(
        capability_type=wanted,
        zone_id=zone.zone_id,
        granted_scope=zone.guest_root,
        mount_scope=zone.guest_root,
        host_path=zone.host_root,
        mode=mode,
        operation_paths=tuple(op_paths),
        policy_binding=binding,
        granted_at=granted_at,
        grant_stamp=issue_grant_stamp(payload),
    )

    COUNTERS["capabilities_created"] += 1
    audit("capability_created", identity=dict(cap.identity))
    return cap
