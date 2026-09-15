"""GrantedCapability inmutable — Fase 1E-R2 (capability integrity).

Remediación de los findings A3 (post-grant mutation) y parte de A2 (mount
injection) de la revisión externa `ANKLA-AGT-1E-R1-EXTERNAL`:

    GrantedCapability era mutable y run() volvía a leer atributos mutables
    sin revalidarlos → mount_before=/workspace/allowed RW, mutate,
    mount_after=/workspace RW, write quarantine succeeds.

Principio de diseño (el cambio respecto de R1):

  * NO más `if` dentro de la tool. NO confiar en que el consumidor "no
    modificará" el objeto. La capability es segura frente a un consumidor
    hostil dentro del modelo de amenaza experimental.

  * `frozen=True` SOLO no basta: un consumidor hostil con acceso Python puede
    saltárselo con `object.__setattr__`. Por eso la autenticidad NO descansa
    en la congelación sino en un **sello HMAC** calculado por la factory sobre
    la identidad completa del grant, con clave de proceso privada de este
    módulo:

      - `__post_init__` verifica el sello: un objeto forjado o un clon
        `dataclasses.replace(...)` con campos ampliados NO LLEGA A EXISTIR.
      - `run()` RE-VERIFICA el sello sobre los valores actuales de los campos
        antes de materializar nada: si alguien mutó el objeto por debajo de
        `frozen` (object.__setattr__), el runtime NO ARRANCA.
      - Los mounts se materializan DENTRO de run() a partir del grant
        verificado; no existe override posterior ni parámetro de mounts.

Propiedades under test:

    GRANT_IMMUTABLE_AFTER_CREATION
    MOUNT_DERIVED_ONLY_FROM_VALIDATED_GRANT

Límite declarado del modelo de amenaza: un atacante con ejecución arbitraria
en el proceso host está fuera de alcance (podría escribir el FS directamente
sin Monty). El consumidor hostil modelado es el cuerpo de la tool: recibe el
objeto capability e intenta ampliarlo por las interfaces disponibles.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import posixpath
import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

import pydantic_monty as pm

# ----------------------------------------------------------------- auditoría

AUDIT: list[dict] = []

COUNTERS = {
    "capabilities_created": 0,
    "factory_denials": 0,
    "monty_runtimes_started": 0,
    "grant_verifications_failed": 0,
    "run_refusals": 0,
}


def audit(kind: str, **fields) -> None:
    AUDIT.append({"ts": time.time(), "kind": kind, **fields})


def audit_reset() -> None:
    AUDIT.clear()


def audit_slice(since: int) -> list[dict]:
    return AUDIT[since:]


# --------------------------------------------------------------- excepciones


class GrantVerificationFailed(Exception):
    """El sello del grant no verifica: objeto forjado, clon mutado o grant
    alterado tras la creación. Fail-closed: sin ejecución."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


# ------------------------------------------------------------- geometría de scope


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


# ------------------------------------------------------------------- sello

# Clave HMAC de proceso, privada de este módulo. No viaja en el objeto, no es
# parámetro de ninguna función pública y no se expone por la factory.
_STAMP_KEY = secrets.token_bytes(32)

MODES = ("read-only", "read-write")

_STAMP_FIELDS = (
    "capability_type", "zone_id", "granted_scope", "mount_scope",
    "host_path", "mode", "operation_paths", "policy_binding", "granted_at",
)


def issue_grant_stamp(payload: dict) -> str:
    """Sello HMAC-SHA256 canónico de un grant. Sólo la factory (módulo
    trusted) lo llama: un consumidor no puede sellar grants arbitrarios."""
    msg = json.dumps(payload, sort_keys=True, ensure_ascii=False,
                     separators=(",", ":")).encode()
    return hmac.new(_STAMP_KEY, msg, hashlib.sha256).hexdigest()


# ----------------------------------------------------------------- capability


@dataclass(frozen=True)
class GrantedCapability:
    """Capability atenuada e inmutable: el único acceso del cuerpo a Monty.

    Inmutabilidad transitiva real (no sólo `frozen=True`):

      * campos escalares: congelados por dataclass;
      * `operation_paths`: tuple[str, ...] (inmutable);
      * `policy_binding`: tuple[tuple[str, str, str], ...] (inmutable);
      * `identity`: propiedad → MappingProxyType sobre snapshot FRESCO;
        mutarlo es imposible y no persiste;
      * `grant_stamp`: HMAC sobre TODOS los campos; cualquier mutación —
        incluso vía `object.__setattr__` que bypasea frozen — invalida el
        sello y `run()` se niega a arrancar runtime.
    """

    capability_type: str
    zone_id: str
    granted_scope: str
    mount_scope: str
    host_path: str
    mode: str
    operation_paths: tuple[str, ...]
    policy_binding: tuple[tuple[str, str, str], ...]
    granted_at: float
    grant_stamp: str

    def __post_init__(self) -> None:
        ok, reason = self.verify()
        if not ok:
            raise GrantVerificationFailed("GRANT_VERIFICATION_FAILED", reason)

    # ------------------------------------------------------------- verificación

    def stamp_payload(self) -> dict:
        return {
            "capability_type": self.capability_type,
            "zone_id": self.zone_id,
            "granted_scope": self.granted_scope,
            "mount_scope": self.mount_scope,
            "host_path": self.host_path,
            "mode": self.mode,
            "operation_paths": list(self.operation_paths),
            "policy_binding": [list(b) for b in self.policy_binding],
            "granted_at": self.granted_at,
        }

    def verify(self) -> tuple[bool, str]:
        """Re-verifica el sello sobre los valores ACTUALES de los campos."""
        if canonical(self.granted_scope) != self.granted_scope:
            return False, "GRANTED_SCOPE_NOT_CANONICAL"
        if canonical(self.mount_scope) != self.mount_scope:
            return False, "MOUNT_SCOPE_NOT_CANONICAL"
        if self.mode not in MODES:
            return False, "MODE_INVALID"
        if not isinstance(self.host_path, str) or not self.host_path.startswith("/"):
            return False, "HOST_PATH_NOT_ABSOLUTE"
        expected = issue_grant_stamp(self.stamp_payload())
        if not hmac.compare_digest(expected, str(self.grant_stamp)):
            return False, "STAMP_MISMATCH"
        return True, "VERIFIED"

    # ------------------------------------------------------------- vistas

    @property
    def mounts(self) -> list[pm.MountDir]:
        """Materialización de mounts SÓLO desde el grant verificado.

        Lista nueva en cada llamada (pydantic-monty exige list): ningún
        caller puede retener ni alterar la tabla que usará run().
        """
        ok, reason = self.verify()
        if not ok:
            raise GrantVerificationFailed("GRANT_VERIFICATION_FAILED", reason)
        return [pm.MountDir(virtual_path=self.mount_scope,
                            host_path=self.host_path, mode=self.mode)]

    def mount_table(self) -> tuple[dict, ...]:
        return tuple({"virtual_path": m.virtual_path, "host_path": m.host_path,
                      "mode": m.mode} for m in self.mounts)

    @property
    def identity(self) -> Mapping:
        ok, reason = self.verify()
        snapshot = {
            "CAPABILITY_TYPE": self.capability_type,
            "ZONE_ID": self.zone_id,
            "GRANTED_SCOPE": self.granted_scope,
            "MOUNT_SCOPE": self.mount_scope,
            "HOST_PATH": self.host_path,
            "MODE": self.mode,
            "OPERATION_PATHS": list(self.operation_paths),
            "POLICY_BINDING": [list(b) for b in self.policy_binding],
            "GRANTED_AT": self.granted_at,
            "TRUST_ROOT": "zone_registry",
            "GRANT_VERIFIED": ok,
            "GRANT_VERIFY_REASON": reason,
        }
        return MappingProxyType(snapshot)

    # ------------------------------------------------------------- ejecución

    def run(self, code: str, *, label: str = "") -> dict:
        """Ejecuta código en Monty con EXACTAMENTE los mounts de esta capability.

        No acepta mounts, host paths ni kwargs de ampliación: la firma no los
        tiene. Antes de materializar nada re-verifica el sello del grant; si
        el objeto fue alterado (incluso por debajo de frozen), NO hay runtime.
        """
        ok, reason = self.verify()
        if not ok:
            COUNTERS["grant_verifications_failed"] += 1
            COUNTERS["run_refusals"] += 1
            audit("run_refused", label=label, reason=reason,
                  grant_stamp_valid=False)
            raise GrantVerificationFailed("GRANT_VERIFICATION_FAILED", reason)
        mounts = self.mounts
        COUNTERS["monty_runtimes_started"] += 1
        audit("monty_runtime_started", label=label, grant_verified=True,
              mounts=self.mount_table())
        chunks: list[str] = []
        try:
            with pm.Monty() as pool:
                with pool.checkout(script_name="r2_capability.py") as session:
                    session.feed_run(
                        code, print_callback=lambda _s, t: chunks.append(t),
                        mount=mounts)
        except Exception as exc:  # noqa: BLE001 — el error de Monty es dato
            return {"stdout": "".join(chunks),
                    "error": {"type": type(exc).__name__, "message": str(exc)}}
        return {"stdout": "".join(chunks), "error": None}
