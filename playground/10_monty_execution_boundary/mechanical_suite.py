"""Fase 1C — Suite mecánica de frontera de ejecución Monty.

0 tokens, sin LLM. Ejecuta C1-C10 más el test de código controlado (sección 8)
y registra evidencia por caso en evidence/.

Hallazgo de API documentado en C0: el bridge oficial
``agent_framework_monty.MontyExecuteCodeTool`` (1.0.0b260730) es incompatible
con ``pydantic-monty`` 0.0.23 (espera la API en-proceso antigua
``Monty(code).start()``; la versión instalada expone un worker-pool
``Monty() -> checkout() -> feed_run()``). La suite conduce por tanto
``pydantic_monty.MontySession.feed_run`` directamente.

Uso:
    .venv/bin/python playground/10_monty_execution_boundary/mechanical_suite.py

Los fixtures se copian a un directorio temporal bajo /private/tmp; los archivos
in-repo bajo fixtures/ nunca se modifican y el worktree se mantiene limpio.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import pydantic_monty as pm

LAB = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "evidence"
FIXTURES = HERE / "fixtures"

READONLY_CODE = "from pathlib import Path\n"
PROTECTED_VIRTUAL = "/data/protected.txt"
MUTABLE_VIRTUAL = "/work/mutable.txt"
OUTSIDE_VIRTUAL = "/outside/forbidden.txt"
SECRET_LINE = "EDITADO-POR-AGENTE"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class Snapshot:
    """Estado físico de los archivos del workspace temporal."""

    files: dict[str, tuple[int, str]] = field(default_factory=dict)

    def as_dict(self) -> dict[str, dict[str, object]]:
        return {
            path: {"bytes": size, "sha256": digest}
            for path, (size, digest) in sorted(self.files.items())
        }


def snapshot(root: Path) -> Snapshot:
    state = Snapshot()
    for p in sorted(root.rglob("*")):
        if p.is_symlink():
            state.files[str(p.relative_to(root))] = ("symlink", p.readlink().as_posix())
        elif p.is_file():
            data = p.read_bytes()
            state.files[str(p.relative_to(root))] = (len(data), sha256_bytes(data))
    return state


class Workspace:
    """Copia temporal de fixtures bajo /private/tmp con symlinks preparados."""

    def __init__(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="monty_boundary_1c_", dir="/private/tmp"))
        self.ro = self.root / "ro"
        self.rw = self.root / "rw"
        self.outside = self.root / "outside"
        shutil.copytree(FIXTURES / "readonly", self.ro)
        shutil.copytree(FIXTURES / "readwrite", self.rw)
        shutil.copytree(FIXTURES / "outside", self.outside)
        # Symlinks controlados para C7 (creados por el HOST, visibles en los mounts)
        (self.rw / "leak.lnk").symlink_to(self.outside / "forbidden.txt")
        (self.ro / "leak.lnk").symlink_to(self.outside / "forbidden.txt")

    def mount_ro(self) -> pm.MountDir:
        return pm.MountDir(virtual_path="/data", host_path=str(self.ro), mode="read-only")

    def mount_rw(self, write_bytes_limit: int | None = None) -> pm.MountDir:
        return pm.MountDir(
            virtual_path="/work",
            host_path=str(self.rw),
            mode="read-write",
            write_bytes_limit=write_bytes_limit,
        )

    def teardown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


def feed(code: str, mounts: list[pm.MountDir]) -> dict[str, object]:
    """Ejecuta un snippet en Monty y devuelve {stdout, error} sin lanzar."""
    chunks: list[str] = []
    feed_kwargs: dict[str, object] = {"print_callback": lambda stream, text: chunks.append(text)}
    if mounts:
        feed_kwargs["mount"] = mounts
    try:
        with pm.Monty() as pool:
            with pool.checkout(script_name="boundary_case.py") as session:
                session.feed_run(code, **feed_kwargs)  # type: ignore[arg-type]
    except Exception as exc:  # MontyRuntimeError envuelve errores del intérprete
        return {"stdout": "".join(chunks), "error": {"type": type(exc).__name__, "message": str(exc)}}
    return {"stdout": "".join(chunks), "error": None}


@dataclass
class Case:
    id: str
    description: str
    expected: str
    code: str
    mounts: list[pm.MountDir]
    check: object  # Callable[[dict, Workspace, Snapshot, Snapshot], tuple[bool, str]]
    informational: bool = False


def verdict_of(case: Case, result: dict, ws: Workspace, before: Snapshot, after: Snapshot) -> tuple[bool, str]:
    return case.check(result, ws, before, after)  # type: ignore[operator]


# ---------- checks por caso ----------


def check_c1(result: dict, ws: Workspace, before: Snapshot, after: Snapshot) -> tuple[bool, str]:
    if result["error"] is not None:
        return False, f"lectura falló: {result['error']}"
    out = str(result["stdout"])
    if "CONTENIDO-PROTEGIDO-1C" not in out:
        return False, f"contenido esperado ausente en stdout: {out!r}"
    if before.files != after.files:
        return False, "estado físico cambió en un caso de sólo lectura"
    data = (ws.ro / "protected.txt").read_bytes()
    return True, f"READ_ALLOWED=YES bytes={len(data)} sha256={sha256_bytes(data)}"


def _denied_with(result: dict, needle: str) -> bool:
    err = result["error"]
    return err is not None and needle in err["message"]


def check_c2(result: dict, ws: Workspace, before: Snapshot, after: Snapshot) -> tuple[bool, str]:
    if not _denied_with(result, "Read-only file system"):
        return False, f"escritura no fue denegada: {result['error']}"
    if before.files != after.files:
        return False, "ORIGINAL_CONTENT_UNCHANGED=NO: el estado físico cambió"
    data = (ws.ro / "protected.txt").read_bytes()
    ok = b"CONTENIDO-PROTEGIDO-1C" in data and SECRET_LINE.encode() not in data
    return ok, "WRITE_ALLOWED=NO ORIGINAL_CONTENT_UNCHANGED=YES (verificado físicamente)"


def check_c3(result: dict, ws: Workspace, before: Snapshot, after: Snapshot) -> tuple[bool, str]:
    if not _denied_with(result, "Read-only file system"):
        return False, f"creación no fue denegada: {result['error']}"
    if (ws.ro / "new.txt").exists():
        return False, "new.txt fue creado en el host"
    if before.files != after.files:
        return False, "estado físico cambió"
    return True, "CREATE_IN_READONLY=DENIED"


def check_c4(result: dict, ws: Workspace, before: Snapshot, after: Snapshot) -> tuple[bool, str]:
    out = str(result["stdout"])
    if result["error"] is not None:
        return False, f"error: {result['error']}"
    if "INICIAL-MUTABLE" not in out or "ESCRITO-POR-SUITE-1C" not in out:
        return False, f"readback incompleto: {out!r}"
    host_data = (ws.rw / "mutable.txt").read_bytes()
    if host_data != b"ESCRITO-POR-SUITE-1C\n":
        return False, f"write-through al host incorrecto: {host_data!r}"
    return True, "RW_READ=PASS RW_WRITE=PASS RW_READBACK=PASS (write-through verificado)"


def check_c5(result: dict, ws: Workspace, before: Snapshot, after: Snapshot) -> tuple[bool, str]:
    err = result["error"]
    if err is None:
        return False, f"lectura fuera de scope permitida: stdout={result['stdout']!r}"
    if "PermissionError" not in err["type"] and "PermissionError" not in err["message"]:
        return False, f"denegado con tipo inesperado: {err}"
    if "FORBIDDEN-FIXTURE" in str(result["stdout"]):
        return False, "contenido prohibido apareció en stdout"
    data = (ws.outside / "forbidden.txt").read_bytes()
    if b"FORBIDDEN-FIXTURE" not in data:
        return False, "el fixture fuera de scope fue alterado"
    return True, f"OUT_OF_SCOPE_READ=DENIED ({err['type']}: {err['message'][:80]})"


def check_c6(result: dict, ws: Workspace, before: Snapshot, after: Snapshot) -> tuple[bool, str]:
    # result aquí es {'t1':..., 't2':...} preparado por el caso
    for tag, r in result.items():  # type: ignore[union-attr]
        err = r["error"]
        if err is None or "FORBIDDEN" in str(r["stdout"]) or "root" in str(r["stdout"]):
            return False, f"traversal {tag} escapó: {r}"
        if "PermissionError" not in err["type"] and "PermissionError" not in err["message"]:
            return False, f"traversal {tag} denegado con tipo inesperado: {err}"
    data = (ws.outside / "forbidden.txt").read_bytes()
    return True, f"PATH_TRAVERSAL_ESCAPE=DENIED (2 variantes, Forbidden intacta: {b'FORBIDDEN-FIXTURE' in data})"


def check_c7(result: dict, ws: Workspace, before: Snapshot, after: Snapshot) -> tuple[bool, str]:
    # result = {'rw_read':..., 'rw_write':..., 'ro_read':..., 'ro_write':...}
    details = {}
    for tag, r in result.items():  # type: ignore[union-attr]
        err = r["error"]
        denied = err is not None and ("PermissionError" in err["type"] or "PermissionError" in err["message"])
        details[tag] = "DENIED" if denied else f"NOT_DENIED({r['stdout']!r})"
    target = ws.outside / "forbidden.txt"
    intact = b"FORBIDDEN-FIXTURE" in target.read_bytes()
    all_denied = all(v == "DENIED" for v in details.values())
    verdict = (
        f"SYMLINK_ESCAPE_READ={details['rw_read']}/{details['ro_read']} "
        f"SYMLINK_ESCAPE_WRITE={details['rw_write']}/{details['ro_write']} target_intact={intact}"
    )
    return all_denied and intact, verdict


def check_c8(result: dict, ws: Workspace, before: Snapshot, after: Snapshot) -> tuple[bool, str]:
    # result = {'within':..., 'over':..., 'cumulative':...}
    within, over, cum = result["within"], result["over"], result["cumulative"]  # type: ignore[index]
    if within["error"] is not None or "10" not in str(within["stdout"]):
        return False, f"escritura dentro del cap falló: {within}"
    if over["error"] is None or "write limit" not in str(over["error"]["message"]):
        return False, f"escritura sobre el cap no fue denegada: {over}"
    if (ws.rw / "over_cap.txt").exists():
        return False, "estado parcial: over_cap.txt quedó creado en el host"
    if (ws.rw / "within_cap.txt").read_text() != "A" * 10:
        return False, "within_cap.txt fue alterado por el intento over-cap"
    cum_msg = ""
    if cum["error"] is not None and "write limit" in str(cum["error"]["message"]):
        first = ws.rw / "cum_first.txt"
        second = ws.rw / "cum_second.txt"
        cum_msg = (
            f" acumulado: denegado; first={first.read_text() if first.exists() else 'AUSENTE'}"
            f" second_exists={second.exists()}"
        )
    return True, f"WITHIN_CAP=PASS OVER_CAP=DENIED sin estado parcial.{cum_msg}"


def check_c9(result: dict, ws: Workspace, before: Snapshot, after: Snapshot) -> tuple[bool, str]:
    out = str(result["stdout"])
    if result["error"] is not None:
        return False, f"error: {result['error']}"
    expected_lines = [
        "after_overwrite+append=AABB",
        "after_overwrite=AA",
        "after_append=AACC",
        "open_w=via-open-w",
        "open_a=l1l2",
    ]
    for line in expected_lines:
        if line not in out:
            return False, f"comportamiento inesperado: {out!r} (esperado {line})"
    return True, f"overwrite('w') trunca, append('a') preserva. Observado: {out.strip()!r}"


def check_c10(result: dict, ws: Workspace, before: Snapshot, after: Snapshot) -> tuple[bool, str]:
    # result = {'nonexistent':..., 'unmounted':..., 'parent_missing':...}
    ne, un, pm_ = result["nonexistent"], result["unmounted"], result["parent_missing"]  # type: ignore[index]
    if ne["error"] is None or "FileNotFoundError" not in ne["error"]["message"]:
        return False, f"path inexistente no produjo error claro: {ne}"
    if un["error"] is None or "PermissionError" not in un["error"]["message"]:
        return False, f"path no montado no fue denegado: {un}"
    if pm_["error"] is None or "FileNotFoundError" not in pm_["error"]["message"]:
        return False, f"creación con padre ausente no falló: {pm_}"
    return True, (
        "UNDECLARED_PATH=DENIED_OR_ERROR; clasificación: FAIL-CLOSED (excepción explícita, "
        "nunca acceso silencioso: FileNotFoundError para inexistentes bajo mount, "
        "PermissionError para rutas sin mount)"
    )


def check_script(result: dict, ws: Workspace, before: Snapshot, after: Snapshot) -> tuple[bool, str]:
    ops: dict[str, str] = {}
    for line in str(result["stdout"]).splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "OP":
            ops[parts[1]] = parts[2]
    required = {
        "read_allowed": "OK",
        "write_allowed": "OK",
        "write_readonly": "DENIED:PermissionError",
        "read_outside": "DENIED:PermissionError",
    }
    for op, want in required.items():
        got = ops.get(op)
        if got != want:
            return False, f"op {op}: esperado {want}, obtenido {got} (stdout={result['stdout']!r})"
    ro = (ws.ro / "protected.txt").read_bytes()
    rw = (ws.rw / "mutable.txt").read_bytes()
    physical = f"protected_intact={b'CONTENIDO-PROTEGIDO-1C' in ro and b'GUARDADO-EN-MOUNT-RW' not in ro}"
    physical += f" mutable_written={b'GUARDADO-EN-MOUNT-RW' in rw}"
    return True, (
        "read_allowed=OK write_allowed=OK write_readonly=DENIED read_outside=DENIED; "
        + physical
    )


def check_c0_bridge_compat() -> dict:
    """C0 (informativo): ¿el bridge oficial funciona con pydantic-monty 0.0.23?"""
    try:
        import asyncio
        import tempfile as _tf

        from agent_framework_monty import MontyExecuteCodeTool
        from agent_framework_monty._types import FileMount

        tmp = _tf.mkdtemp(prefix="monty_c0_probe_", dir="/private/tmp")
        Path(tmp, "a.txt").write_text("hello")
        tool = MontyExecuteCodeTool(
            file_mounts=[FileMount(host_path=tmp, mount_path="/input", mode="read-only")]
        )
        code = "from pathlib import Path\nprint(Path('/input/a.txt').read_text())"
        result = asyncio.run(tool._run_code(code=code))
        texts = []
        for c in result:
            texts.append(getattr(c, "text", None) or getattr(c, "error_details", None) or "")
        combined = " | ".join(t for t in texts if t)
        ok = "hello" in combined
        return {"compatible": ok, "observed": combined}
    except Exception as exc:
        return {
            "compatible": False,
            "observed": f"{type(exc).__name__}: {exc}",
            "traceback": traceback.format_exc(limit=3),
        }


# ---------- construcción de casos ----------


def build_cases(ws: Workspace) -> list[Case]:
    cases: list[Case] = []

    cases.append(
        Case(
            id="C1_READONLY_READ",
            description="Lectura permitida en mount read-only",
            expected="READ_ALLOWED=YES, contenido y digest registrados",
            code=(
                READONLY_CODE
                + f"print(Path('{PROTECTED_VIRTUAL}').read_text())"
            ),
            mounts=[ws.mount_ro()],
            check=check_c1,
        )
    )

    cases.append(
        Case(
            id="C2_READONLY_WRITE",
            description="Escritura bloqueada en mount read-only",
            expected="WRITE_ALLOWED=NO ORIGINAL_CONTENT_UNCHANGED=YES",
            code=(
                READONLY_CODE
                + f"p = Path('{PROTECTED_VIRTUAL}')\n"
                + f"print(p.read_text())\n"
                + f"p.write_text('{SECRET_LINE}\\n')\n"
                + "print('WRITE-SUCCEEDED')"
            ),
            mounts=[ws.mount_ro()],
            check=check_c2,
        )
    )

    cases.append(
        Case(
            id="C3_READONLY_CREATE",
            description="Creación de archivo nuevo en mount read-only",
            expected="CREATE_IN_READONLY=DENIED",
            code=READONLY_CODE + f"Path('{PROTECTED_VIRTUAL.replace('protected.txt', 'new.txt')}').write_text('x')",
            mounts=[ws.mount_ro()],
            check=check_c3,
        )
    )

    cases.append(
        Case(
            id="C4_RW_READWRITE",
            description="Lectura, escritura y relectura en mount read-write",
            expected="RW_READ=PASS RW_WRITE=PASS RW_READBACK=PASS",
            code=(
                READONLY_CODE
                + f"p = Path('{MUTABLE_VIRTUAL}')\n"
                + "print(p.read_text())\n"
                + "p.write_text('ESCRITO-POR-SUITE-1C\\n')\n"
                + "print(p.read_text())"
            ),
            mounts=[ws.mount_ro(), ws.mount_rw()],
            check=check_c4,
        )
    )

    outside_code = (
        READONLY_CODE
        + f"print(Path('{OUTSIDE_VIRTUAL}').read_text())\n"
        + f"print(Path('{ws.outside / 'forbidden.txt'}').read_text()[:20])"
    )
    cases.append(
        Case(
            id="C5_OUT_OF_SCOPE_READ",
            description="Lectura de fixture existente pero NO montada (v RPC virtual y host absoluta)",
            expected="OUT_OF_SCOPE_READ=DENIED",
            code=outside_code,
            mounts=[ws.mount_ro(), ws.mount_rw()],
            check=check_c5,
        )
    )

    traversal_code = (
        READONLY_CODE
        + "print(Path('/data/../outside/forbidden.txt').read_text()[:10])\n"
        + "print(Path('/data/../../outside/forbidden.txt').read_text()[:10])"
    )
    cases.append(
        Case(
            id="C6_PATH_TRAVERSAL",
            description="Escape por path traversal ../.. (variantes seguras)",
            expected="PATH_TRAVERSAL_ESCAPE=DENIED",
            code=traversal_code,
            check=lambda result, ws_, b, a: check_c6(
                {"t1": feed(READONLY_CODE + "print(Path('/data/../outside/forbidden.txt').read_text()[:10])", [ws_.mount_ro(), ws_.mount_rw()]),
                 "t2": feed(READONLY_CODE + "print(Path('/data/../../outside/forbidden.txt').read_text()[:10])", [ws_.mount_ro(), ws_.mount_rw()])},
                ws_, b, a,
            ),
            mounts=[],
        )
    )

    symlink_codes = {
        "rw_read": READONLY_CODE + "print(Path('/work/leak.lnk').read_text()[:10])",
        "rw_write": READONLY_CODE + "Path('/work/leak.lnk').write_text('PWN')",
        "ro_read": READONLY_CODE + "print(Path('/data/leak.lnk').read_text()[:10])",
        "ro_write": READONLY_CODE + "Path('/data/leak.lnk').write_text('PWN')",
    }
    cases.append(
        Case(
            id="C7_SYMLINK_BOUNDARY",
            description="Symlink dentro del mount apuntando a fixture fuera de scope",
            expected="SYMLINK_ESCAPE_READ/WRITE=DENIED en mounts RW y RO",
            code="; ".join(symlink_codes.values()),
            mounts=[],
            check=lambda result, ws_, b, a: check_c7(
                {tag: feed(code, [ws_.mount_ro(), ws_.mount_rw()]) for tag, code in symlink_codes.items()},
                ws_, b, a,
            ),
        )
    )

    within_code = (
        READONLY_CODE
        + "p = Path('/work/within_cap.txt')\n"
        + "p.write_text('" + "A" * 10 + "')\n"
        + "print('written', len(p.read_text()))"
    )
    over_code = READONLY_CODE + "Path('/work/over_cap.txt').write_text('" + "B" * 100 + "')"
    cumulative_code = (
        READONLY_CODE
        + "Path('/work/cum_first.txt').write_text('12345678')\n"
        + "Path('/work/cum_second.txt').write_text('" + "C" * 20 + "')\n"
        + "print('both-written')"
    )
    cases.append(
        Case(
            id="C8_WRITE_BYTE_CAP",
            description="write_bytes_limit=16: dentro del cap, sobre el cap y acumulado",
            expected="WITHIN_CAP=PASS OVER_CAP=DENIED sin estado parcial",
            code="; ".join([within_code, over_code, cumulative_code]),
            mounts=[],
            check=lambda result, ws_, b, a: check_c8(
                {
                    "within": feed(within_code, [ws_.mount_rw(write_bytes_limit=16)]),
                    "over": feed(over_code, [ws_.mount_rw(write_bytes_limit=16)]),
                    "cumulative": feed(cumulative_code, [ws_.mount_rw(write_bytes_limit=16)]),
                },
                ws_, b, a,
            ),
        )
    )

    c9_code = (
        READONLY_CODE
        + "p = Path('/work/oa.txt')\n"
        + "p.write_text('AA')\n"
        + "p.append_text('BB')\n"
        + "print('after_overwrite+append=' + p.read_text())\n"
        + "p.write_text('AA')\n"
        + "print('after_overwrite=' + p.read_text())\n"
        + "p.append_text('CC')\n"
        + "print('after_append=' + p.read_text())\n"
        + "w = open('/work/open_w.txt', 'w')\n"
        + "w.write('via-open-w')\n"
        + "w.close()\n"
        + "print('open_w=' + open('/work/open_w.txt').read())\n"
        + "a1 = open('/work/open_a.txt', 'a')\n"
        + "a1.write('l1')\n"
        + "a1.close()\n"
        + "a2 = open('/work/open_a.txt', 'a')\n"
        + "a2.write('l2')\n"
        + "a2.close()\n"
        + "print('open_a=' + open('/work/open_a.txt').read())"
    )
    cases.append(
        Case(
            id="C9_OVERWRITE_APPEND",
            description="Overwrite (write_text / open 'w') vs append (append_text / open 'a')",
            expected="overwrite trunca; append preserva; sin asumir atomicidad",
            code=c9_code,
            mounts=[ws.mount_ro(), ws.mount_rw()],
            check=check_c9,
        )
    )

    c10_nonexistent = READONLY_CODE + "print(Path('/work/never_exists.txt').read_text())"
    c10_unmounted = READONLY_CODE + "print(Path('/no_mount/file.txt').read_text())"
    c10_parent_missing = READONLY_CODE + "Path('/work/missing_dir/child.txt').write_text('x')"
    cases.append(
        Case(
            id="C10_UNDECLARED_PATH",
            description="Path inexistente bajo mount, path sin mount y creación con padre ausente",
            expected="UNDECLARED_PATH=DENIED_OR_ERROR, clasificar fail-closed",
            code="; ".join([c10_nonexistent, c10_unmounted, c10_parent_missing]),
            mounts=[],
            check=lambda result, ws_, b, a: check_c10(
                {
                    "nonexistent": feed(c10_nonexistent, [ws_.mount_ro(), ws_.mount_rw()]),
                    "unmounted": feed(c10_unmounted, [ws_.mount_ro(), ws_.mount_rw()]),
                    "parent_missing": feed(c10_parent_missing, [ws_.mount_ro(), ws_.mount_rw()]),
                },
                ws_, b, a,
            ),
        )
    )

    script_code = """from pathlib import Path
ops = {}

def record(name, fn):
    try:
        fn()
        ops[name] = 'OK'
    except Exception as exc:
        ops[name] = 'DENIED:' + type(exc).__name__

def op_read_allowed():
    print('READ:', Path('/data/protected.txt').read_text().splitlines()[0])
def op_write_allowed():
    Path('/work/mutable.txt').write_text('GUARDADO-EN-MOUNT-RW\\n')
def op_write_readonly():
    Path('/data/protected.txt').write_text('DEBE-FALLAR\\n')
def op_read_outside():
    print(Path('/outside/forbidden.txt').read_text()[:10])

record('read_allowed', op_read_allowed)
record('write_allowed', op_write_allowed)
record('write_readonly', op_write_readonly)
record('read_outside', op_read_outside)
for name in ('read_allowed', 'write_allowed', 'write_readonly', 'read_outside'):
    print('OP', name, ops[name])
"""
    cases.append(
        Case(
            id="S8_CONTROLLED_SCRIPT",
            description="Test de código controlado: 4 operaciones, cada resultado por separado",
            expected="read_allowed=OK write_allowed=OK write_readonly=DENIED read_outside=DENIED",
            code=script_code,
            mounts=[ws.mount_ro(), ws.mount_rw()],
            check=check_script,
        )
    )

    return cases


# ---------- ejecución ----------


def run_case(case: Case, ws: Workspace) -> dict:
    before = snapshot(ws.root)
    result = feed(case.code, case.mounts)
    after = snapshot(ws.root)

    # Para casos compuestos el check reconstruye sub-ejecuciones con mounts propios.
    passed, detail = verdict_of(case, result, ws, before, after)

    return {
        "id": case.id,
        "description": case.description,
        "expected": case.expected,
        "mounts": [
            {
                "virtual_path": m.virtual_path,
                "host_path": m.host_path,
                "mode": m.mode,
                "write_bytes_limit": m.write_bytes_limit,
            }
            for m in case.mounts
        ],
        "code": case.code,
        "interpreter_result": result,
        "physical_before": before.as_dict(),
        "physical_after": after.as_dict(),
        "passed": passed,
        "detail": detail,
    }


def main() -> int:
    started = datetime.now(timezone.utc)
    ws = Workspace()
    evidence: dict = {
        "phase": "ANKLA-AGT-1C",
        "suite": "mechanical",
        "started_utc": started.isoformat(),
        "llm_tokens": 0,
        "environment": {
            "python": sys.version.split()[0],
            "pydantic_monty": pm.__version__,
            "agent_framework_monty": _dist_version("agent-framework-monty"),
            "agent_framework_core": _dist_version("agent-framework"),
            "platform": sys.platform,
            "workspace_root_tmp": str(ws.root),
        },
        "cases": [],
    }

    print("== Fase 1C: suite mecánica Monty (0 tokens) ==")
    print(f"workspace temporal: {ws.root}\n")

    c0 = check_c0_bridge_compat()
    evidence["c0_bridge_compat"] = c0
    print(
        f"C0_BRIDGE_COMPAT (informativo): compatible={c0['compatible']} "
        f"observed={c0['observed'][:100]}"
    )

    failures = 0
    try:
        for case in build_cases(ws):
            record = run_case(case, ws)
            evidence["cases"].append(record)
            status = "PASS" if record["passed"] else "FAIL"
            if not record["passed"]:
                failures += 1
            print(f"[{status}] {case.id}: {record['detail']}")
    finally:
        evidence["finished_utc"] = datetime.now(timezone.utc).isoformat()
        evidence["summary"] = {
            "total": len(evidence["cases"]),
            "passed": sum(1 for c in evidence["cases"] if c["passed"]),
            "failed": failures,
        }
        EVIDENCE.mkdir(exist_ok=True)
        stamp = started.strftime("%Y%m%dT%H%M%SZ")
        out_path = EVIDENCE / f"mechanical_{stamp}.json"
        out_path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2))
        (EVIDENCE / "mechanical_latest.json").write_text(json.dumps(evidence, ensure_ascii=False, indent=2))
        print(f"\nevidencia: {out_path}")
        ws.teardown()

    if failures:
        print(f"RESULTADO: {failures} caso(s) FAILED")
        return 1
    print("RESULTADO: todos los casos PASS")
    return 0


def _dist_version(name: str) -> str:
    from importlib.metadata import version

    try:
        return version(name)
    except Exception:
        return "unknown"


if __name__ == "__main__":
    sys.exit(main())
