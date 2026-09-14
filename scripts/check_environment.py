"""Gate local de entorno para microsoftAGTlab.

Comprueba, sin gastar tokens y sin imprimir nunca ZAI_API_KEY:
  - intérprete y venv
  - agent-framework importable y versión del core
  - skew de versiones entre core y proveedores (dato, no fallo)
  - entry points esperados (devui, mcp)
  - .env presente con las variables mínimas

Salida: líneas `comando/chequeo -> resultado [pass|fail|inconclusive]`.
Exit 0 = sano; exit 1 = algo requerido falla.
"""

from __future__ import annotations

import importlib.metadata
import os
import pathlib
import sys

from dotenv import dotenv_values

ROOT = pathlib.Path(__file__).resolve().parent.parent
EXIT_OK = 0
EXIT_FAIL = 1


def collect() -> tuple[list[str], bool]:
    lines: list[str] = []
    ok = True

    def line(label: str, result: str, verdict: str) -> None:
        lines.append(f"{label} -> {result} [{verdict}]")

    # Intérprete
    v = sys.version_info
    line("python", f"{v.major}.{v.minor}.{v.micro}", "pass")

    # agent-framework core
    try:
        import agent_framework  # noqa: PLC0415

        core = importlib.metadata.version("agent-framework-core")
        line("import agent_framework", f"OK, core {core}", "pass")
    except Exception as exc:  # pragma: no cover - entorno roto
        line("import agent_framework", f"{type(exc).__name__}", "fail")
        return lines, False

    # Skew de proveedores: dato informativo, no fallo
    providers = {}
    for dist in importlib.metadata.distributions():
        name = (dist.metadata.get("Name") or "")
        if name.startswith("agent-framework-") and name != "agent-framework-core":
            providers[name] = dist.version
    skew = sorted({pv for name, pv in providers.items()
                   if name in ("agent-framework-openai", "agent-framework-orchestrations",
                               "agent-framework-ag-ui", "agent-framework-declarative",
                               "agent-framework-foundry", "agent-framework-github-copilot")})
    if skew:
        line("agent-framework-* proveedores (estables)", ", ".join(skew), "pass")
    betas = sum(1 for pv in providers.values() if "b26" in pv or "a26" in pv)
    line("agent-framework-* paquetes beta/alpha", str(betas), "pass")

    # Entry points
    eps = {ep.name for ep in importlib.metadata.entry_points(group="console_scripts")}
    for ep_name in ("devui", "mcp"):
        line(f"entry point {ep_name}", "presente" if ep_name in eps else "ausente",
             "pass" if ep_name in eps else "fail")

    # .env y variables mínimas (la API key sólo por presencia)
    env_path = ROOT / ".env"
    line(".env existe", str(env_path.exists()).lower(), "pass" if env_path.exists() else "fail")
    if not env_path.exists():
        return lines, False

    env = dotenv_values(env_path)
    api_key = env.get("ZAI_API_KEY") or os.environ.get("ZAI_API_KEY") or ""
    has_key = bool(api_key.strip())
    line("ZAI_API_KEY", "presente" if has_key else "ausente", "pass" if has_key else "fail")
    base_url = env.get("ZAI_BASE_URL") or os.environ.get("ZAI_BASE_URL") or ""
    line("ZAI_BASE_URL", base_url or "(sin definir; el ejemplo usa default Z.ai)",
         "pass" if base_url else "inconclusive: usa default del código")
    model = env.get("ZAI_MODEL") or os.environ.get("ZAI_MODEL") or ""
    line("ZAI_MODEL", model or "(sin definir)", "pass" if model else "inconclusive: usa default del código")

    ok = has_key and "devui" in eps and "mcp" in eps
    return lines, ok


def _secret_candidates(env_path: pathlib.Path) -> set[str]:
    """Valores que jamás pueden salir por pantalla (entorno + .env)."""
    candidates: set[str] = set()

    def harvest(mapping) -> None:
        for name, value in (mapping or {}).items():
            if value and any(tag in name.upper() for tag in ("KEY", "SECRET", "TOKEN", "PASS")):
                candidates.add(str(value).strip())

    harvest(os.environ)
    try:
        harvest(dotenv_values(env_path))
    except OSError:
        pass
    return {c for c in candidates if len(c) >= 6}


def main() -> int:
    lines, ok = collect()
    # Barrera anti-fuga: ningún candidato a secreto puede aparecer en la salida.
    secrets = _secret_candidates(ROOT / ".env")
    lines = [ln for ln in lines if not any(s in ln for s in secrets)]
    print("check_environment — microsoftAGTlab")
    for ln in lines:
        print(" ", ln)
    print("RESULTADO:", "OK" if ok else "BLOQ")
    return EXIT_OK if ok else EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main())
