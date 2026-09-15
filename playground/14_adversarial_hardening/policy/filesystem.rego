# Policy declarativa Fase 1E — superficie ampliada para el harness adversarial.
#
# Deriva de playground/13_opa_rego_policy/policy/filesystem.rego (1D-R2) y
# mantiene sus propiedades: Rego v1, default DENY, canonicalización dentro de
# la propia policy.
#
# Diferencia: cubre varias tools y, para cada una, TODOS sus argumentos de tipo
# ruta. Escrita como la escribiría un implementador competente — no se debilita
# a propósito para que un ataque tenga éxito. Si un ataque pasa, es un hallazgo
# real, no un montaje.

package acs

import rego.v1

allowed_prefixes := ["/workspace/allowed", "/protected"]

denied_prefixes := ["/workspace/quarantine"]

# Tools declaradas y cuáles de sus argumentos son rutas que deben validarse.
# Una tool ausente de este mapa es desconocida para la policy → deny.
tool_path_args := {
	"controlled_write": ["path"],
	"copy_allowed_file": ["src", "dst"],
	"outer_tool": ["path"],
	"safe_tool": ["path"],
	"safe_tool_wrapper": ["path"],
	# `safe_tool_alias` se declara en el manifest pero NO aquí: comprueba que
	# una identidad de tool no contemplada por la policy falla cerrada.
	# `unmapped_tool` idem.
	"deploy_test_service": [],
}

# ------------------------------------------------------- canonicalización

raw_segments(p) := [s |
	some s in split(p, "/")
	s != ""
	s != "."
]

fold_step(parts) := out if {
	idxs := [i |
		some i, _ in parts
		parts[i] != ".."
		i + 1 < count(parts)
		parts[i + 1] == ".."
	]
	count(idxs) > 0
	i := idxs[0]
	out := array.concat(
		array.slice(parts, 0, i),
		array.slice(parts, i + 2, count(parts)),
	)
} else := parts

folded(p) := f8 if {
	f0 := raw_segments(p)
	f1 := fold_step(f0)
	f2 := fold_step(f1)
	f3 := fold_step(f2)
	f4 := fold_step(f3)
	f5 := fold_step(f4)
	f6 := fold_step(f5)
	f7 := fold_step(f6)
	f8 := fold_step(f7)
}

# Indefinido si queda cualquier ".." → gobierna el default deny.
canon(p) := c if {
	parts := folded(p)
	not ".." in parts
	c := concat("", ["/", concat("/", parts)])
}

under(path, prefix) if path == prefix

under(path, prefix) if startswith(path, concat("", [prefix, "/"]))

# ----------------------------------------------------------------- entrada

target := v if {
	pt := object.get(input, ["policy_target"], null)
	is_object(pt)
	v := object.get(pt, ["value"], null)
	is_object(v)
}

tool_name := n if {
	n := object.get(target, ["name"], null)
	is_string(n)
}

args := a if {
	a := object.get(target, ["args"], null)
	is_object(a)
}

# Nombres de los argumentos de ruta que esta tool declara.
declared_path_args := tool_path_args[tool_name]

# Valores crudos de esos argumentos, sólo si TODOS están presentes y son str.
raw_paths := ps if {
	ps := [v |
		some k in declared_path_args
		v := args[k]
	]
	count(ps) == count(declared_path_args)
	every p in ps {
		is_string(p)
	}
}

# Canónicos, sólo si TODOS canonicalizan (ningún ".." residual).
canon_paths := cs if {
	cs := [c |
		some p in raw_paths
		c := canon(p)
	]
	count(cs) == count(raw_paths)
}

# ----------------------------------------------------------------- reglas

path_denied(c) if {
	some d in denied_prefixes
	under(c, d)
}

path_allowed(c) if {
	not path_denied(c)
	some a in allowed_prefixes
	under(c, a)
}

# ----------------------------------------------------------------- veredicto

default verdict := {
	"decision": "deny",
	"message": "policy 1E (rego): denegado por defecto — la solicitud no satisface ninguna regla de permiso",
}

# Deny explícito cuando ALGÚN argumento de ruta cae en zona prohibida.
verdict := {
	"decision": "deny",
	"message": sprintf(
		"policy 1E (rego): '%v' denegada — argumento en zona prohibida tras canonicalizar (%v -> %v)",
		[tool_name, raw_paths, canon_paths],
	),
} if {
	tool_path_args[tool_name]
	some c in canon_paths
	path_denied(c)
}

# Allow cuando la tool es conocida y TODOS sus argumentos de ruta son válidos.
verdict := {
	"decision": "allow",
	"message": sprintf(
		"policy 1E (rego): '%v' permitida sobre %v (canónico de %v)",
		[tool_name, canon_paths, raw_paths],
	),
} if {
	tool_path_args[tool_name]
	count(canon_paths) > 0
	every c in canon_paths {
		path_allowed(c)
	}
}

# Allow para tools conocidas SIN argumentos de ruta (p. ej. deploy_test_service):
# la policy no es la capa que las gobierna; el gate es el approval.
verdict := {
	"decision": "allow",
	"message": sprintf("policy 1E (rego): '%v' sin argumentos de ruta; gate = approval", [tool_name]),
} if {
	count(tool_path_args[tool_name]) == 0
}
