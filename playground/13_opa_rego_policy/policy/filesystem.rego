# Policy declarativa Fase 1D-R2 — frontera de filesystem para controlled_write.
#
# Reimplementa declarativamente la intención de policy de T1/T3 (Fase 1D-R1),
# que hasta ahora vivía en un dispatcher Python del harness.
#
# Sintaxis: Rego v1 (OPA 1.x). El bloque rego del manifest de la Fase 1D usaba
# sintaxis v0 (`verdict = {...} { ... }`), que OPA 1.20 ni siquiera compila —
# evidencia adicional de que aquel bloque nunca se evaluó.
#
# CANONICALIZACIÓN: la hace ESTA policy, no el host. `canon` pliega los
# segmentos "." y ".." con desenrollado acotado (MAX_FOLDS). Si tras el límite
# queda cualquier ".." sin plegar, o el path intenta escapar por encima de la
# raíz, la decisión es DENY. No se delega la responsabilidad a otra capa.
#
# Default DENY. Nunca `default allow := true`.

package acs

import rego.v1

# ----------------------------------------------------------------- constantes

allowed_prefixes := ["/workspace/allowed", "/protected"]

denied_prefixes := ["/workspace/quarantine"]

known_tools := {"controlled_write"}

# Profundidad máxima de plegado de "..". Un path que necesite más queda DENY.
max_folds := 8

# ------------------------------------------------------- canonicalización

# Segmentos no vacíos y distintos de "." (elimina "//" y "/./").
raw_segments(p) := [s |
	some s in split(p, "/")
	s != ""
	s != "."
]

# Un paso de plegado: elimina el primer par <segmento>/".." que encuentre.
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

# Desenrollado acotado: OPA no permite recursión en reglas, así que el plegado
# se aplica un número fijo y auditable de veces.
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

# El path canónico sólo existe si el plegado terminó: ningún ".." residual.
# Un ".." residual significa o bien escape por encima de la raíz, o bien que se
# excedió max_folds. En ambos casos `canon` queda indefinido y la regla por
# defecto (deny) gobierna.
canon(p) := c if {
	parts := folded(p)
	not ".." in parts
	c := concat("", ["/", concat("/", parts)])
}

under(path, prefix) if path == prefix

under(path, prefix) if startswith(path, concat("", [prefix, "/"]))

# ----------------------------------------------------------------- entrada
#
# Shape real que ACS 0.3.1b1 entrega a Rego (verificado empíricamente, no
# copiado de otra versión):
#
#   {
#     "intervention_point": "pre_tool_call",
#     "policy_target": {"kind": null, "path": "$.tool_call", "value": {...}},
#     "snapshot": {"tool_call": {...}},
#     "annotations": {},
#     "tool": {"name": "...", "args": {...}}
#   }
#
# Se lee de `policy_target.value` — el objetivo declarado en el manifest
# (`policy_target: $.tool_call`) — con `object.get` en toda la cadena, para que
# una forma inesperada no produzca error de evaluación sino ausencia de match,
# que la regla por defecto convierte en DENY.

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

requested_path := p if {
	args := object.get(target, ["args"], null)
	is_object(args)
	p := object.get(args, ["path"], null)
	is_string(p)
}

# ----------------------------------------------------------------- veredicto

# DEFAULT DENY. Cualquier input que no satisfaga todas las condiciones de
# `allow_path` cae aquí: tool ausente o desconocida, args no-objeto, path
# ausente / lista / nulo / objeto, snapshot malformado, traversal irresoluble.
default verdict := {
	"decision": "deny",
	"message": "policy 1D-R2 (rego): denegado por defecto — la solicitud no satisface ninguna regla de permiso",
}

verdict := {
	"decision": "deny",
	"message": sprintf(
		"policy 1D-R2 (rego): ruta denegada tras canonicalizar (%v -> %v)",
		[requested_path, canon(requested_path)],
	),
} if {
	tool_name in known_tools
	c := canon(requested_path)
	some d in denied_prefixes
	under(c, d)
}

verdict := {
	"decision": "allow",
	"message": sprintf(
		"policy 1D-R2 (rego): '%v' permitida sobre %v (canónico de %v)",
		[tool_name, canon(requested_path), requested_path],
	),
} if {
	tool_name in known_tools
	c := canon(requested_path)

	# ninguna regla de denegación aplica
	not denied(c)

	# y cae dentro de un prefijo permitido explícito
	some a in allowed_prefixes
	under(c, a)
}

denied(c) if {
	some d in denied_prefixes
	under(c, d)
}
