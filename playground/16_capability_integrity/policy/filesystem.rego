# Policy declarativa Fase 1E-R2 — capability integrity & trust binding.
#
# Deriva de playground/15_capability_confinement/policy/filesystem.rego (1E-R1)
# y conserva sus propiedades: Rego v1, default DENY, canonicalización propia,
# validación de todos los argumentos de ruta declarados de cada tool.
#
# Diferencia decisiva (remediación A9): el veredicto ALLOW ya NO transporta
# paths. Los result_labels nombran una ZONA LÓGICA autorizada con la forma
# "zone:<capability>:<zone_id>". La policy NO puede fabricar host_path ni
# mount path: sólo puede seleccionar una identidad pre-registrada en el
# zone_registry del host (raíz de confianza). Una identidad no registrada es
# fail-closed en la capability_factory.

package acs

import rego.v1

allowed_prefixes := ["/workspace/allowed"]

denied_prefixes := ["/workspace/quarantine"]

# Zona lógica autorizada por tool: la IDENTIDAD que la policy está dispuesta
# a autorizar para la capability. La factory resuelve la identidad contra el
# zone_registry del host; jamás recibe un path de esta policy.
tool_authorized_zone := {
	"controlled_write": {"capability": "filesystem.write", "zone_id": "workspace.allowed"},
	"outer_tool": {"capability": "filesystem.write", "zone_id": "workspace.allowed"},
	"outer_tool_via_helper": {"capability": "filesystem.write", "zone_id": "workspace.allowed"},
	"probe_tool": {"capability": "filesystem.write", "zone_id": "workspace.allowed"},
	"mutation_probe_tool": {"capability": "filesystem.write", "zone_id": "workspace.allowed"},
	"replacement_probe_tool": {"capability": "filesystem.write", "zone_id": "workspace.allowed"},
}

# Tools declaradas y cuáles de sus argumentos son rutas que deben validarse.
# Una tool ausente de este mapa es desconocida para la policy → deny.
tool_path_args := {
	"controlled_write": ["path"],
	"outer_tool": ["path"],
	"outer_tool_via_helper": ["path"],
	"probe_tool": ["path"],
	"mutation_probe_tool": ["path"],
	"replacement_probe_tool": ["path"],
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

declared_path_args := tool_path_args[tool_name]

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

canon_paths := cs if {
	cs := [c |
		some p in raw_paths
		c := canon(p)
	]
	count(cs) == count(raw_paths)
}

authorized_zone := tool_authorized_zone[tool_name]

zone_label := concat("", ["zone:", authorized_zone.capability, ":", authorized_zone.zone_id])

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
	"message": "policy 1E-R2 (rego): denegado por defecto — la solicitud no satisface ninguna regla de permiso",
}

verdict := {
	"decision": "deny",
	"message": sprintf(
		"policy 1E-R2 (rego): '%v' denegada — argumento en zona prohibida tras canonicalizar (%v -> %v)",
		[tool_name, raw_paths, canon_paths],
	),
} if {
	tool_path_args[tool_name]
	some c in canon_paths
	path_denied(c)
}

# ALLOW: la tool es conocida, todos sus argumentos de ruta canonicalizan bajo
# la zona permitida, y el veredicto transporta SÓLO la identidad de zona
# autorizada. El path efectivo del mount lo fija el zone_registry del host,
# no esta policy ni el veredicto.
verdict := {
	"decision": "allow",
	"message": sprintf(
		"policy 1E-R2 (rego): '%v' permitida sobre %v (canónico de %v); zona lógica autorizada %v",
		[tool_name, canon_paths, raw_paths, zone_label],
	),
	"result_labels": [zone_label],
} if {
	tool_path_args[tool_name]
	count(canon_paths) > 0
	every c in canon_paths {
		path_allowed(c)
	}
}
