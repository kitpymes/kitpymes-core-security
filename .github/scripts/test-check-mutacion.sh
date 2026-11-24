#!/usr/bin/env bash
# Prueba check-mutacion.py contra informes falsos: tiene que fallar por debajo del umbral
# y sin mutantes, y pasar en el umbral y por encima.
set -u
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
script="$(dirname "$0")/check-mutacion.py"

informe() { # killed survived nocoverage timeout
  python3 - "$dir/$5.json" "$1" "$2" "$3" "$4" <<'PY'
import json, sys
path, k, s, nc, t = sys.argv[1], *map(int, sys.argv[2:])
mutants = [{"status": st} for st, n in (("Killed", k), ("Survived", s), ("NoCoverage", nc), ("Timeout", t), ("CompileError", 5), ("Ignored", 5)) for _ in range(n)]
json.dump({"files": {"a.cs": {"mutants": mutants}}}, open(path, "w"))
PY
}

informe 79 21 0 0 bajo        # 79 %
informe 70 10 10 10 justo     # 80 % con Timeout como detectado
informe 95 5 0 0 alto         # 95 %
informe 0 0 0 0 vacio         # sin mutantes que contar

fallos=0
espera() { # codigo esperado (0 pasa, 1 falla), informes...
  local esperado=$1; shift
  python3 "$script" 80 "$@" > /dev/null 2>&1; local real=$?
  [ "$real" -ne 0 ] && real=1
  if [ "$real" -ne "$esperado" ]; then echo "MAL: $* dio $real y se esperaba $esperado"; fallos=1; else echo "bien: $* -> $real"; fi
}

espera 1 "$dir/bajo.json"
espera 0 "$dir/justo.json"
espera 0 "$dir/alto.json"
espera 1 "$dir/vacio.json"
espera 1 "$dir/alto.json" "$dir/bajo.json"
espera 1 "$dir/no-existe.json"

exit $fallos
