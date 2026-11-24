"""Falla si la puntuación de mutación de algún informe de Stryker está por debajo del umbral.

Uso: python check-mutacion.py <umbral> <informe.json> [<informe.json> ...]

La puntuación es la de Stryker: (Killed + Timeout) / (Killed + Timeout + Survived + NoCoverage).
Los mutantes que no compilan o que se ignoran no cuentan.
"""
import json
import sys


def score(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    detected = undetected = 0
    for file in data["files"].values():
        for mutant in file["mutants"]:
            status = mutant["status"]
            if status in ("Killed", "Timeout"):
                detected += 1
            elif status in ("Survived", "NoCoverage"):
                undetected += 1
    total = detected + undetected
    if total == 0:
        raise SystemExit(f"{path}: sin mutantes que contar; no se puede comprobar el umbral.")
    return 100.0 * detected / total


def main(args):
    if len(args) < 2:
        raise SystemExit("Uso: check-mutacion.py <umbral> <informe.json> [...]")
    threshold = float(args[0])
    failed = False
    for path in args[1:]:
        value = score(path)
        ok = value >= threshold
        failed |= not ok
        print(f"{path}: {value:.2f} % ({'pasa' if ok else 'por debajo de'} el {threshold:g} %)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
