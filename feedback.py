import json
import os
import re

LISTAS_DIR = "listas"


def _archivo(usuario, tipo):
    os.makedirs(LISTAS_DIR, exist_ok=True)
    seguro = "".join(ch if ch.isalnum() or ch in "._-@" else "_" for ch in usuario)
    return os.path.join(LISTAS_DIR, f"{seguro}_{tipo}.json")


def _leer(usuario, tipo):
    path = _archivo(usuario, tipo)
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _guardar(usuario, tipo, datos):
    with open(_archivo(usuario, tipo), "w", encoding="utf-8") as f:
        json.dump(datos, f, ensure_ascii=False, indent=2)


def extraer_email(remitente):
    match = re.search(r"<([^>]+)>", remitente or "")
    if match:
        return match.group(1).lower()
    return (remitente or "").strip().lower()


def marcar(usuario, remitente, accion):
    email = extraer_email(remitente)
    if not email:
        return {"ok": False, "mensaje": "No hay remitente"}

    confiables = _leer(usuario, "confiar")
    sospechosos = _leer(usuario, "sospechoso")

    if accion == "confiar":
        if email not in confiables:
            confiables.append(email)
        sospechosos = [x for x in sospechosos if x != email]
        _guardar(usuario, "confiar", confiables)
        _guardar(usuario, "sospechoso", sospechosos)
        return {"ok": True, "mensaje": f"Confiable: {email}"}

    if accion == "sospechoso":
        if email not in sospechosos:
            sospechosos.append(email)
        confiables = [x for x in confiables if x != email]
        _guardar(usuario, "confiar", confiables)
        _guardar(usuario, "sospechoso", sospechosos)
        return {"ok": True, "mensaje": f"Sospechoso: {email}"}

    return {"ok": False, "mensaje": "Accion desconocida"}


def ajustar_resultado(usuario, remitente, resultado):
    email = extraer_email(remitente)
    puntos = int(resultado.get("puntos", 0))
    motivos = list(resultado.get("motivos", []))

    if email in _leer(usuario, "confiar"):
        puntos -= 30
        motivos.append("remitente confiable")
    elif email in _leer(usuario, "sospechoso"):
        puntos += 20
        motivos.append("remitente marcado por el usuario")

    if puntos < 0:
        puntos = 0

    if puntos >= 50:
        riesgo = "Alto"
    elif puntos >= 20:
        riesgo = "Medio"
    else:
        riesgo = "Bajo"

    resultado["puntos"] = puntos
    resultado["motivos"] = motivos
    resultado["riesgo"] = riesgo
    return resultado