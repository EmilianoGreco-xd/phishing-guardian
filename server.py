import os

from flask import Flask, jsonify, request, redirect, session

from gmail_reader import leer_correos, leer_correos_con_service
from feedback import marcar, ajustar_resultado
from auth_web import crear_flow, guardar_token, service_de_email

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

app = Flask(__name__)
app.secret_key = "phishing-guardian-escolar"


def analizar_correo(correo):
    try:
        from analyzer import analizar
        return analizar(
            correo.get("de", ""),
            correo.get("asunto", ""),
            correo.get("cuerpo", ""),
            correo.get("enlaces", []),
        )
    except Exception:
        texto = f"{correo.get('de','')} {correo.get('asunto','')} {correo.get('cuerpo','')}".lower()
        puntos = 0
        motivos = []

        urgencia = ["urgente", "bloqueada", "inmediato", "actua ahora", "24 horas"]
        datos = ["contraseña", "password", "clave", "pin", "tarjeta"]

        if any(p in texto for p in urgencia):
            puntos += 15
            motivos.append("urgencia")
        if any(p in texto for p in datos):
            puntos += 25
            motivos.append("pide datos")
        if correo.get("enlaces"):
            puntos += 5
            motivos.append("contiene enlaces")

        if puntos >= 50:
            riesgo = "Alto"
        elif puntos >= 20:
            riesgo = "Medio"
        else:
            riesgo = "Bajo"

        return {"riesgo": riesgo, "puntos": puntos, "motivos": motivos}


@app.after_request
def cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp


@app.get("/analizar")
def analizar_endpoint():
    usuario = request.args.get("usuario", "denzel")
    datos = leer_correos(usuario, cantidad=5)
    analizados = []

    for correo in datos["correos"]:
        resultado = analizar_correo(correo)
        resultado = ajustar_resultado(usuario, correo.get("de", ""), resultado)
        analizados.append({**correo, **resultado})

    return jsonify({
        "cuenta": datos["cuenta"],
        "usuario": usuario,
        "correos": analizados,
    })


@app.post("/feedback")
def feedback_endpoint():
    data = request.get_json(force=True) or {}
    resultado = marcar(
        data.get("usuario", "denzel"),
        data.get("de", ""),
        data.get("accion", ""),
    )
    return jsonify(resultado)


@app.get("/login")
def login():
    flow = crear_flow()
    url, state = flow.authorization_url(
        access_type="offline",
        prompt="consent",
    )
    session["state"] = state
    session["code_verifier"] = flow.code_verifier
    return redirect(url)


@app.get("/callback")
def callback():
    flow = crear_flow()
    flow.code_verifier = session.get("code_verifier")
    flow.fetch_token(authorization_response=request.url)
    email = guardar_token(flow.credentials)
    session["email"] = email
    return f"Listo. Sesion iniciada: {email}. Ya podes cerrar esta pestana."


@app.get("/sesiones")
def sesiones():
    carpeta = "tokens_web"
    if not os.path.isdir(carpeta):
        return jsonify({"cuentas": []})
    cuentas = [
        nombre.replace(".json", "")
        for nombre in os.listdir(carpeta)
        if nombre.endswith(".json")
    ]
    return jsonify({"cuentas": cuentas})


@app.get("/analizar_web")
def analizar_web():
    email = request.args.get("email") or session.get("email")
    if not email:
        return jsonify({"error": "No hay sesion. Entra a /login"}), 401

    service = service_de_email(email)
    if service is None:
        return jsonify({"error": "No hay token. Entra a /login"}), 401

    datos = leer_correos_con_service(service, cantidad=5)
    analizados = []
    for correo in datos["correos"]:
        resultado = analizar_correo(correo)
        resultado = ajustar_resultado(email, correo.get("de", ""), resultado)
        analizados.append({**correo, **resultado})

    return jsonify({
        "cuenta": datos["cuenta"],
        "usuario": email,
        "correos": analizados,
    })


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
