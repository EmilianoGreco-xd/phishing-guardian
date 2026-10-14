#!/usr/bin/env python3
"""
PHISHING GUARDIAN - Backend con interfaz web simple
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from typing import List
from pathlib import Path
import uvicorn

from analyzer import (
    PhishingAnalyzer,
    EmailData,
    LinkInfo,
    AnalysisResult,
)


# ============================================================
# Modelos
# ============================================================

class LinkIn(BaseModel):
    display_text: str = Field(..., example="Ingresar al banco")
    url: str = Field(..., example="https://bit.ly/ejemplo")


class EmailIn(BaseModel):
    from_name: str = Field("", example="Banco Nación")
    from_email: str = Field(..., example="seguridad@b4nco-nacion.com")
    subject: str = Field("", example="URGENTE: tu cuenta será bloqueada")
    body: str = Field("", example="Estimado usuario, haga clic aquí...")
    links: List[LinkIn] = Field(default_factory=list)
    attachments: List[str] = Field(default_factory=list, example=["factura.zip"])


class RuleOut(BaseModel):
    code: str
    description: str
    points: int
    triggered: bool = True
    detail: str = ""


class AnalysisOut(BaseModel):
    total_points: int
    risk_level: str
    recommendation: str
    triggered_rules: List[RuleOut]
    all_rules: List[RuleOut] = []


class WhitelistUpdate(BaseModel):
    email_or_domain: str = Field(..., example="profesor@fecea.edu.ar")


# ============================================================
# App
# ============================================================

app = FastAPI(
    title="Phishing Guardian API",
    description="Motor de análisis heurístico de correos sospechosos de phishing",
    version="1.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

templates = Jinja2Templates(directory="templates")
WHITELIST_PATH = Path("whitelist.txt")


def cargar_whitelist() -> set:
    if not WHITELIST_PATH.exists():
        return set()
    with open(WHITELIST_PATH, "r", encoding="utf-8") as f:
        return {
            linea.strip().lower()
            for linea in f
            if linea.strip() and not linea.startswith("#")
        }


def guardar_whitelist(whitelist: set) -> None:
    with open(WHITELIST_PATH, "w", encoding="utf-8") as f:
        f.write("# Lista de remitentes y dominios confiables\n\n")
        for item in sorted(whitelist):
            f.write(item + "\n")


analyzer = PhishingAnalyzer(whitelist=cargar_whitelist())


def refrescar_analyzer():
    global analyzer
    analyzer = PhishingAnalyzer(whitelist=cargar_whitelist())


# ============================================================
# Interfaz web + endpoints
# ============================================================

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(request, "index.html")


@app.get("/health")
def health():
    return {"status": "ok", "whitelist_count": len(analyzer.whitelist)}


@app.post("/analyze", response_model=AnalysisOut)
def analyze_email(email: EmailIn):
    try:
        email_data = EmailData(
            from_name=email.from_name,
            from_email=email.from_email,
            subject=email.subject,
            body=email.body,
            links=[LinkInfo(l.display_text, l.url) for l in email.links],
            attachments=email.attachments,
        )

        resultado: AnalysisResult = analyzer.analyze(email_data)

        triggered = [
            RuleOut(
                code=r.code,
                description=r.description,
                points=r.points,
                triggered=True,
                detail=r.detail,
            )
            for r in resultado.triggered_rules
        ]

        return AnalysisOut(
            total_points=resultado.total_points,
            risk_level=resultado.risk_level,
            recommendation=resultado.recommendation,
            triggered_rules=triggered,
            all_rules=triggered,
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al analizar: {str(e)}")


@app.get("/whitelist")
def get_whitelist():
    return {
        "count": len(analyzer.whitelist),
        "items": sorted(list(analyzer.whitelist)),
    }


@app.post("/whitelist/add")
def add_to_whitelist(data: WhitelistUpdate):
    item = data.email_or_domain.strip().lower()
    if not item:
        raise HTTPException(status_code=400, detail="El valor no puede estar vacío")

    whitelist = cargar_whitelist()
    whitelist.add(item)
    guardar_whitelist(whitelist)
    refrescar_analyzer()

    return {"message": f"'{item}' agregado a la whitelist", "count": len(whitelist)}


@app.post("/whitelist/remove")
def remove_from_whitelist(data: WhitelistUpdate):
    item = data.email_or_domain.strip().lower()
    if not item:
        raise HTTPException(status_code=400, detail="El valor no puede estar vacío")

    whitelist = cargar_whitelist()
    if item not in whitelist:
        raise HTTPException(status_code=404, detail=f"'{item}' no está en la whitelist")

    whitelist.remove(item)
    guardar_whitelist(whitelist)
    refrescar_analyzer()

    return {"message": f"'{item}' eliminado de la whitelist", "count": len(whitelist)}


@app.post("/whitelist/reload")
def reload_whitelist():
    refrescar_analyzer()
    return {
        "message": "Whitelist recargada",
        "count": len(analyzer.whitelist),
        "items": sorted(list(analyzer.whitelist)),
    }


# ============================================================
# Ejecutar
# ============================================================

if __name__ == "__main__":
    print("=" * 50)
    print("  PHISHING GUARDIAN")
    print("  Interfaz:  http://127.0.0.1:8000")
    print("  Docs API:  http://127.0.0.1:8000/docs")
    print("=" * 50)
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)



# ============================================================
# Final
# ============================================================

from pydantic import BaseModel
import json
import os

class TrustedSender(BaseModel):
    gmail: str
    sender: str

@app.post("/trust")
def trust_sender(data: TrustedSender):

    archivo = f"usuarios/{data.gmail.replace('@','_')}_whitelist.json"

    os.makedirs("usuarios", exist_ok=True)

    if os.path.exists(archivo):
        with open(archivo, "r", encoding="utf-8") as f:
            lista = json.load(f)
    else:
        lista = []

    if data.sender not in lista:
        lista.append(data.sender)

    with open(archivo, "w", encoding="utf-8") as f:
        json.dump(lista, f, indent=4)

    return {"mensaje": "Remitente agregado"}

class SuspiciousSender(BaseModel):
    gmail: str
    sender: str

@app.post("/suspicious")
def suspicious_sender(data: SuspiciousSender):

    archivo = f"usuarios/{data.gmail.replace('@','_')}_blacklist.json"

    os.makedirs("usuarios", exist_ok=True)

    if os.path.exists(archivo):
        with open(archivo, "r", encoding="utf-8") as f:
            lista = json.load(f)
    else:
        lista = []

    if data.sender not in lista:
        lista.append(data.sender)

    with open(archivo, "w", encoding="utf-8") as f:
        json.dump(lista, f, indent=4)

    return {"mensaje": "Remitente marcado"}