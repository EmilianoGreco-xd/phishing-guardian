#!/usr/bin/env python3
"""
PHISHING GUARDIAN - Analizador Heurístico de Correos
Fecha: 23/09/2026
Autores: Emiliano Greco, Lucio Sacco, Denzel Alderete Campos

Cada correo empieza con 0 puntos.
Si una regla se cumple, se suman (o restan) puntos.
Clasificación final:
  - 0 a 19  → Bajo
  - 20 a 49 → Medio
  - 50 o más → Alto
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Set
from urllib.parse import urlparse


# ============================================================
# CONFIGURACIÓN Y CONSTANTES
# ============================================================

FREE_EMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com",
    "live.com", "yahoo.com", "yahoo.com.ar", "icloud.com",
    "protonmail.com", "proton.me", "aol.com", "mail.com",
    "zoho.com", "yandex.com", "gmx.com", "gmx.net",
}

TRUSTED_DOMAINS = {
    "fecea.edu.ar", "google.com", "microsoft.com", "apple.com",
    "afip.gob.ar", "anses.gob.ar", "banco.nacion.com.ar",
    "santander.com.ar", "bbva.com.ar", "galicia.com.ar",
    "mercadolibre.com.ar", "mercadopago.com.ar",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "cutt.ly", "goo.gl",
    "ow.ly", "is.gd", "buff.ly", "adf.ly", "rebrand.ly",
    "shorturl.at", "tiny.cc",
}

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif",
    ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh",
    ".iso", ".img", ".dmg", ".msi", ".jar",
    ".ps1", ".psm1", ".reg",
}

SUSPICIOUS_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz",
    ".html", ".htm", ".shtml",
    ".docm", ".xlsm", ".pptm",
}

URGENCY_WORDS = [
    r"urgente", r"inmediato", r"última?\s+oportunidad",
    r"tu\s+cuenta\s+ser[aá]\s+bloqueada", r"act[uú]a\s+ahora",
    r"vencimiento", r"suspendida", r"24\s+horas", r"hoy\s+mismo",
    r"expira", r"caduca", r"últimos?\s+días?",
]

THREAT_WORDS = [
    r"bloqueo", r"demanda", r"polic[ií]a", r"multa",
    r"virus\s+detectado", r"cuenta\s+comprometida",
    r"actividad\s+sospechosa", r"acceso\s+no\s+autorizado",
    r"suspender[aá]", r"cerrar[aá]\s+tu\s+cuenta",
]

PRIZE_WORDS = [
    r"ganaste", r"premio", r"transferencia", r"reembolso",
    r"factura\s+adjunta", r"pago\s+pendiente", r"has\s+ganado",
    r"loter[ií]a", r"sorteo", r"dinero\s+gratis",
]

PERSONAL_DATA_WORDS = [
    r"clave", r"contrase[nñ]a", r"password", r"pin",
    r"tarjeta", r"c[oó]digo\s+de\s+verificaci[oó]n",
    r"usuario", r"dni", r"cuit", r"cvv", r"cvc",
    r"n[uú]mero\s+de\s+cuenta", r"datos\s+bancarios",
]

CLICK_TO_SAVE_PHRASES = [
    r"verifica\s+tu\s+cuenta", r"iniciar\s+sesi[oó]n\s+aqu[ií]",
    r"actualizar\s+datos", r"confirmar\s+identidad",
    r"restablecer\s+acceso", r"validar\s+cuenta",
    r"haz\s+clic\s+aqu[ií]", r"ingresa\s+aqu[ií]",
]


# ============================================================
# ESTRUCTURAS DE DATOS
# ============================================================

@dataclass
class LinkInfo:
    display_text: str
    url: str


@dataclass
class EmailData:
    from_name: str = ""
    from_email: str = ""
    subject: str = ""
    body: str = ""
    links: List[LinkInfo] = field(default_factory=list)
    attachments: List[str] = field(default_factory=list)


@dataclass
class RuleResult:
    code: str
    description: str
    points: int
    triggered: bool
    detail: str = ""


@dataclass
class AnalysisResult:
    total_points: int
    risk_level: str
    triggered_rules: List[RuleResult]
    recommendation: str


# ============================================================
# ANALIZADOR PRINCIPAL
# ============================================================

class PhishingAnalyzer:

    def __init__(self, whitelist: Optional[Set[str]] = None):
        self.whitelist = {w.lower().strip() for w in (whitelist or set())}

    def analyze(self, email: EmailData) -> AnalysisResult:
        results: List[RuleResult] = []

        results.append(self._rule_a1(email))
        results.append(self._rule_a2(email))
        results.append(self._rule_a3(email))
        results.append(self._rule_a4(email))

        results.append(self._rule_b1(email))
        results.append(self._rule_b2(email))
        results.append(self._rule_b3(email))
        results.append(self._rule_b4(email))

        results.append(self._rule_c1(email))
        results.append(self._rule_c2(email))
        results.append(self._rule_c3(email))
        results.append(self._rule_c4(email))

        results.append(self._rule_d1(email))
        results.append(self._rule_d2(email))
        results.append(self._rule_d3(email))
        results.append(self._rule_d4(email))

        results.append(self._rule_e1(email))
        results.append(self._rule_e2(email))

        total = sum(r.points for r in results if r.triggered)

        if total >= 50:
            risk = "Alto"
            recommendation = (
                "PELIGROSO: Se recomienda NO abrir enlaces ni descargar adjuntos. "
                "Marcar como phishing y eliminar."
            )
        elif total >= 20:
            risk = "Medio"
            recommendation = (
                "SOSPECHOSO: Revisar con cuidado. No hacer clic en enlaces "
                "ni abrir adjuntos hasta verificar la legitimidad."
            )
        else:
            risk = "Bajo"
            recommendation = (
                "Riesgo bajo según las reglas heurísticas. "
                "Aun así, usar siempre el criterio personal."
            )

        triggered = [r for r in results if r.triggered]

        return AnalysisResult(
            total_points=total,
            risk_level=risk,
            triggered_rules=triggered,
            recommendation=recommendation,
        )

    # ========== REGLAS A – REMITENTE ==========

    def _rule_a1(self, email: EmailData) -> RuleResult:
        domain = self._extract_domain(email.from_email)
        triggered = False
        detail = ""

        if domain in FREE_EMAIL_DOMAINS:
            name_lower = email.from_name.lower()
            institutional_keywords = [
                "banco", "universidad", "colegio", "escuela", "gobierno",
                "afip", "anses", "ministerio", "oficial", "soporte",
                "seguridad", "cuenta", "notificación",
            ]
            if any(kw in name_lower for kw in institutional_keywords):
                triggered = True
                detail = f"Dominio gratuito '{domain}' usado con nombre institucional"

        return RuleResult("A1", "Dominio gratis o raro", 15, triggered, detail)

    def _rule_a2(self, email: EmailData) -> RuleResult:
        triggered = False
        detail = ""

        if email.from_name and email.from_email:
            name_lower = email.from_name.lower()
            domain = self._extract_domain(email.from_email)

            known_institutions = {
                "banco nación": ["banco.nacion", "bna.com.ar", "nacion.com.ar"],
                "banco nacion": ["banco.nacion", "bna.com.ar", "nacion.com.ar"],
                "santander": ["santander.com"],
                "bbva": ["bbva.com"],
                "galicia": ["galicia.com"],
                "google": ["google.com", "gmail.com"],
                "microsoft": ["microsoft.com", "outlook.com", "live.com"],
                "apple": ["apple.com", "icloud.com"],
                "afip": ["afip.gob.ar"],
                "anses": ["anses.gob.ar"],
                "fecea": ["fecea.edu.ar"],
                "mercado libre": ["mercadolibre.com", "mercadopago.com"],
                "mercadolibre": ["mercadolibre.com", "mercadopago.com"],
            }

            for inst, valid_domains in known_institutions.items():
                if inst in name_lower:
                    if not any(vd in domain for vd in valid_domains):
                        triggered = True
                        detail = f"Nombre '{email.from_name}' no coincide con dominio '{domain}'"
                        break

        return RuleResult("A2", "Nombre visible distinto del correo real", 20, triggered, detail)

    def _rule_a3(self, email: EmailData) -> RuleResult:
        domain = self._extract_domain(email.from_email)
        triggered = False
        detail = ""

        legitimate = [
            "fecea.edu.ar", "google.com", "gmail.com", "microsoft.com",
            "outlook.com", "apple.com", "afip.gob.ar", "anses.gob.ar",
            "banco.nacion.com.ar", "santander.com.ar", "bbva.com.ar",
            "galicia.com.ar", "mercadolibre.com.ar", "mercadopago.com.ar",
        ]

        for legit in legitimate:
            if domain and domain != legit and self._is_typosquat(domain, legit):
                triggered = True
                detail = f"Posible typosquatting: '{domain}' se parece a '{legit}'"
                break

        return RuleResult("A3", "Dominio parecido al verdadero (typosquatting)", 25, triggered, detail)

    def _rule_a4(self, email: EmailData) -> RuleResult:
        triggered = False
        detail = ""

        email_lower = email.from_email.lower().strip()
        domain = self._extract_domain(email.from_email)

        if email_lower in self.whitelist or domain in self.whitelist:
            triggered = True
            detail = f"Remitente '{email.from_email}' está en la whitelist"

        return RuleResult("A4", "Remitente en lista confiable", -30, triggered, detail)

    # ========== REGLAS B – ASUNTO ==========

    def _rule_b1(self, email: EmailData) -> RuleResult:
        triggered = self._matches_any(email.subject, URGENCY_WORDS)
        detail = "Palabras de urgencia detectadas en el asunto" if triggered else ""
        return RuleResult("B1", "Urgencia en el asunto", 10, triggered, detail)

    def _rule_b2(self, email: EmailData) -> RuleResult:
        triggered = self._matches_any(email.subject, THREAT_WORDS)
        detail = "Palabras de amenaza/miedo detectadas" if triggered else ""
        return RuleResult("B2", "Amenaza o miedo", 12, triggered, detail)

    def _rule_b3(self, email: EmailData) -> RuleResult:
        triggered = self._matches_any(email.subject, PRIZE_WORDS)
        detail = "Palabras de premio/dinero fácil detectadas" if triggered else ""
        return RuleResult("B3", "Premio o dinero fácil", 10, triggered, detail)

    def _rule_b4(self, email: EmailData) -> RuleResult:
        subject = email.subject.strip()
        triggered = False
        detail = ""

        if not subject:
            triggered = True
            detail = "Asunto vacío"
        elif len(re.findall(r"[!¡?]{2,}", subject)) > 0 or subject.count("!") >= 3:
            triggered = True
            detail = "Exceso de signos de exclamación/interrogación"

        return RuleResult("B4", "Asunto vacío o con muchos signos", 5, triggered, detail)

    # ========== REGLAS C – CUERPO ==========

    def _rule_c1(self, email: EmailData) -> RuleResult:
        triggered = self._matches_any(email.body, PERSONAL_DATA_WORDS)
        detail = "Solicitud de datos personales detectada" if triggered else ""
        return RuleResult("C1", "Pide datos personales", 25, triggered, detail)

    def _rule_c2(self, email: EmailData) -> RuleResult:
        triggered = self._matches_any(email.body, CLICK_TO_SAVE_PHRASES)
        detail = "Frase de 'verificar/actualizar cuenta' detectada" if triggered else ""
        return RuleResult("C2", "Pide clic para no perder la cuenta", 15, triggered, detail)

    def _rule_c3(self, email: EmailData) -> RuleResult:
        body = email.body
        triggered = False
        detail = ""

        if not body or len(body) < 30:
            return RuleResult("C3", "Errores graves de escritura", 8, False, "")

        upper_ratio = sum(1 for c in body if c.isupper()) / max(len(body), 1)
        if upper_ratio > 0.35:
            triggered = True
            detail = "Exceso de mayúsculas"

        if body.count("!!!") >= 2 or body.count("???") >= 2:
            triggered = True
            detail = (detail + " + " if detail else "") + "Signos excesivos"

        return RuleResult("C3", "Errores graves de escritura", 8, triggered, detail)

    def _rule_c4(self, email: EmailData) -> RuleResult:
        body_lower = email.body.lower()
        triggered = False
        detail = ""

        generic_greetings = [
            r"estimado\s+usuario", r"estimado\s+cliente",
            r"hola\s+usuario", r"dear\s+user", r"dear\s+customer",
            r"estimado/a", r"señor/a",
        ]
        has_generic = self._matches_any(body_lower, generic_greetings)
        has_urgency = self._matches_any(body_lower, URGENCY_WORDS + THREAT_WORDS)

        if has_generic and has_urgency:
            triggered = True
            detail = "Saludo genérico combinado con urgencia/amenaza"

        return RuleResult("C4", "Saludo genérico + pedido urgente", 10, triggered, detail)

    # ========== REGLAS D – ENLACES ==========

    def _rule_d1(self, email: EmailData) -> RuleResult:
        triggered = False
        detail = ""

        for link in email.links:
            display = link.display_text.lower().strip()
            url_domain = self._extract_domain(link.url)

            if re.search(r"[a-z0-9\-]+\.[a-z]{2,}", display):
                display_domain = self._extract_domain("http://" + display)
                if display_domain and url_domain and display_domain not in url_domain and url_domain not in display_domain:
                    triggered = True
                    detail = f"Texto '{link.display_text}' → URL real '{link.url}'"
                    break

        return RuleResult("D1", "Texto del enlace no coincide con la URL", 25, triggered, detail)

    def _rule_d2(self, email: EmailData) -> RuleResult:
        triggered = False
        detail = ""

        for link in email.links:
            domain = self._extract_domain(link.url)
            if domain in URL_SHORTENERS:
                triggered = True
                detail = f"Acortador detectado: {domain}"
                break

        return RuleResult("D2", "Enlace acortado", 10, triggered, detail)

    def _rule_d3(self, email: EmailData) -> RuleResult:
        triggered = False
        detail = ""

        for link in email.links:
            parsed = urlparse(link.url)
            if parsed.scheme == "http":
                domain = parsed.netloc.lower()
                sensitive_keywords = [
                    "banco", "login", "cuenta", "secure", "auth",
                    "afip", "anses", "pago", "pay", "bank",
                ]
                if any(kw in domain or kw in link.url.lower() for kw in sensitive_keywords):
                    triggered = True
                    detail = f"HTTP inseguro en: {link.url}"
                    break

        return RuleResult("D3", "Usa HTTP en vez de HTTPS", 8, triggered, detail)

    def _rule_d4(self, email: EmailData) -> RuleResult:
        triggered = False
        detail = ""

        for link in email.links:
            domain = self._extract_domain(link.url)
            if not domain:
                continue

            if domain in URL_SHORTENERS:
                continue

            is_trusted = (
                domain in TRUSTED_DOMAINS
                or domain in FREE_EMAIL_DOMAINS
                or any(domain.endswith("." + td) for td in TRUSTED_DOMAINS)
            )

            if not is_trusted:
                if len(domain) > 5 and not re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
                    triggered = True
                    detail = f"Dominio no reconocido: {domain}"
                    break

        return RuleResult("D4", "Dominio desconocido", 10, triggered, detail)

    # ========== REGLAS E – ADJUNTOS ==========

    def _rule_e1(self, email: EmailData) -> RuleResult:
        triggered = False
        detail = ""

        for att in email.attachments:
            att_lower = att.lower()
            for ext in DANGEROUS_EXTENSIONS | SUSPICIOUS_EXTENSIONS:
                if att_lower.endswith(ext):
                    triggered = True
                    detail = f"Adjunto sospechoso: {att}"
                    break
            if triggered:
                break

        return RuleResult("E1", "Adjunto ejecutable o raro", 20, triggered, detail)

    def _rule_e2(self, email: EmailData) -> RuleResult:
        triggered = False
        detail = ""

        subject_body = (email.subject + " " + email.body).lower()
        mentions_invoice = any(
            w in subject_body
            for w in ["factura", "boletin", "boletín", "comprobante", "recibo", "invoice"]
        )

        if mentions_invoice:
            for att in email.attachments:
                att_lower = att.lower()
                if any(att_lower.endswith(ext) for ext in [".zip", ".rar", ".7z", ".exe", ".js", ".html", ".htm"]):
                    triggered = True
                    detail = f"Menciona factura/boletín pero adjunta: {att}"
                    break

        return RuleResult("E2", "Dice factura/boletín pero manda comprimido", 15, triggered, detail)

    # ========== UTILIDADES ==========

    @staticmethod
    def _extract_domain(email_or_url: str) -> str:
        if not email_or_url:
            return ""

        text = email_or_url.lower().strip()

        if "@" in text and not text.startswith("http"):
            return text.split("@")[-1].strip()

        if not text.startswith(("http://", "https://")):
            text = "http://" + text

        try:
            parsed = urlparse(text)
            domain = parsed.netloc or parsed.path.split("/")[0]
            domain = domain.split(":")[0]
            if domain.startswith("www."):
                domain = domain[4:]
            return domain
        except Exception:
            return ""

    @staticmethod
    def _matches_any(text: str, patterns: List[str]) -> bool:
        if not text:
            return False
        text_lower = text.lower()
        for pat in patterns:
            if re.search(pat, text_lower, re.IGNORECASE):
                return True
        return False

    @staticmethod
    def _is_typosquat(suspect: str, legitimate: str) -> bool:
        if not suspect or not legitimate:
            return False

        replacements = {
            "0": "o", "1": "l", "3": "e", "4": "a",
            "5": "s", "7": "t", "8": "b", "@": "a",
        }

        def normalize(s: str) -> str:
            s = s.lower()
            for k, v in replacements.items():
                s = s.replace(k, v)
            return s

        s_norm = normalize(suspect)
        l_norm = normalize(legitimate)

        if s_norm == l_norm and suspect != legitimate:
            return True

        def levenshtein(a: str, b: str) -> int:
            if len(a) < len(b):
                return levenshtein(b, a)
            if not b:
                return len(a)
            prev = list(range(len(b) + 1))
            for i, ca in enumerate(a):
                curr = [i + 1]
                for j, cb in enumerate(b):
                    cost = 0 if ca == cb else 1
                    curr.append(min(curr[j] + 1, prev[j + 1] + 1, prev[j] + cost))
                prev = curr
            return prev[-1]

        distance = levenshtein(suspect, legitimate)
        max_len = max(len(suspect), len(legitimate))
        if max_len > 0 and distance <= 2 and distance / max_len <= 0.25:
            return True

        return False


# ============================================================
# FUNCIÓN PARA IMPRIMIR RESULTADOS
# ============================================================

def print_analysis(result: AnalysisResult) -> None:
    print("=" * 60)
    print("  PHISHING GUARDIAN - Resultado del análisis")
    print("=" * 60)
    print(f"  Puntaje total : {result.total_points}")
    print(f"  Nivel de riesgo: {result.risk_level}")
    print("-" * 60)

    if result.triggered_rules:
        print("  Reglas activadas:")
        for r in result.triggered_rules:
            sign = "+" if r.points > 0 else ""
            print(f"    [{r.code}] {r.description}: {sign}{r.points} pts")
            if r.detail:
                print(f"           → {r.detail}")
    else:
        print("  Ninguna regla se activó.")

    print("-" * 60)
    print(f"  Recomendación: {result.recommendation}")
    print("=" * 60)


# ============================================================
# EJEMPLOS DE PRUEBA
# ============================================================

if __name__ == "__main__":
    # Ejemplo 1: Correo malicioso
    email_malo = EmailData(
        from_name="Banco Nación",
        from_email="seguridad@b4nco-nacion.com",
        subject="URGENTE!!! Tu cuenta será bloqueada en 24 horas",
        body=(
            "Estimado usuario,\n\n"
            "Detectamos actividad sospechosa. Su cuenta sera bloqueada hoy.\n"
            "Por favor verifique su cuenta haciendo clic aquí e ingrese su clave y DNI.\n"
            "Actúe ahora o perderá el acceso."
        ),
        links=[
            LinkInfo("Ingresar a Banco Nación", "http://bit.ly/bna-seguro-2026"),
            LinkInfo("fecea.edu.ar", "http://fecea-edu-login.ru/verificar"),
        ],
        attachments=["factura_septiembre.zip"],
    )

    analyzer = PhishingAnalyzer(whitelist={"profesor@fecea.edu.ar"})
    resultado = analyzer.analyze(email_malo)
    print_analysis(resultado)

    print("\n")

    # Ejemplo 2: Correo legítimo
    email_bueno = EmailData(
        from_name="Soporte FECEA",
        from_email="soporte@fecea.edu.ar",
        subject="Recordatorio de inscripción a finales",
        body=(
            "Hola,\n\n"
            "Te recordamos que el período de inscripción a mesas de final "
            "cierra el viernes. Podés inscribirte desde el campus virtual.\n\n"
            "Saludos,\nEquipo de Soporte"
        ),
        links=[
            LinkInfo("Campus Virtual", "https://campus.fecea.edu.ar"),
        ],
        attachments=[],
    )

    resultado2 = analyzer.analyze(email_bueno)
    print_analysis(resultado2)


def analizar(de: str, asunto: str, cuerpo: str, enlaces=None) -> dict:
    """Puente para server.py. Usa las 18 reglas de PhishingAnalyzer."""
    texto = (de or "").strip()
    from_name = ""
    from_email = ""
    match = re.search(r"^(.*?)\s*<([^>]+)>\s*$", texto)
    if match:
        from_name = match.group(1).strip().strip("\"")
        from_email = match.group(2).strip()
    elif "@" in texto:
        from_email = texto
    else:
        from_name = texto

    links = []
    for item in enlaces or []:
        if isinstance(item, str):
            links.append(LinkInfo(item, item))
        else:
            links.append(LinkInfo(str(item), str(item)))

    email = EmailData(
        from_name=from_name,
        from_email=from_email,
        subject=asunto or "",
        body=cuerpo or "",
        links=links,
        attachments=[],
    )
    result = PhishingAnalyzer().analyze(email)
    return {
        "riesgo": result.risk_level,
        "puntos": result.total_points,
        "motivos": [f"{r.code}: {r.description}" for r in result.triggered_rules],
    }
