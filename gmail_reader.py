import base64
import os
import re

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
CREDENTIALS_FILE = "credentials.json"


def tokens_dir():
    if os.path.isdir("tokens"):
        return "tokens"
    return "Tokens"


def get_service(usuario):
    os.makedirs(tokens_dir(), exist_ok=True)
    token_path = os.path.join(tokens_dir(), f"{usuario}.json")

    creds = None
    if os.path.exists(token_path):
        creds = Credentials.from_authorized_user_file(token_path, SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(token_path, "w", encoding="utf-8") as token:
            token.write(creds.to_json())

    return build("gmail", "v1", credentials=creds)


def _decode(data):
    if not data:
        return ""
    return base64.urlsafe_b64decode(data + "==").decode("utf-8", errors="replace")


def _extract_body(payload):
    if payload.get("body", {}).get("data"):
        return _decode(payload["body"]["data"])

    text = ""
    for part in payload.get("parts", []):
        mime = part.get("mimeType", "")
        if mime == "text/plain":
            text += _decode(part.get("body", {}).get("data", ""))
        elif mime.startswith("multipart/"):
            text += _extract_body(part)
        elif mime == "text/html" and not text:
            html = _decode(part.get("body", {}).get("data", ""))
            text += re.sub(r"<[^>]+>", " ", html)
    return text


def leer_correos(usuario, cantidad=5):
    service = get_service(usuario)
    return leer_correos_con_service(service, cantidad)


def leer_correos_con_service(service, cantidad=5):
    profile = service.users().getProfile(userId="me").execute()
    results = service.users().messages().list(userId="me", maxResults=cantidad).execute()
    messages = results.get("messages", [])
    correos = []

    for item in messages:
        msg = service.users().messages().get(userId="me", id=item["id"], format="full").execute()
        headers = {
            h["name"].lower(): h["value"]
            for h in msg.get("payload", {}).get("headers", [])
        }
        cuerpo = _extract_body(msg.get("payload", {}))
        enlaces = re.findall(r"https?://[^\s<>\"]+", cuerpo)
        correos.append({
            "id": item["id"],
            "de": headers.get("from", ""),
            "asunto": headers.get("subject", ""),
            "cuerpo": cuerpo[:4000],
            "enlaces": enlaces[:20],
        })

    return {
        "cuenta": profile.get("emailAddress"),
        "correos": correos,
    }