import os

if os.environ.get("GOOGLE_CREDENTIALS"):
    with open("credentials_web.json", "w", encoding="utf-8") as f:
        f.write(os.environ["GOOGLE_CREDENTIALS"])

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
CLIENT_FILE = "credentials_web.json"
REDIRECT = "https://phishing-guardian.onrender.com/callback"
TOKENS_WEB = "tokens_web"


def crear_flow():
    return Flow.from_client_secrets_file(
        CLIENT_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT,
    )


def guardar_token(creds):
    os.makedirs(TOKENS_WEB, exist_ok=True)
    service = build("gmail", "v1", credentials=creds)
    profile = service.users().getProfile(userId="me").execute()
    email = profile.get("emailAddress")
    path = os.path.join(TOKENS_WEB, email + ".json")
    with open(path, "w", encoding="utf-8") as f:
        f.write(creds.to_json())
    return email


def service_de_email(email):
    path = os.path.join(TOKENS_WEB, email + ".json")
    if not os.path.exists(path):
        return None
    creds = Credentials.from_authorized_user_file(path, SCOPES)
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
        with open(path, "w", encoding="utf-8") as f:
            f.write(creds.to_json())
    return build("gmail", "v1", credentials=creds)