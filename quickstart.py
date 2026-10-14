import argparse
import os

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
CREDENTIALS_FILE = "credentials.json"
TOKENS_DIR = "tokens"


def get_service(usuario):
    os.makedirs(TOKENS_DIR, exist_ok=True)
    token_path = os.path.join(TOKENS_DIR, f"{usuario}.json")

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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--usuario",
        required=True,
        choices=["emiliano", "lucio", "denzel"],
    )
    args = parser.parse_args()

    try:
        service = get_service(args.usuario)
        profile = service.users().getProfile(userId="me").execute()
        print(f"Cuenta conectada: {profile.get('emailAddress')}")
        print(f"Total de correos: {profile.get('messagesTotal')}")

        results = service.users().messages().list(userId="me", maxResults=5).execute()
        messages = results.get("messages", [])

        if not messages:
            print("No hay correos para mostrar.")
            return

        print("\nUltimos 5 correos:")
        for item in messages:
            msg = service.users().messages().get(
                userId="me",
                id=item["id"],
                format="metadata",
                metadataHeaders=["From", "Subject"],
            ).execute()
            headers = {
                h["name"]: h["value"]
                for h in msg.get("payload", {}).get("headers", [])
            }
            print(f"- De: {headers.get('From', '(sin remitente)')}")
            print(f"  Asunto: {headers.get('Subject', '(sin asunto)')}")

    except HttpError as error:
        print(f"Error de la API: {error}")


if __name__ == "__main__":
    main()