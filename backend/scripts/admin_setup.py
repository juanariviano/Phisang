"""Generate the admin credentials for .env, and the QR line to enrol an app.

    backend/.venv/bin/python backend/scripts/admin_setup.py admin@example.com

Prints four values to paste into .env and an otpauth:// URI to turn into a QR
code. The password is read from a prompt, never from the command line, so it
does not land in your shell history. Nothing is written to disk by this script.
"""
import getpass
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import admin, totp


def main():
    email = sys.argv[1] if len(sys.argv) > 1 else input("Admin email: ").strip()
    password = getpass.getpass("Admin password: ")
    if not email or not password:
        raise SystemExit("An email and a password are both required.")
    if password != getpass.getpass("Repeat password: "):
        raise SystemExit("The passwords did not match.")

    secret = totp.new_secret()
    print("\n--- paste into .env (keep it out of git) ---")
    print(f"ADMIN_EMAIL={email}")
    print(f"ADMIN_PASSWORD_HASH={admin.hash_password(password)}")
    print(f"ADMIN_TOTP_SECRET={secret}")
    print(f"ADMIN_SESSION_SECRET={secrets.token_urlsafe(48)}")
    print("\n--- enrol the authenticator ---")
    print("Scan this as a QR code, or type the secret into the app by hand:")
    print(totp.provisioning_uri(secret, email))
    print(f"\nSecret for manual entry: {secret}")


if __name__ == "__main__":
    main()
