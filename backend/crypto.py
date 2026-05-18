"""
OpenPGP signing and verification via python-gnupg (wraps system gpg binary).

Each operation creates an isolated temporary gnupghome so this process never
touches the user's real ~/.gnupg keyring.

Key type : Ed25519 (EdDSA) — sign only, no expiry.
UID format: "Full Name (handle) <>" per RFC 4880 §5.11.
Signature format: OpenPGP clearsign — JSON body is plaintext, independently
                  verifiable with any gpg-compatible client:
                  gpg --verify assertion.asc
"""

import json
import os
import shutil
import tempfile

import gnupg


def _tmp_gpg() -> tuple[gnupg.GPG, str]:
    """Return (gpg, homedir). Caller must shutil.rmtree(homedir) when done."""
    homedir = tempfile.mkdtemp(prefix="auth_poc_gpg_")
    os.chmod(homedir, 0o700)
    return gnupg.GPG(gnupghome=homedir), homedir


def generate_keypair(full_name: str, handle: str | None = None) -> tuple[str, str]:
    """
    Generate an Ed25519 keypair.
    Returns (private_key_armored, public_key_armored).
    """
    gpg, homedir = _tmp_gpg()
    try:
        params = gpg.gen_key_input(
            key_type="EDDSA",
            key_curve="Ed25519",
            key_usage="sign",
            name_real=full_name,
            name_comment=handle or "",
            name_email="",
            expire_date="0",
            no_protection=True,
        )
        result = gpg.gen_key(params)
        fp = str(result)
        # expect_passphrase=False: key was generated with no_protection=True
        # so the agent holds it unencrypted — no passphrase needed for export.
        private_key = str(gpg.export_keys(fp, secret=True, armor=True, expect_passphrase=False))
        public_key  = str(gpg.export_keys(fp, secret=False, armor=True))
        return private_key, public_key
    finally:
        shutil.rmtree(homedir, ignore_errors=True)


def key_fingerprint(public_key_armored: str) -> str:
    """Return the 40-char OpenPGP fingerprint of a public key."""
    gpg, homedir = _tmp_gpg()
    try:
        result = gpg.import_keys(public_key_armored)
        return result.fingerprints[0] if result.fingerprints else ""
    finally:
        shutil.rmtree(homedir, ignore_errors=True)


def sign_assertion(private_key_armored: str, assertion: dict) -> str:
    """
    Sign a dict as an OpenPGP clearsign message.
    JSON is sorted + indented so the plaintext is deterministic and readable.
    Returns the full armored clearsign block.
    """
    gpg, homedir = _tmp_gpg()
    try:
        gpg.import_keys(private_key_armored)
        payload = json.dumps(assertion, indent=2, sort_keys=True)
        signed  = gpg.sign(payload, clearsign=True)
        return str(signed)
    finally:
        shutil.rmtree(homedir, ignore_errors=True)


def verify_signature(public_key_armored: str, signed_message_armored: str) -> tuple[bool, dict]:
    """
    Verify an OpenPGP clearsign block against a public key.
    Returns (signature_valid, assertion_dict).
    """
    gpg, homedir = _tmp_gpg()
    try:
        gpg.import_keys(public_key_armored)
        verified = gpg.verify(signed_message_armored)
        valid    = bool(verified.valid)
        assertion = json.loads(_extract_clearsign_body(signed_message_armored))
        return valid, assertion
    finally:
        shutil.rmtree(homedir, ignore_errors=True)


def authenticate_private_key(key_armored: str) -> str | None:
    """
    Verify the armored text is a private (secret) key.
    Returns the 40-char fingerprint if valid, None otherwise.
    Used for celebrity login: proves possession of the private key.
    """
    gpg, homedir = _tmp_gpg()
    try:
        result = gpg.import_keys(key_armored)
        if not result.fingerprints:
            return None
        secret_keys = gpg.list_keys(secret=True)
        if not secret_keys:
            return None  # public key uploaded — not sufficient for login
        return result.fingerprints[0]
    finally:
        shutil.rmtree(homedir, ignore_errors=True)


def _extract_clearsign_body(armored: str) -> str:
    """Extract the plaintext payload from a PGP clearsign block."""
    lines   = armored.splitlines()
    body    = []
    in_body = False
    for line in lines:
        if line.startswith("-----BEGIN PGP SIGNATURE-----"):
            break
        if in_body:
            body.append(line)
        elif line == "":
            in_body = True  # blank line after headers signals start of body
    return "\n".join(body).strip()
