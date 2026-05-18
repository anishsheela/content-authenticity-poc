from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from crypto import authenticate_private_key, generate_keypair, key_fingerprint, sign_assertion, verify_signature
from database import Base, SessionLocal, engine
from fingerprint import (
    MODIFIED_THRESHOLD,
    classify_image_match,
    hamming_distance,
    phash_image,
    sha256_pdf,
    similarity_score,
)
from models import ContentRegistration, ContentType, Creator

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Content Authenticity POC")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

SUPPORTED_IMAGES = {".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".tiff"}
FRONTEND_DIR = Path(__file__).parent.parent / "frontend"


# ---------------------------------------------------------------------------
# Celebrity: register identity and get keypair
# ---------------------------------------------------------------------------

@app.post("/api/register")
async def register(full_name: str = Form(...), handle: str = Form(None)):
    private_key, public_key = generate_keypair(full_name, handle)
    fingerprint = key_fingerprint(public_key)

    db = SessionLocal()
    try:
        creator = Creator(
            full_name=full_name,
            handle=handle or None,
            public_key_armored=public_key,
            private_key_armored=private_key,
            pgp_fingerprint=fingerprint,
        )
        db.add(creator)
        db.commit()
        db.refresh(creator)

        return {
            "creator_id": str(creator.id),
            "full_name": creator.full_name,
            "handle": creator.handle,
            "pgp_fingerprint": fingerprint,
            "public_key": public_key,
            "private_key": private_key,
        }
    finally:
        db.close()


@app.post("/api/login")
async def login(file: UploadFile = File(...)):
    """
    Celebrity login: upload your private key (.asc).
    Server extracts the PGP fingerprint from the key and matches it against
    registered creators. Proves possession of the private key without a password.
    """
    key_bytes = await file.read()
    try:
        key_text = key_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(400, "Key file must be a UTF-8 armored PGP private key (.asc).")

    fingerprint = authenticate_private_key(key_text)
    if not fingerprint:
        raise HTTPException(401, "Invalid or unrecognised key. Make sure you upload your private key (.asc), not the public key.")

    db = SessionLocal()
    try:
        creator = db.query(Creator).filter(Creator.pgp_fingerprint == fingerprint).first()
        if not creator:
            raise HTTPException(404, "No registered creator found for this key.")

        return {
            "creator_id": str(creator.id),
            "full_name": creator.full_name,
            "handle": creator.handle,
            "pgp_fingerprint": fingerprint,
        }
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Celebrity: register a piece of content (sign + store fingerprint)
# ---------------------------------------------------------------------------

@app.post("/api/register-content")
async def register_content(
    creator_id: str = Form(...),
    title: str = Form(None),
    file: UploadFile = File(...),
):
    file_bytes = await file.read()
    suffix = Path(file.filename).suffix.lower()

    if suffix == ".pdf":
        content_type = ContentType.pdf
        fingerprint = sha256_pdf(file_bytes)
        fingerprint_type = "sha256-normalized-text"
    elif suffix in SUPPORTED_IMAGES:
        content_type = ContentType.image
        fingerprint = phash_image(file_bytes)
        fingerprint_type = "phash-dct-64"
    else:
        raise HTTPException(400, f"Unsupported file type '{suffix}'. Use JPEG, PNG, WebP, or PDF.")

    db = SessionLocal()
    try:
        creator = db.query(Creator).filter(Creator.id == creator_id).first()
        if not creator:
            raise HTTPException(404, "Creator not found.")

        assertion = {
            "creator_id": str(creator.id),
            "name": creator.full_name,
            "handle": creator.handle,
            "fingerprint": fingerprint,
            "fingerprint_type": fingerprint_type,
            "content_type": content_type.value,
            "title": title,
            "registered_at": datetime.now(timezone.utc).isoformat(),
        }

        signed = sign_assertion(creator.private_key_armored, assertion)

        reg = ContentRegistration(
            creator_id=creator.id,
            content_type=content_type,
            fingerprint=fingerprint,
            signed_assertion=signed,
            title=title,
        )
        db.add(reg)
        db.commit()
        db.refresh(reg)

        return {
            "registration_id": str(reg.id),
            "fingerprint": fingerprint,
            "fingerprint_type": fingerprint_type,
            "signed_assertion": signed,
        }
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Anyone: verify a file against registered content
# ---------------------------------------------------------------------------

@app.post("/api/verify")
async def verify(file: UploadFile = File(...)):
    file_bytes = await file.read()
    suffix = Path(file.filename).suffix.lower()

    db = SessionLocal()
    try:
        if suffix == ".pdf":
            fingerprint = sha256_pdf(file_bytes)
            reg = (
                db.query(ContentRegistration)
                .filter(
                    ContentRegistration.fingerprint == fingerprint,
                    ContentRegistration.content_type == ContentType.pdf,
                )
                .first()
            )

            if not reg:
                return {"status": "not_found", "message": "No matching registered document found."}

            valid, _ = verify_signature(reg.creator.public_key_armored, reg.signed_assertion)
            return {
                "status": "authentic" if valid else "signature_invalid",
                "match_type": "exact",
                "hamming_distance": None,
                "similarity_score": 1.0 if valid else None,
                "creator": {"name": reg.creator.full_name, "handle": reg.creator.handle},
                "title": reg.title,
                "registered_at": reg.registered_at.isoformat(),
                "signature_valid": valid,
                "signed_assertion": reg.signed_assertion,
            }

        elif suffix in SUPPORTED_IMAGES:
            fingerprint = phash_image(file_bytes)
            all_regs = (
                db.query(ContentRegistration)
                .filter(ContentRegistration.content_type == ContentType.image)
                .all()
            )

            best, best_dist = None, 65
            for reg in all_regs:
                dist = hamming_distance(fingerprint, reg.fingerprint)
                if dist < best_dist:
                    best_dist = dist
                    best = reg

            if best is None or best_dist > MODIFIED_THRESHOLD:
                return {"status": "not_found", "message": "No matching registered image found."}

            valid, _ = verify_signature(best.creator.public_key_armored, best.signed_assertion)
            status = classify_image_match(best_dist) if valid else "signature_invalid"
            return {
                "status": status,
                "match_type": "perceptual",
                "hamming_distance": best_dist,
                "similarity_score": similarity_score(best_dist),
                "creator": {"name": best.creator.full_name, "handle": best.creator.handle},
                "title": best.title,
                "registered_at": best.registered_at.isoformat(),
                "signature_valid": valid,
                "signed_assertion": best.signed_assertion,
            }

        else:
            raise HTTPException(400, f"Unsupported file type '{suffix}'.")
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Serve frontend
# ---------------------------------------------------------------------------

app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
