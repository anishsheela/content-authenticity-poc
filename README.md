# Content Authenticity POC

Proof-of-concept for media authenticity. Creators register images or PDFs with a PGP-signed fingerprint; anyone can later verify a file — even after re-encoding or light editing — and see who originally published it.

## How it works

- **Register** — generates a PGP keypair for the creator, computes a perceptual hash (images) or normalised SHA-256 (PDFs), signs the assertion, and stores everything in the database.
- **Verify** — re-fingerprints the uploaded file, finds the closest registered record, checks the PGP signature, and returns the match status.

Image matching tolerates re-encoding and minor edits using DCT perceptual hashing (Hamming distance ≤ 10 = exact, ≤ 20 = modified, > 20 = not found).

## Stack

| Layer | Tech |
|-------|------|
| Backend | FastAPI + SQLAlchemy |
| Database | PostgreSQL |
| Crypto | GnuPG (python-gnupg) |
| Fingerprinting | imagehash (pHash), PyMuPDF |
| Frontend | Vanilla HTML/CSS/JS |

## Local development

```bash
# Start PostgreSQL
docker compose up -d

# Install deps
python3 -m venv .venv && source .venv/bin/activate
pip install -r backend/requirements.txt

# Run
cd backend
uvicorn main:app --reload --port 8000
```

Open `http://localhost:8000`.

## API

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/register` | Register a new creator, get PGP keypair |
| POST | `/api/login` | Authenticate by uploading private key |
| POST | `/api/register-content` | Sign and register an image or PDF |
| POST | `/api/verify` | Verify a file against registered content |
