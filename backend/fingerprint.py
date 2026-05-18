"""
Content fingerprinting.

Images  → 64-bit DCT perceptual hash (pHash).
          Resistant to: format changes, JPEG re-compression, aspect-ratio-
          preserving resizes, minor crops.  Compared via Hamming distance.

PDFs    → SHA-256 of normalized text content.
          Strips metadata and whitespace variance; survives PDF re-saves
          that don't alter the text.
"""

import hashlib
import io
import re

import fitz  # PyMuPDF
import imagehash
from PIL import Image

AUTHENTIC_THRESHOLD = 0   # bits: only an exact perceptual match is authentic
MODIFIED_THRESHOLD = 20   # bits: above this → treat as different image


def phash_image(file_bytes: bytes) -> str:
    """Return the 64-bit pHash of an image as a 16-char hex string."""
    img = Image.open(io.BytesIO(file_bytes)).convert("RGB")
    return str(imagehash.phash(img))


def hamming_distance(hash_a: str, hash_b: str) -> int:
    return int(imagehash.hex_to_hash(hash_a) - imagehash.hex_to_hash(hash_b))


def similarity_score(distance: int) -> float:
    return round(1.0 - distance / 64.0, 3)


def classify_image_match(distance: int) -> str:
    if distance <= AUTHENTIC_THRESHOLD:
        return "authentic"
    if distance <= MODIFIED_THRESHOLD:
        return "possibly_modified"
    return "not_matched"


def sha256_pdf(file_bytes: bytes) -> str:
    """
    Extract text from every page of the PDF, normalize whitespace,
    and return the SHA-256 hex digest of the UTF-8 encoded result.
    """
    doc = fitz.open(stream=file_bytes, filetype="pdf")
    pages = [page.get_text() for page in doc]
    raw = "\n".join(pages)
    normalized = re.sub(r"\s+", " ", raw).strip()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()
