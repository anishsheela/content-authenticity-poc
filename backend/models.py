import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from database import Base


class ContentType(str, enum.Enum):
    image = "image"
    pdf = "pdf"


class Creator(Base):
    __tablename__ = "creators"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    full_name = Column(String, nullable=False)
    handle = Column(String, nullable=True)
    public_key_armored = Column(Text, nullable=False)
    # POC simplification: server retains private key for signing.
    # In production, signing moves fully client-side.
    private_key_armored = Column(Text, nullable=False)
    pgp_fingerprint = Column(String(40), nullable=False, unique=True, index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    registrations = relationship("ContentRegistration", back_populates="creator")


class ContentRegistration(Base):
    __tablename__ = "content_registrations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    creator_id = Column(UUID(as_uuid=True), ForeignKey("creators.id"), nullable=False)
    content_type = Column(Enum(ContentType), nullable=False)
    fingerprint = Column(String, nullable=False, index=True)
    signed_assertion = Column(Text, nullable=False)  # OpenPGP clearsign block
    title = Column(String, nullable=True)
    registered_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    creator = relationship("Creator", back_populates="registrations")
