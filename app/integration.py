"""
Platform Integration API for Business Robots AI.

Flow:
1. Platform sends message -> /api/v1/anonymize -> returns anonymized message + session_id
2. Platform sends to OpenAI
3. OpenAI response -> /api/v1/deanonymize -> returns restored message
"""
import re
import uuid
import time
import logging
from typing import Dict, Optional, List, Any
from pydantic import BaseModel, Field

from .anonymizer import anonymizer
from .database import pii_db

logger = logging.getLogger(__name__)


# Request/Response models for platform integration
class PlatformAnonymizeRequest(BaseModel):
    """Request from platform to anonymize message."""
    message: str = Field(..., min_length=1, max_length=50000, description="Message to anonymize")
    page_id: Optional[str] = Field(default=None, description="Platform page/bot ID")
    session_id: Optional[str] = Field(default=None, description="Existing session ID to reuse")


class PlatformAnonymizeResponse(BaseModel):
    """Response with anonymized message."""
    success: bool
    session_id: str = Field(description="Session ID for deanonymization")
    original_message: str
    anonymized_message: str
    pii_found: List[str] = Field(default_factory=list)
    pii_count: int
    processing_time_ms: int


class PlatformDeanonymizeRequest(BaseModel):
    """Request to restore PII in message."""
    message: str = Field(..., min_length=1, max_length=50000, description="Message with placeholders")
    session_id: str = Field(..., description="Session ID from anonymization")


class PlatformDeanonymizeResponse(BaseModel):
    """Response with restored message."""
    success: bool
    session_id: str
    anonymized_message: str
    restored_message: str
    processing_time_ms: int


class PlatformIntegration:
    """
    Handles integration with Business Robots AI platform.

    Uses {{field_name}} format for placeholders:
    - {{first_name_1}}, {{first_name_2}} for names
    - {{phone_1}} for phones
    - {{pinfl_1}} for PINFL
    - etc.
    """

    # Mapping from internal types to user-friendly placeholder names
    TYPE_TO_PLACEHOLDER = {
        "NAME": "name",
        "PINFL": "pinfl",
        "PASSPORT": "passport",
        "PHONE": "phone",
        "CARD": "card",
        "INN": "inn",
        "ACCOUNT": "account",
        "EMAIL": "email",
        "ADDRESS": "address",
        "DATE": "date",
    }

    def anonymize_for_platform(
        self,
        message: str,
        page_id: Optional[str] = None,
        existing_session_id: Optional[str] = None,
        user_id: Optional[int] = None,
        **kwargs,
    ) -> PlatformAnonymizeResponse:
        """
        Anonymize message for platform integration.

        Returns anonymized message with {{field_name}} placeholders.
        """
        start_time = time.time()

        # Create or reuse session
        session_id = existing_session_id or str(uuid.uuid4())[:16]

        try:
            pii_db.create_session(
                session_id=session_id,
                page_id=page_id,
                user_id=user_id
            )
        except Exception as e:
            logger.warning(f"Could not create DB session, using memory: {e}")

        # Perform anonymization
        anonymized_text, mapping, pii_types, proc_time = anonymizer.anonymize(message)

        # Get confidence data from anonymizer
        raw_confidence = getattr(anonymizer, '_last_confidence', {})

        # Convert [TYPE_001] format to {{type_1}} format
        converted_mapping = {}
        pii_type_mapping = {}
        converted_confidence = {}
        new_text = anonymized_text

        for placeholder, original_value in mapping.items():
            # Extract type and number from [TYPE_001]
            match = re.match(r"\[([A-Z]+)_(\d+)\]", placeholder)
            if match:
                pii_type = match.group(1)
                num = int(match.group(2))
                friendly_type = self.TYPE_TO_PLACEHOLDER.get(pii_type, pii_type.lower())
                new_placeholder = f"{{{{{friendly_type}_{num}}}}}"

                new_text = new_text.replace(placeholder, new_placeholder)
                converted_mapping[new_placeholder] = original_value
                pii_type_mapping[new_placeholder] = pii_type
                if placeholder in raw_confidence:
                    converted_confidence[new_placeholder] = raw_confidence[placeholder]

        # Store in database
        try:
            pii_db.store_mapping(session_id, converted_mapping, pii_type_mapping, user_id=user_id, confidence_map=converted_confidence)
            pii_db.log_action(
                action="anonymize",
                session_id=session_id,
                details={
                    "pii_count": len(converted_mapping),
                    "pii_types": pii_types
                }
            )
        except Exception as e:
            logger.warning(f"Could not store in DB: {e}")
            # Fall back to memory cache
            anonymizer.mapping_cache.store(converted_mapping)

        processing_time_ms = int((time.time() - start_time) * 1000)

        return PlatformAnonymizeResponse(
            success=True,
            session_id=session_id,
            original_message=message,
            anonymized_message=new_text,
            pii_found=pii_types,
            pii_count=len(converted_mapping),
            processing_time_ms=processing_time_ms
        )

    def deanonymize_for_platform(
        self,
        message: str,
        session_id: str,
        user_id: Optional[int] = None,
    ) -> PlatformDeanonymizeResponse:
        """
        Restore PII in message using session mapping.
        """
        start_time = time.time()

        # Get mapping from database
        mapping = None
        try:
            mapping = pii_db.get_mapping(session_id)
        except Exception as e:
            logger.warning(f"Could not get from DB: {e}")

        if not mapping:
            # Try memory cache
            mapping = anonymizer.mapping_cache.get(session_id)

        if not mapping:
            return PlatformDeanonymizeResponse(
                success=False,
                session_id=session_id,
                anonymized_message=message,
                restored_message=message,
                processing_time_ms=0
            )

        # Replace placeholders with original values
        restored = message
        for placeholder, original_value in mapping.items():
            restored = restored.replace(placeholder, original_value)

        # Log action
        try:
            pii_db.log_action(
                action="deanonymize",
                session_id=session_id,
                details={"placeholders_restored": len(mapping)}
            )
        except Exception as e:
            logger.warning(f"Could not log action: {e}")

        processing_time_ms = int((time.time() - start_time) * 1000)

        return PlatformDeanonymizeResponse(
            success=True,
            session_id=session_id,
            anonymized_message=message,
            restored_message=restored,
            processing_time_ms=processing_time_ms
        )


# Global instance
platform_integration = PlatformIntegration()
