"""
OpenAI Proxy with automatic PII anonymization/deanonymization.

This module provides a drop-in replacement for OpenAI API that automatically:
1. Anonymizes user messages before sending to OpenAI
2. Deanonymizes AI responses before returning to client
"""
import os
import time
import logging
import httpx
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

from .integration import platform_integration
from .database import pii_db

logger = logging.getLogger(__name__)

# Default OpenAI API key (can be overridden per request)
DEFAULT_OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"


class OpenAIMessage(BaseModel):
    """Single message in OpenAI format."""
    role: str
    content: str
    name: Optional[str] = None


class OpenAIProxyRequest(BaseModel):
    """Request format compatible with OpenAI Chat Completions API."""
    model: str = Field(default="gpt-4o-mini", description="OpenAI model to use")
    messages: List[OpenAIMessage] = Field(..., description="Conversation messages")
    temperature: Optional[float] = Field(default=0.7)
    max_tokens: Optional[int] = Field(default=1000)
    top_p: Optional[float] = None
    frequency_penalty: Optional[float] = None
    presence_penalty: Optional[float] = None
    stop: Optional[List[str]] = None

    # PII-specific fields
    contact_id: Optional[str] = Field(default=None, description="Contact ID for session tracking")
    page_id: Optional[str] = Field(default=None, description="Bot/Page ID")
    channel: Optional[str] = Field(default=None, description="Channel (telegram, whatsapp, etc)")
    pii_enabled: bool = Field(default=True, description="Enable PII anonymization")
    openai_api_key: Optional[str] = Field(default=None, description="Custom OpenAI API key")

    # System prompt injection
    pii_system_prompt: Optional[str] = Field(
        default=None,
        description="Additional system prompt about PII placeholders"
    )


class OpenAIProxyResponse(BaseModel):
    """Response format compatible with OpenAI Chat Completions API."""
    id: str
    object: str = "chat.completion"
    created: int
    model: str
    choices: List[Dict[str, Any]]
    usage: Optional[Dict[str, int]] = None

    # PII-specific fields
    pii_session_id: Optional[str] = None
    pii_entities_found: Optional[List[str]] = None
    pii_count: Optional[int] = None
    pii_processing_time_ms: Optional[int] = None


class OpenAIProxyService:
    """
    Proxy service that wraps OpenAI API with automatic PII protection.

    Flow:
    1. Receive OpenAI-compatible request
    2. Anonymize all user messages
    3. Forward to OpenAI
    4. Deanonymize response
    5. Return to client
    """

    # Default system prompt addition for PII awareness
    DEFAULT_PII_SYSTEM_PROMPT = """
ВАЖНО: Данные клиента передаются в защищённом виде как {{name_1}}, {{phone_1}}, {{email_1}} и т.д.
Используй эти плейсхолдеры как есть в своих ответах - система автоматически заменит их на реальные данные.
НЕ пытайся угадать или спрашивать реальные данные клиента.
"""

    def __init__(self):
        self.http_client = httpx.AsyncClient(timeout=60.0)

    async def process_request(
        self,
        request: OpenAIProxyRequest
    ) -> OpenAIProxyResponse:
        """
        Process OpenAI request with PII protection.
        """
        start_time = time.time()
        session_id = None
        pii_entities = []
        pii_count = 0

        # Get or create session for this contact
        if request.contact_id:
            session_id = self._get_or_create_session(
                contact_id=request.contact_id,
                page_id=request.page_id,
                channel=request.channel
            )

        # Prepare messages (with anonymization if enabled)
        processed_messages = []

        for msg in request.messages:
            if msg.role == "user" and request.pii_enabled:
                # Anonymize user messages
                anon_result = platform_integration.anonymize_for_platform(
                    message=msg.content,
                    contact_id=request.contact_id,
                    page_id=request.page_id,
                    channel=request.channel,
                    existing_session_id=session_id
                )

                session_id = anon_result.session_id
                pii_entities.extend(anon_result.pii_found)
                pii_count += anon_result.pii_count

                processed_messages.append({
                    "role": msg.role,
                    "content": anon_result.anonymized_message
                })

                logger.info(
                    f"Anonymized user message: found {anon_result.pii_count} PII items"
                )

            elif msg.role == "system" and request.pii_enabled:
                # Add PII awareness to system prompt
                pii_addition = request.pii_system_prompt or self.DEFAULT_PII_SYSTEM_PROMPT
                enhanced_content = msg.content + "\n\n" + pii_addition
                processed_messages.append({
                    "role": msg.role,
                    "content": enhanced_content
                })

            else:
                # Pass through assistant messages and other roles
                processed_messages.append({
                    "role": msg.role,
                    "content": msg.content
                })

        # Prepare OpenAI request
        openai_request = {
            "model": request.model,
            "messages": processed_messages,
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
        }

        # Add optional parameters
        if request.top_p is not None:
            openai_request["top_p"] = request.top_p
        if request.frequency_penalty is not None:
            openai_request["frequency_penalty"] = request.frequency_penalty
        if request.presence_penalty is not None:
            openai_request["presence_penalty"] = request.presence_penalty
        if request.stop is not None:
            openai_request["stop"] = request.stop

        # Get API key
        api_key = request.openai_api_key or DEFAULT_OPENAI_API_KEY
        if not api_key:
            raise ValueError("OpenAI API key not provided and no default configured")

        # Call OpenAI API
        try:
            openai_response = await self._call_openai(openai_request, api_key)
        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            raise

        # Deanonymize response if PII was found
        if request.pii_enabled and session_id and pii_count > 0:
            for choice in openai_response.get("choices", []):
                if "message" in choice and "content" in choice["message"]:
                    original_content = choice["message"]["content"]

                    deanon_result = platform_integration.deanonymize_for_platform(
                        message=original_content,
                        session_id=session_id
                    )

                    choice["message"]["content"] = deanon_result.restored_message

                    logger.info(
                        f"Deanonymized response: restored {pii_count} PII items"
                    )

        processing_time_ms = int((time.time() - start_time) * 1000)

        # Build response
        return OpenAIProxyResponse(
            id=openai_response.get("id", f"pii-{int(time.time())}"),
            object=openai_response.get("object", "chat.completion"),
            created=openai_response.get("created", int(time.time())),
            model=openai_response.get("model", request.model),
            choices=openai_response.get("choices", []),
            usage=openai_response.get("usage"),
            pii_session_id=session_id,
            pii_entities_found=list(set(pii_entities)) if pii_entities else None,
            pii_count=pii_count if pii_count > 0 else None,
            pii_processing_time_ms=processing_time_ms
        )

    async def _call_openai(
        self,
        request: Dict[str, Any],
        api_key: str
    ) -> Dict[str, Any]:
        """Call OpenAI API."""
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

        response = await self.http_client.post(
            OPENAI_API_URL,
            json=request,
            headers=headers
        )

        if response.status_code != 200:
            error_detail = response.text
            logger.error(f"OpenAI API error {response.status_code}: {error_detail}")
            raise Exception(f"OpenAI API error: {response.status_code} - {error_detail}")

        return response.json()

    def _get_or_create_session(
        self,
        contact_id: str,
        page_id: Optional[str] = None,
        channel: Optional[str] = None
    ) -> str:
        """
        Get existing session for contact or create new one.
        This ensures consistent PII mapping within a conversation.
        """
        try:
            # Try to find existing session for this contact
            from .database import get_connection
            from psycopg2.extras import RealDictCursor

            with get_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    # Find most recent non-expired session for this contact
                    cur.execute("""
                        SELECT session_id FROM pii_sessions
                        WHERE contact_id = %s
                        AND expires_at > CURRENT_TIMESTAMP
                        ORDER BY updated_at DESC
                        LIMIT 1
                    """, (contact_id,))

                    row = cur.fetchone()
                    if row:
                        logger.info(f"Found existing session {row['session_id']} for contact {contact_id}")
                        return row['session_id']

            # No existing session, create new one
            import uuid
            new_session_id = str(uuid.uuid4())[:16]

            pii_db.create_session(
                session_id=new_session_id,
                contact_id=contact_id,
                page_id=page_id,
                channel=channel,
                ttl_hours=24  # Sessions last 24 hours
            )

            logger.info(f"Created new session {new_session_id} for contact {contact_id}")
            return new_session_id

        except Exception as e:
            logger.warning(f"Session management error: {e}, creating temporary session")
            import uuid
            return str(uuid.uuid4())[:16]

    async def close(self):
        """Close HTTP client."""
        await self.http_client.aclose()


# Global instance
openai_proxy_service = OpenAIProxyService()
