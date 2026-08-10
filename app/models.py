"""
Pydantic models for API request/response
"""
from typing import Dict, Optional, List
from pydantic import BaseModel, Field


class AnonymizeRequest(BaseModel):
    """Request model for /anonymize endpoint"""
    text: str = Field(
        ...,
        min_length=1,
        max_length=100000,
        description="Text to anonymize (up to 100k chars — covers long agent system prompts + history)"
    )
    return_mapping: bool = Field(
        default=True,
        description="Whether to return the PII mapping"
    )
    use_llm: Optional[bool] = Field(
        default=None,
        description="Use LLM for detection (None=use default, False=regex only, True=LLM)"
    )
    seed_values: Optional[Dict[str, List[str]]] = Field(
        default=None,
        description=(
            "Force-anonymize specific tokens regardless of dictionary/regex coverage. "
            "Shape: {\"NAME\": [\"Amar\", \"Farkhadi\"], \"PHONE\": [\"+998901234567\"], "
            "\"EMAIL\": [\"a@b.com\"], \"ADDRESS\": [\"ул. Пушкина 10\"]}. "
            "Used by the backend to inject Contact.firstName / lastName / phone / email so "
            "non-dictionary surnames (e.g. transliterated Persian/Tajik names) still get "
            "redacted before the LLM sees them. Replaced FIRST, before regex/dictionary "
            "passes — longest values win when one is a substring of another."
        )
    )

    class Config:
        json_schema_extra = {
            "example": {
                "text": "Меня зовут Алишер Каримов, ПИНФЛ 12345678901234, телефон +998901234567",
                "return_mapping": True,
                "use_llm": False
            }
        }


class AnonymizeResponse(BaseModel):
    """Response model for /anonymize endpoint"""
    original: str = Field(description="Original text")
    anonymized: str = Field(description="Anonymized text with placeholders")
    mapping: Optional[Dict[str, str]] = Field(
        default=None,
        description="Mapping of placeholders to original values"
    )
    mapping_id: str = Field(description="ID to retrieve mapping later")
    processing_time_ms: int = Field(description="Processing time in milliseconds")
    pii_found: List[str] = Field(
        default_factory=list,
        description="List of PII types found"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "original": "Меня зовут Алишер Каримов, ПИНФЛ 12345678901234",
                "anonymized": "Меня зовут [NAME_001] [SURNAME_001], ПИНФЛ [PINFL_001]",
                "mapping": {
                    "[NAME_001]": "Алишер",
                    "[SURNAME_001]": "Каримов",
                    "[PINFL_001]": "12345678901234"
                },
                "mapping_id": "a1b2c3d4",
                "processing_time_ms": 3200,
                "pii_found": ["NAME", "SURNAME", "PINFL"]
            }
        }


class DeanonymizeRequest(BaseModel):
    """Request model for /deanonymize endpoint"""
    text: str = Field(
        ...,
        min_length=1,
        max_length=100000,
        description="Anonymized text to restore"
    )
    mapping_id: Optional[str] = Field(
        default=None,
        description="ID of stored mapping"
    )
    mapping: Optional[Dict[str, str]] = Field(
        default=None,
        description="Direct mapping to use"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "text": "Меня зовут [NAME_001] [SURNAME_001]",
                "mapping_id": "a1b2c3d4"
            }
        }


class DeanonymizeResponse(BaseModel):
    """Response model for /deanonymize endpoint"""
    anonymized: str = Field(description="Input anonymized text")
    restored: str = Field(description="Text with PII restored")
    processing_time_ms: int = Field(description="Processing time in milliseconds")


class HealthResponse(BaseModel):
    """Response model for /health endpoint"""
    status: str = Field(description="Service status")
    model_loaded: bool = Field(description="Whether model is loaded")
    model_path: str = Field(description="Path to loaded model")
    uptime_seconds: float = Field(description="Service uptime")


class ErrorResponse(BaseModel):
    """Error response model"""
    error: str = Field(description="Error message")
    detail: Optional[str] = Field(default=None, description="Error details")
