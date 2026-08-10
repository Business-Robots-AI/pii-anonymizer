"""
Configuration for PII Anonymization Service
"""
import os
from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings with environment variable support"""

    # Model settings
    model_path: str = "/opt/models/qwen2.5-3b-instruct-q4_k_m.gguf"
    n_threads: int = 14  # Use 14 of 16 CPU cores
    n_ctx: int = 2048    # Context window size
    n_batch: int = 512   # Batch size for prompt processing

    # Inference settings
    max_tokens: int = 512
    temperature: float = 0.0  # Deterministic output
    top_p: float = 1.0

    # Anonymization mode
    use_llm: bool = False  # False = regex only (fast), True = LLM + regex (slow but accurate)

    # API settings
    host: str = "0.0.0.0"
    port: int = 8100
    workers: int = 1  # Single worker for LLM (model not thread-safe)

    # Timeouts
    request_timeout: int = 30  # seconds
    inference_timeout: int = 15  # seconds

    # Cache settings
    mapping_ttl: int = 3600  # 1 hour TTL for mappings
    max_cache_size: int = 10000  # Max cached mappings

    # Logging
    log_level: str = "INFO"
    log_format: str = "json"

    # Rate limiting
    rate_limit_requests: int = 30  # requests per minute
    rate_limit_window: int = 60  # seconds

    class Config:
        env_prefix = "PII_"
        env_file = ".env"


settings = Settings()
