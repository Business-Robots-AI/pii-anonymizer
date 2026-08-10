"""
LLM Service - Handles Qwen 2.5 3B model loading and inference

In the BRAI_V2 deployment this service runs in regex-only mode, so
`llama_cpp` is imported lazily inside `load_model()` — the package
does not need to be installed when `PII_USE_LLM=False`.
"""
import logging
import time
from typing import Any, Optional
from pathlib import Path

from .config import settings

logger = logging.getLogger(__name__)


class LLMService:
    """Service for managing LLM model and inference"""

    _instance: Optional["LLMService"] = None
    _model: Optional[Any] = None
    _model_loaded: bool = False
    _load_time: float = 0

    def __new__(cls) -> "LLMService":
        """Singleton pattern - only one model instance"""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def load_model(self) -> bool:
        """
        Load the Qwen model into memory.

        Returns:
            True if model loaded successfully, False otherwise
        """
        if self._model_loaded:
            logger.info("Model already loaded")
            return True

        try:
            from llama_cpp import Llama
        except ImportError:
            logger.error(
                "llama_cpp not installed — LLM mode unavailable. "
                "Set PII_USE_LLM=False or install llama-cpp-python."
            )
            return False

        model_path = Path(settings.model_path)
        if not model_path.exists():
            logger.error(f"Model file not found: {model_path}")
            return False

        logger.info(f"Loading model from {model_path}...")
        start_time = time.time()

        try:
            self._model = Llama(
                model_path=str(model_path),
                n_ctx=settings.n_ctx,
                n_threads=settings.n_threads,
                n_batch=settings.n_batch,
                verbose=False,  # Reduce logging noise
            )
            self._load_time = time.time() - start_time
            self._model_loaded = True
            logger.info(f"Model loaded successfully in {self._load_time:.2f}s")
            return True

        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return False

    def generate(
        self,
        prompt: str,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        stop: Optional[list] = None,
    ) -> tuple[str, dict]:
        """
        Generate text using the loaded model.

        Args:
            prompt: Input prompt string
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            stop: Stop sequences

        Returns:
            Tuple of (generated_text, metadata_dict)
        """
        if not self._model_loaded or self._model is None:
            raise RuntimeError("Model not loaded. Call load_model() first.")

        max_tokens = max_tokens or settings.max_tokens
        temperature = temperature if temperature is not None else settings.temperature
        stop = stop or ["<|im_end|>", "<|im_start|>"]

        start_time = time.time()

        try:
            output = self._model(
                prompt,
                max_tokens=max_tokens,
                temperature=temperature,
                top_p=settings.top_p,
                stop=stop,
                echo=False,
            )

            generation_time = time.time() - start_time

            # Extract generated text
            generated_text = output["choices"][0]["text"].strip()

            # Compile metadata
            metadata = {
                "generation_time_ms": int(generation_time * 1000),
                "prompt_tokens": output.get("usage", {}).get("prompt_tokens", 0),
                "completion_tokens": output.get("usage", {}).get("completion_tokens", 0),
                "total_tokens": output.get("usage", {}).get("total_tokens", 0),
            }

            return generated_text, metadata

        except Exception as e:
            logger.error(f"Generation failed: {e}")
            raise

    @property
    def is_loaded(self) -> bool:
        """Check if model is loaded"""
        return self._model_loaded

    @property
    def model_path(self) -> str:
        """Get model path"""
        return settings.model_path

    @property
    def load_time(self) -> float:
        """Get model load time in seconds"""
        return self._load_time

    def get_stats(self) -> dict:
        """Get model statistics"""
        return {
            "model_loaded": self._model_loaded,
            "model_path": settings.model_path,
            "load_time_seconds": self._load_time,
            "n_threads": settings.n_threads,
            "n_ctx": settings.n_ctx,
        }


# Global instance
llm_service = LLMService()
