"""
ai/providers/base.py
────────────────────
Single OpenAI-compatible provider (OpenAI or OpenRouter via CUSTOM_AI_BASE_URL).
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class AIResponse:
    content: str
    model_used: str = ""
    provider: str = ""


class AIProvider(ABC):
    """
    Interface that the OpenAI-compatible provider adapter implements.
    The analyzer layer (ai/AI_analyzer.py) only calls complete(),
    making the underlying model swappable without touching any scan logic.
    """

    @abstractmethod
    def complete(self, system_prompt: str, user_prompt: str) -> AIResponse:
        """
        Send a prompt pair and return a structured response.
        Must raise ProviderError on unrecoverable failure.
        """
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier string, e.g. 'openai', 'openrouter'."""
        ...


class ProviderError(Exception):
    """Raised by provider adapters on unrecoverable API failure."""
    pass
