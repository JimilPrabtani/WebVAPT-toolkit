"""
ai/providers/base.py
────────────────────
Abstract base class that every AI provider adapter must implement.
Adding a new provider = subclass AIProvider + register in provider_factory.py.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AIResponse:
    content: str
    model_used: str
    provider: str
    tokens_used: Optional[int] = None


class AIProvider(ABC):
    """
    Interface that all AI provider adapters implement.
    The analyzer layer (ai/analyzer.py) only calls complete() and health_check(),
    making the underlying model fully swappable without touching any scan logic.
    """

    @abstractmethod
    def complete(self, system_prompt: str, user_prompt: str) -> AIResponse:
        """
        Send a prompt pair and return a structured response.
        Must raise ProviderError on unrecoverable failure.
        """
        ...

    @abstractmethod
    def health_check(self) -> bool:
        """Return True if the provider is reachable and the key is valid."""
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier string, e.g. 'gemini', 'openai', 'ollama'."""
        ...


class ProviderError(Exception):
    """Raised by provider adapters on unrecoverable API failure."""
    pass


class AllProvidersFailedError(ProviderError):
    """Raised by the fallback chain when every provider in the chain has failed."""
    pass
