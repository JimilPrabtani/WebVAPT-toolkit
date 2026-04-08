"""
ai/provider_factory.py
────────────────────────
Reads AI_PROVIDER and AI_FALLBACK from .env and builds a provider chain.

HOW PROVIDER SELECTION WORKS:
  1. Reads AI_PROVIDER (e.g. "gemini") from .env
  2. Reads AI_FALLBACK (e.g. "openai,anthropic") from .env
  3. Builds a list of providers in order: [primary, fallback1, fallback2, ...]
  4. Returns a _FallbackChainProvider that tries each one in sequence
  5. If primary fails (quota, bad key, model error) → automatically tries next provider

EXAMPLE .env CONFIGURATION:
  AI_PROVIDER=gemini          # Primary provider
  GEMINI_API_KEY=your_key
  AI_FALLBACK=openai          # Fallback if Gemini fails
  OPENAI_API_KEY=your_key

DEFAULT MODELS (override via .env):
  - Gemini:    gemini-2.0-flash  (fast, works on free tier)
  - OpenAI:    gpt-4o
  - Anthropic: claude-sonnet-4-6
  - Ollama:    user-configured local model

HOW TO ADD A NEW PROVIDER:
  1. Create ai/providers/my_provider.py implementing the AIProvider interface (see base.py)
  2. Add a new if block in _build_provider() below
  3. Add the env var docs to .env.example

USAGE (anywhere in the codebase):
  from ai.provider_factory import get_provider
  provider = get_provider()
  response = provider.complete(system_prompt, user_prompt)
"""

import json
import os
from ai.providers.base import AIProvider, AIResponse, AllProvidersFailedError, ProviderError


def _build_provider(name: str) -> AIProvider | None:
    """Construct a single named provider from environment variables. Returns None if unconfigured."""
    name = (name or "").strip().lower()

    if name == "gemini":
        key = os.getenv("GEMINI_API_KEY", "")
        if not key:
            return None
        from ai.providers.gemini_provider import GeminiProvider
        return GeminiProvider(api_key=key, model=os.getenv("GEMINI_MODEL", "gemini-2.0-flash"))

    if name == "openai":
        key = os.getenv("OPENAI_API_KEY", "")
        if not key:
            return None
        from ai.providers.openai_provider import OpenAIProvider
        return OpenAIProvider(api_key=key, model=os.getenv("OPENAI_MODEL", "gpt-4o"))

    if name == "anthropic":
        key = os.getenv("ANTHROPIC_API_KEY", "")
        if not key:
            return None
        from ai.providers.anthropic_provider import AnthropicProvider
        return AnthropicProvider(api_key=key, model=os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6"))

    if name == "ollama":
        from ai.providers.ollama_provider import OllamaProvider
        return OllamaProvider(
            base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
            model    = os.getenv("OLLAMA_MODEL", "llama2"),
        )

    if name == "custom":
        key      = os.getenv("CUSTOM_AI_API_KEY", "")
        base_url = os.getenv("CUSTOM_AI_BASE_URL", "")
        model    = os.getenv("CUSTOM_AI_MODEL", "")
        if not (key and base_url and model):
            return None
        from ai.providers.openai_provider import OpenAIProvider
        return OpenAIProvider(api_key=key, model=model, base_url=base_url)

    return None


def get_provider() -> AIProvider:
    """
    Build a provider chain from AI_PROVIDER + AI_FALLBACK env vars.
    Returns a FallbackChainProvider that tries each provider in order.

    Example .env:
        AI_PROVIDER=gemini
        AI_FALLBACK=openai,anthropic,ollama

    If all fail, raises AllProvidersFailedError when complete() is called.
    """
    primary_name  = os.getenv("AI_PROVIDER", "gemini")
    fallback_names = [
        n.strip() for n in os.getenv("AI_FALLBACK", "").split(",") if n.strip()
    ]

    ordered_names = [primary_name] + fallback_names
    providers     = []
    for name in ordered_names:
        p = _build_provider(name)
        if p is not None:
            providers.append(p)
            print(f"[AI] Provider registered: {p.name}")

    if not providers:
        raise RuntimeError(
            "No AI provider configured. Set AI_PROVIDER and the matching API key in .env. "
            "See .env.example for all options."
        )

    return _FallbackChainProvider(providers)


class _FallbackChainProvider(AIProvider):
    """
    Try providers left-to-right. Falls through to the next on ProviderError.
    Not part of the public API — use get_provider() to obtain an instance.
    """

    def __init__(self, providers: list[AIProvider]):
        self._providers = providers

    @property
    def name(self) -> str:
        return "+".join(p.name for p in self._providers)

    def complete(self, system_prompt: str, user_prompt: str) -> AIResponse:
        last_error = None
        for provider in self._providers:
            try:
                result = provider.complete(system_prompt, user_prompt)
                return result
            except ProviderError as e:
                print(f"  [AI] {provider.name} failed: {e} — trying next provider")
                last_error = e
        raise AllProvidersFailedError(
            f"All AI providers exhausted. Last error: {last_error}"
        )

    def health_check(self) -> bool:
        return any(p.health_check() for p in self._providers)
