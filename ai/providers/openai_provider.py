"""
ai/providers/openai_provider.py
────────────────────────────────
OpenAI adapter (GPT-4o, GPT-4-turbo, etc.).
Default model: gpt-4o — override per run with AI_MODEL (or OPENAI_MODEL) in .env.
Also works as a base for any OpenAI-compatible endpoint (Groq, Together AI, Mistral).
"""

from ai.providers.base import AIProvider, AIResponse, ProviderError


class OpenAIProvider(AIProvider):
    def __init__(
        self,
        api_key  : str = None,
        model    : str = None,
        base_url : str = None,
    ):
        try:
            import openai as _openai
            import os
        except ImportError:
            raise ImportError("Install openai: pip install openai")

        # Dynamic defaults from .env for any endpoint / key / model
        if api_key is None:
            api_key = os.getenv("OPENAI_API_KEY", "")
        if model is None:
            model = (os.getenv("AI_MODEL", "") or os.getenv("OPENAI_MODEL", "") or "gpt-4o").strip()
        if base_url is None:
            base_url = os.getenv("CUSTOM_AI_BASE_URL", "").strip() or None
        if not model:
            model = "gpt-4o"

        self._model = model
        self._client = _openai.OpenAI(
            api_key  = api_key,
            base_url = base_url,
        )

    @property
    def name(self) -> str:
        return "openai"

    def complete(self, system_prompt: str, user_prompt: str) -> AIResponse:
        try:
            resp = self._client.chat.completions.create(
                model           = self._model,
                response_format = {"type": "json_object"},
                messages        = [
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": user_prompt},
                ],
            )
            content = resp.choices[0].message.content or ""
            return AIResponse(
                content     = content,
                model_used  = self._model,
                provider    = self.name,
                tokens_used = resp.usage.total_tokens if resp.usage else None,
            )
        except Exception as e:
            raise ProviderError(f"OpenAI error: {e}") from e

    def health_check(self) -> bool:
        try:
            self._client.models.list()
            return True
        except Exception:
            return False
