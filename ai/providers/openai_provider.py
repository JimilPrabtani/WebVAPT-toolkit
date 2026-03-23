"""
ai/providers/openai_provider.py
────────────────────────────────
OpenAI adapter (GPT-5.3, GPT-4-turbo, etc.).
Latest model: gpt-5.3 (multi-modal, fast, latest reasoning capabilities)
Also works as a base for any OpenAI-compatible endpoint (Groq, Together AI, Mistral).
"""

from ai.providers.base import AIProvider, AIResponse, ProviderError


class OpenAIProvider(AIProvider):
    def __init__(
        self,
        api_key  : str,
        model    : str = "gpt-5.3",
        base_url : str = None,   # Override for OpenAI-compatible endpoints
    ):
        try:
            import openai as _openai
        except ImportError:
            raise ImportError("Install openai: pip install openai")

        self._model = model
        self._client = _openai.OpenAI(
            api_key  = api_key,
            base_url = base_url,   # None = use official OpenAI endpoint
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
