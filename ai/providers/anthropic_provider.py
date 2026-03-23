"""
ai/providers/anthropic_provider.py
────────────────────────────────────
Anthropic Claude adapter.
Latest model: claude-sonnet-4.5 (best balance of speed and capability)
Alternative: claude-opus for maximum capability, claude-haiku for speed
"""

from ai.providers.base import AIProvider, AIResponse, ProviderError


class AnthropicProvider(AIProvider):
    def __init__(self, api_key: str, model: str = "claude-sonnet-4.5"):
        try:
            import anthropic as _anthropic
        except ImportError:
            raise ImportError("Install anthropic: pip install anthropic")

        self._model  = model
        self._client = _anthropic.Anthropic(api_key=api_key)

    @property
    def name(self) -> str:
        return "anthropic"

    def complete(self, system_prompt: str, user_prompt: str) -> AIResponse:
        try:
            resp = self._client.messages.create(
                model      = self._model,
                max_tokens = 2048,
                system     = system_prompt,
                messages   = [{"role": "user", "content": user_prompt}],
            )
            content     = resp.content[0].text if resp.content else ""
            tokens_used = (resp.usage.input_tokens + resp.usage.output_tokens
                           if resp.usage else None)
            return AIResponse(
                content     = content,
                model_used  = self._model,
                provider    = self.name,
                tokens_used = tokens_used,
            )
        except Exception as e:
            raise ProviderError(f"Anthropic error: {e}") from e

    def health_check(self) -> bool:
        try:
            # Minimal API call to verify key validity
            self._client.messages.create(
                model      = self._model,
                max_tokens = 5,
                messages   = [{"role": "user", "content": "ping"}],
            )
            return True
        except Exception:
            return False
