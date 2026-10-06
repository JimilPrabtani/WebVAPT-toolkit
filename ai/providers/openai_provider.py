"""
ai/providers/openai_provider.py
────────────────────────────────
OpenAI-compatible adapter (OpenAI or OpenRouter).
Default model: gpt-4o — override with AI_MODEL (or OPENAI_MODEL) in .env.
For OpenRouter: OPENAI_API_KEY=<openrouter key>,
CUSTOM_AI_BASE_URL=https://openrouter.ai/api/v1, AI_MODEL=openai/gpt-4o-mini.

MODEL FALLBACK CHAIN (free-tier resilience):
  AI_MODEL accepts a comma-separated priority list, e.g.
    AI_MODEL=nvidia/nemotron-3-super-120b-a12b:free,cohere/north-mini-code:free
  complete() tries each model in order and uses the first that answers.
  Failover triggers on missing/rate-limited/dead models (404, 429, 5xx,
  timeouts) — but NOT on auth errors (401/403: the key itself is wrong,
  retrying another model can't help). Free-model pools are flaky, so a
  chain is the difference between "AI analyzed: false" and real enrichment.
"""

from ai.providers.base import AIProvider, AIResponse, ProviderError

# Auth failures — retrying another model is pointless, fail fast.
_NON_RETRYABLE_MARKERS = ("401", "403", "invalid_api_key", "unauthorized",
                          "invalid api key", "authentication_error")


def _is_retryable(err: Exception) -> bool:
    """True when trying the next model in the chain could help."""
    msg = str(err).lower()
    return not any(m in msg for m in _NON_RETRYABLE_MARKERS)


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

        # Priority-ordered fallback chain (first = preferred).
        self._models = [m.strip() for m in model.split(",") if m.strip()]
        self._model = self._models[0]
        self._base_url = base_url
        self._client = _openai.OpenAI(
            api_key  = api_key,
            base_url = base_url,
        )

    @property
    def name(self) -> str:
        if self._base_url and "openrouter" in self._base_url:
            return "openrouter"
        return "openai"

    def complete(self, system_prompt: str, user_prompt: str) -> AIResponse:
        errors = []
        for model in self._models:
            try:
                resp = self._client.chat.completions.create(
                    model           = model,
                    response_format = {"type": "json_object"},
                    messages        = [
                        {"role": "system", "content": system_prompt},
                        {"role": "user",   "content": user_prompt},
                    ],
                )
                content = resp.choices[0].message.content or ""
                return AIResponse(
                    content     = content,
                    model_used  = model,
                    provider    = self.name,
                )
            except Exception as e:
                errors.append(f"{model}: {e}")
                if not _is_retryable(e):
                    break  # auth error — another model won't help
                continue  # try the next model in the chain
        raise ProviderError(
            f"OpenAI error (all {len(self._models)} model(s) failed): "
            + " | ".join(errors)
        )
