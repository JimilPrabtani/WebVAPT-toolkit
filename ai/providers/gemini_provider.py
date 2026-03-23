"""
ai/providers/gemini_provider.py
────────────────────────────────
Google Gemini adapter. Wraps google.generativeai.
Latest model: gemini-3.0 (fast, free tier friendly, latest capabilities)
"""

import time
import json
import google.generativeai as genai

from ai.providers.base import AIProvider, AIResponse, ProviderError


class GeminiProvider(AIProvider):
    def __init__(self, api_key: str, model: str = "gemini-3.0"):
        self._api_key = api_key
        self._model   = model

    @property
    def name(self) -> str:
        return "gemini"

    def _get_model(self, system_instruction: str):
        genai.configure(api_key=self._api_key)
        return genai.GenerativeModel(
            model_name        = self._model,
            system_instruction= system_instruction,
        )

    def complete(self, system_prompt: str, user_prompt: str) -> AIResponse:
        model = self._get_model(system_prompt)
        for attempt in range(3):
            try:
                resp     = model.generate_content(user_prompt)
                raw_text = resp.text.strip()
                if raw_text.startswith("```"):
                    lines    = raw_text.split("\n")
                    raw_text = "\n".join(lines[1:-1]).strip()
                return AIResponse(
                    content    = raw_text,
                    model_used = self._model,
                    provider   = self.name,
                )
            except json.JSONDecodeError:
                raise
            except Exception as e:
                err = str(e).lower()
                if "quota" in err or "resource_exhausted" in err or "429" in err:
                    wait = 60
                    print(f"  [Gemini] quota hit — waiting {wait}s")
                    time.sleep(wait)
                elif attempt < 2:
                    time.sleep(2 ** attempt)
                else:
                    raise ProviderError(f"Gemini failed after 3 attempts: {e}") from e
        raise ProviderError("Gemini: all retries exhausted")

    def health_check(self) -> bool:
        try:
            genai.configure(api_key=self._api_key)
            # Lightweight check: just list available models
            list(genai.list_models())
            return True
        except Exception:
            return False
