"""
ai/providers/gemini_provider.py
────────────────────────────────
Google Gemini adapter for the AI analysis layer.

HOW IT WORKS:
  - Wraps the google.generativeai Python SDK
  - Sends a (system_prompt, user_prompt) pair to the Gemini API
  - Returns an AIResponse dataclass with the text content

COMMON ERRORS AND HOW TO FIX THEM:
  - "Model not found" → Check GEMINI_MODEL in your .env (default: gemini-2.0-flash)
  - "API key invalid"  → Check GEMINI_API_KEY in your .env
  - "Quota exceeded"  → Your free tier limit hit; upgrade or wait 24h
  - "Resource exhausted" → Same as quota — use a paid key or reduce MAX_PAGES_TO_CRAWL

TO CHANGE THE MODEL:
  Add this line to your .env file:
    GEMINI_MODEL=gemini-1.5-pro    # slower, smarter
    GEMINI_MODEL=gemini-2.0-flash  # fast and free-tier friendly (default)
"""

import time
import json
import google.generativeai as genai

from ai.providers.base import AIProvider, AIResponse, ProviderError


class GeminiProvider(AIProvider):
    """
    Google Gemini AI provider.

    Initialized by provider_factory.py — do not instantiate directly.
    Use: from ai.provider_factory import get_provider
    """

    def __init__(self, api_key: str, model: str = "gemini-2.0-flash"):
        """
        Args:
            api_key: Your Google Gemini API key (from .env: GEMINI_API_KEY)
            model:   Gemini model name (from .env: GEMINI_MODEL)
                     Default: "gemini-2.0-flash" — fast, reliable, works on free tier.
                     Options: "gemini-1.5-pro", "gemini-2.0-flash", "gemini-1.5-flash"
        """
        self._api_key = api_key
        self._model   = model

    @property
    def name(self) -> str:
        """Provider identifier used in logs and UI."""
        return "gemini"

    def _get_model(self, system_instruction: str):
        """
        Configure the Gemini SDK with the API key and return a model instance.
        Called fresh each time to avoid stale connections.
        """
        genai.configure(api_key=self._api_key)
        return genai.GenerativeModel(
            model_name         = self._model,
            system_instruction = system_instruction,
        )

    def complete(self, system_prompt: str, user_prompt: str) -> AIResponse:
        """
        Send a prompt to Gemini and return the text response.

        Retries up to 3 times:
          - On quota/rate-limit errors: waits 60 seconds then retries
          - On other transient errors: exponential backoff (2s, 4s)
          - If model name is wrong: shows a clear error message immediately

        Args:
            system_prompt: Sets the AI's role/behaviour (e.g. "You are a pentester...")
            user_prompt:   The actual question/task to send

        Returns:
            AIResponse with .content (the text), .model_used, .provider

        Raises:
            ProviderError: After all retries exhausted
        """
        model = self._get_model(system_prompt)

        for attempt in range(3):
            try:
                resp     = model.generate_content(user_prompt)
                raw_text = resp.text.strip()

                # Strip markdown code fences if the model added them
                # (some Gemini versions wrap JSON in ```json ... ```)
                if raw_text.startswith("```"):
                    lines    = raw_text.split("\n")
                    raw_text = "\n".join(lines[1:-1]).strip()

                return AIResponse(
                    content    = raw_text,
                    model_used = self._model,
                    provider   = self.name,
                )

            except json.JSONDecodeError:
                # JSON parsing is handled upstream — re-raise immediately
                raise

            except Exception as e:
                err = str(e).lower()

                # ── Quota / rate limit errors ─────────────────────────────
                # These mean the API is fine but you've hit usage limits.
                # Wait 60 seconds and retry automatically.
                if "quota" in err or "resource_exhausted" in err or "429" in err:
                    wait = 60
                    print(f"  [Gemini] Rate limit hit — waiting {wait}s before retry "
                          f"(attempt {attempt + 1}/3)")
                    time.sleep(wait)

                # ── Model not found ────────────────────────────────────────
                # This means the model name in .env or the default is wrong.
                # Common mistake: "gemini-3.0" doesn't exist.
                elif "not found" in err or "invalid model" in err or "404" in err:
                    raise ProviderError(
                        f"Gemini model '{self._model}' not found. "
                        f"Check GEMINI_MODEL in your .env file. "
                        f"Valid options: gemini-2.0-flash, gemini-1.5-pro, gemini-1.5-flash. "
                        f"Original error: {e}"
                    ) from e

                # ── API key invalid ────────────────────────────────────────
                elif "api key" in err or "401" in err or "invalid_api_key" in err:
                    raise ProviderError(
                        f"Gemini API key is invalid or missing. "
                        f"Check GEMINI_API_KEY in your .env file. "
                        f"Get a key at: https://aistudio.google.com/app/apikey"
                    ) from e

                # ── Other transient errors — exponential backoff ───────────
                elif attempt < 2:
                    wait = 2 ** attempt   # 1s, 2s
                    print(f"  [Gemini] Transient error (attempt {attempt + 1}/3): {e} — retrying in {wait}s")
                    time.sleep(wait)

                else:
                    raise ProviderError(f"Gemini failed after 3 attempts: {e}") from e

        raise ProviderError("Gemini: all retries exhausted")

    def health_check(self) -> bool:
        """
        Quick connectivity test — does NOT send a full prompt.
        Returns True if the API key is valid and reachable.

        Used by the dashboard to show API status in settings.
        """
        try:
            genai.configure(api_key=self._api_key)
            # List available models — lightweight call that validates the key
            list(genai.list_models())
            return True
        except Exception:
            return False
