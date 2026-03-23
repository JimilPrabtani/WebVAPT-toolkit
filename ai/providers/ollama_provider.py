"""
ai/providers/ollama_provider.py
────────────────────────────────
Ollama local model adapter — zero API key required.
Runs any model you have pulled locally: llama3.2, mistral, codellama, etc.

Usage: OLLAMA_BASE_URL=http://localhost:11434  OLLAMA_MODEL=llama3.2
"""

import json
import requests

from ai.providers.base import AIProvider, AIResponse, ProviderError

_DEFAULT_BASE = "http://localhost:11434"


class OllamaProvider(AIProvider):
    def __init__(self, base_url: str = _DEFAULT_BASE, model: str = "llama3.2"):
        self._base_url = base_url.rstrip("/")
        self._model    = model

    @property
    def name(self) -> str:
        return "ollama"

    def complete(self, system_prompt: str, user_prompt: str) -> AIResponse:
        """
        Ollama /api/generate endpoint.
        We embed the system prompt in the prompt body because not all models
        support a separate system field via the chat endpoint.
        Appending JSON instructions to the system prompt ensures compliance
        without relying on json_mode (not all Ollama models support it).
        """
        combined_system = (
            system_prompt
            + "\n\nIMPORTANT: Respond ONLY with raw JSON. No markdown, no code fences, no extra text."
        )
        payload = {
            "model" : self._model,
            "system": combined_system,
            "prompt": user_prompt,
            "stream": False,
        }
        try:
            resp = requests.post(
                f"{self._base_url}/api/generate",
                json    = payload,
                timeout = 120,
            )
            resp.raise_for_status()
            return AIResponse(
                content    = resp.json().get("response", ""),
                model_used = self._model,
                provider   = self.name,
            )
        except requests.RequestException as e:
            raise ProviderError(f"Ollama error: {e}") from e

    def health_check(self) -> bool:
        try:
            resp = requests.get(f"{self._base_url}/api/tags", timeout=5)
            return resp.status_code == 200
        except Exception:
            return False
