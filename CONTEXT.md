# Domain vocabulary — WebVAPT-toolkit

- **Scan**: a security assessment job (crawl + check pipeline).
- **AI adapter**: the single OpenAI module (`openai_provider.py`) that satisfies the `AIProvider` interface. The multi-provider factory (`provider_factory.py`) and its adapters (`gemini_provider.py`, `anthropic_provider.py`, `ollama_provider.py`) have been deleted.
- **Seam**: `ScanRequest` (UI and backend share the same interface: `enable_ai`, `max_pages`). The `.env` variables (`ENABLE_AI_ANALYSIS`, `MAX_PAGES_TO_CRAWL`) are defaults, not overrides.
- **Module depth**: `run_scan()` is the deep module; `max_pages` and `run_ai` are parameters of its interface.
