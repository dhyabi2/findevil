"""
LLM client abstraction supporting multiple providers via OpenAI-compatible API.

Default: OpenRouter with Google Gemma 4.
"""

import os
import json
import time
import logging
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger("findevil.llm")


@dataclass
class LLMResponse:
    """Structured response from LLM."""
    content: str
    model: str
    usage: dict = field(default_factory=dict)
    latency_ms: float = 0.0
    raw: dict = field(default_factory=dict)


@dataclass
class LLMConfig:
    """LLM provider configuration."""
    provider: str = "openrouter"
    api_key: str = ""
    base_url: str = "https://openrouter.ai/api/v1"
    model: str = "google/gemma-4-31b-it"
    fallback_model: str = "google/gemma-3-27b-it"
    max_tokens: int = 8192
    temperature: float = 0.2
    top_p: float = 0.9
    site_url: str = "https://github.com/dhyabi2/findevil"
    site_name: str = "FIND EVIL IABF Agent"

    @classmethod
    def from_yaml(cls, config: dict) -> "LLMConfig":
        """Load from parsed YAML config."""
        llm = config.get("llm", {})
        provider = llm.get("provider", "openrouter")
        provider_cfg = llm.get(provider, {})

        api_key = provider_cfg.get("api_key", "")
        if api_key.startswith("${") and api_key.endswith("}"):
            env_var = api_key[2:-1]
            api_key = os.environ.get(env_var, "")

        return cls(
            provider=provider,
            api_key=api_key,
            base_url=provider_cfg.get("base_url", cls.base_url),
            model=provider_cfg.get("default_model", cls.model),
            fallback_model=provider_cfg.get("fallback_model", cls.fallback_model),
            max_tokens=provider_cfg.get("max_tokens", cls.max_tokens),
            temperature=provider_cfg.get("temperature", cls.temperature),
            top_p=provider_cfg.get("top_p", cls.top_p),
            site_url=provider_cfg.get("site_url", cls.site_url),
            site_name=provider_cfg.get("site_name", cls.site_name),
        )


class LLMClient:
    """Unified LLM client for the IABF agent."""

    def __init__(self, config: LLMConfig):
        self.config = config
        self._client = httpx.Client(timeout=120.0)
        self._total_tokens = 0
        self._total_calls = 0

    @property
    def stats(self) -> dict:
        return {
            "total_calls": self._total_calls,
            "total_tokens": self._total_tokens,
        }

    def _headers(self) -> dict:
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }
        if self.config.provider == "openrouter":
            headers["HTTP-Referer"] = self.config.site_url
            headers["X-Title"] = self.config.site_name
        return headers

    def chat(
        self,
        messages: list[dict],
        system: str | None = None,
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        response_format: dict | None = None,
    ) -> LLMResponse:
        """Send a chat completion request."""
        model = model or self.config.model
        payload = {
            "model": model,
            "messages": [],
            "max_tokens": max_tokens or self.config.max_tokens,
            "temperature": temperature if temperature is not None else self.config.temperature,
            "top_p": self.config.top_p,
        }

        if system:
            payload["messages"].append({"role": "system", "content": system})
        payload["messages"].extend(messages)

        if response_format:
            payload["response_format"] = response_format

        url = f"{self.config.base_url}/chat/completions"

        start = time.monotonic()

        def _post_with_retry(pl: dict, max_attempts: int = 5) -> httpx.Response:
            """POST with exponential backoff on transient errors (DNS, timeout, 5xx)."""
            last_exc: Exception | None = None
            for attempt in range(max_attempts):
                try:
                    r = self._client.post(url, headers=self._headers(), json=pl)
                    # Retry on 5xx and 429
                    if r.status_code >= 500 or r.status_code == 429:
                        last_exc = httpx.HTTPStatusError(
                            f"HTTP {r.status_code}", request=r.request, response=r)
                    else:
                        r.raise_for_status()
                        return r
                except (httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError,
                        httpx.ConnectTimeout, httpx.NetworkError) as e:
                    last_exc = e
                delay = min(2 ** attempt, 30)
                logger.warning(f"LLM request failed (attempt {attempt+1}/{max_attempts}): "
                               f"{type(last_exc).__name__}. Retrying in {delay}s...")
                time.sleep(delay)
            raise last_exc if last_exc else RuntimeError("LLM request failed with unknown error")

        try:
            resp = _post_with_retry(payload)
        except httpx.HTTPStatusError as e:
            # Try fallback model on persistent 4xx failure
            if model != self.config.fallback_model:
                logger.warning(f"Model {model} failed ({e}), trying fallback {self.config.fallback_model}")
                payload["model"] = self.config.fallback_model
                resp = _post_with_retry(payload)
            else:
                raise
        latency = (time.monotonic() - start) * 1000

        data = resp.json()
        choice = data["choices"][0]
        usage = data.get("usage", {})

        self._total_calls += 1
        self._total_tokens += usage.get("total_tokens", 0)

        return LLMResponse(
            content=choice["message"]["content"],
            model=data.get("model", model),
            usage=usage,
            latency_ms=latency,
            raw=data,
        )

    def chat_json(
        self,
        messages: list[dict],
        system: str | None = None,
        model: str | None = None,
    ) -> dict:
        """Send a chat request expecting JSON output. Parse and return dict."""
        if system:
            system += "\n\nYou MUST respond with valid JSON only. No markdown, no explanation."
        else:
            system = "You MUST respond with valid JSON only. No markdown, no explanation."

        resp = self.chat(
            messages=messages,
            system=system,
            model=model,
            response_format={"type": "json_object"},
        )

        # Try to parse JSON from response
        content = resp.content.strip()
        # Strip markdown code fences if present
        if content.startswith("```"):
            lines = content.split("\n")
            content = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

        return json.loads(content)

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class FakeLLMClient:
    """Scripted LLM client for tests and --dry-run. No network calls.

    Usage:
        fake = FakeLLMClient([
            "Narrative: user downloaded X...",
            {"hypotheses": [{"description": "...", "tool_commands": ["echo 1"], "confidence": 0.7}]},
            {"verdict": "confirmed", "confidence_after": 0.95, "evidence_for": ["..."]},
            {"root_cause_reached": True, "root_cause": "...", "confidence_in_root_cause": 0.9,
             "investigation_complete": True},
        ])

    Each script entry is consumed per chat() / chat_json() call. Dicts are returned
    from chat_json and JSON-serialized for chat(). Strings are returned verbatim.
    When the script is exhausted, a default "inconclusive" response is returned so
    the loop terminates gracefully.
    """

    def __init__(self, script: list | None = None):
        self.script = list(script) if script else []
        self._calls: list[dict] = []
        self._total_calls = 0
        self._total_tokens = 0

    @property
    def stats(self) -> dict:
        return {
            "total_calls": self._total_calls,
            "total_tokens": self._total_tokens,
            "mode": "fake",
        }

    @property
    def calls(self) -> list[dict]:
        """Inspect captured call history (for assertions in tests)."""
        return self._calls

    def _next(self, purpose: str):
        self._total_calls += 1
        if self.script:
            return self.script.pop(0)
        return None

    def chat(self, messages, system=None, model=None, temperature=None,
             max_tokens=None, response_format=None) -> LLMResponse:
        self._calls.append({"kind": "chat", "messages": messages, "system": system})
        nxt = self._next("chat")
        if nxt is None:
            content = "Fake response: no scripted output remaining."
        elif isinstance(nxt, dict):
            content = json.dumps(nxt)
        else:
            content = str(nxt)
        return LLMResponse(
            content=content,
            model="fake-llm",
            usage={"total_tokens": 0},
            latency_ms=0.0,
            raw={},
        )

    def chat_json(self, messages, system=None, model=None) -> dict:
        self._calls.append({"kind": "chat_json", "messages": messages, "system": system})
        nxt = self._next("chat_json")
        if nxt is None:
            return {"verdict": "inconclusive", "investigation_complete": True,
                    "root_cause_reached": False}
        if isinstance(nxt, dict):
            return nxt
        # string -> try parse, else wrap
        try:
            return json.loads(str(nxt))
        except (json.JSONDecodeError, TypeError):
            return {"raw": str(nxt)}

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass
