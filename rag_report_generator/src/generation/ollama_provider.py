"""Ollama LLM provider using local REST API."""

import json
import urllib.error
import urllib.request
from typing import Any
from .llm_provider import LLMProvider
from ..models.report_metadata import ReportConfig


class OllamaProvider(LLMProvider):
    """Local Ollama LLM provider interfacing via HTTP API."""

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        default_model: str = "llama3.2",
        timeout: float = 60.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.default_model = default_model
        self.timeout = timeout

    def is_available(self) -> bool:
        """Check if Ollama server is running and accessible."""
        url = f"{self.base_url}/api/tags"
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=2.0) as response:
                return response.status == 200
        except Exception:
            return False

    def generate(self, prompt: str, config: ReportConfig | None = None) -> str:
        """Invoke Ollama's generate API in JSON mode."""
        cfg = config or ReportConfig()
        model_name = cfg.llm_model or self.default_model
        timeout = cfg.timeout_seconds or self.timeout
        base_url = (cfg.ollama_base_url or self.base_url).rstrip("/")

        url = f"{base_url}/api/generate"
        payload = {
            "model": model_name,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": cfg.temperature,
                "num_predict": cfg.max_output_tokens,
            },
        }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                if response.status != 200:
                    raise RuntimeError(f"Ollama returned HTTP status {response.status}")
                body = json.loads(response.read().decode("utf-8"))
                return str(body.get("response", ""))
        except urllib.error.URLError as e:
            raise ConnectionError(
                f"Failed to connect to Ollama at {url}: {e.reason}. "
                "Ensure Ollama is running and accessible."
            ) from e
        except TimeoutError as e:
            raise TimeoutError(f"Ollama generation timed out after {timeout} seconds.") from e
        except Exception as e:
            raise RuntimeError(f"Ollama generation failed: {e}") from e
