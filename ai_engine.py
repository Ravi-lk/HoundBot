"""
ai_engine.py — Ollama Cloud API Integration

Sends structured BloodHound findings to the Ollama qwen3.5:397b model
via the native Ollama API (/api/chat) for AI-powered exploitation guidance.
"""

import os
import sys
import json
import requests
from rich.console import Console
from rich.panel import Panel

from prompts import SYSTEM_PROMPT, build_analysis_prompt

console = Console(force_terminal=True)

# Force UTF-8 on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Default configuration
DEFAULT_MODEL = "qwen3.5:397b"
DEFAULT_BASE_URL = "https://ollama.com"
REQUEST_TIMEOUT = 300  # 5 minutes for large analysis


class OllamaEngine:
    """Handles communication with the Ollama Cloud API."""

    def __init__(self, api_key: str = None, model: str = None, base_url: str = None):
        self.api_key = api_key or os.getenv("OLLAMA_API_KEY", "")
        self.model = model or os.getenv("OLLAMA_MODEL", DEFAULT_MODEL)
        self.base_url = (base_url or os.getenv("OLLAMA_BASE_URL", DEFAULT_BASE_URL)).rstrip("/")
        self.chat_endpoint = f"{self.base_url}/api/chat"

        if not self.api_key:
            console.print(
                "[bold red]![/] OLLAMA_API_KEY not set. "
                "Set it in .env file or pass --api-key flag.",
                style="red",
            )
            console.print(
                "  Get your API key from: https://ollama.com/settings/keys",
            )

    def is_configured(self) -> bool:
        """Check if the engine is properly configured."""
        return bool(self.api_key)

    def analyze(
        self,
        findings_summary: str,
        domain_info: str,
        owned_user: str,
        dc_ip: str,
        stream: bool = True,
    ) -> str:
        """
        Send findings to the AI model and return exploitation guidance.

        Args:
            findings_summary: Formatted findings text from analyzer
            domain_info: Domain name
            owned_user: Currently owned username
            dc_ip: Domain Controller IP
            stream: Whether to stream the response

        Returns:
            str: AI-generated exploitation commands and analysis
        """
        if not self.is_configured():
            return "!! AI engine not configured. Run with --no-ai for static analysis only."

        # Build the prompt
        user_prompt = build_analysis_prompt(findings_summary, domain_info, owned_user, dc_ip)

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        # Native Ollama API format
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": stream,
            "options": {
                "temperature": 0.3,  # Low temp for precise, consistent commands
            },
        }

        try:
            if stream:
                return self._stream_response(headers, payload)
            else:
                return self._batch_response(headers, payload)
        except requests.exceptions.ConnectionError:
            return (
                "!! Connection error: Could not reach the Ollama API. "
                "Check your network connection and OLLAMA_BASE_URL setting."
            )
        except requests.exceptions.Timeout:
            return (
                f"!! Request timed out after {REQUEST_TIMEOUT}s. "
                "The model may be overloaded. Try again later."
            )
        except Exception as e:
            return f"!! AI engine error: {str(e)}"

    def _stream_response(self, headers: dict, payload: dict) -> str:
        """Stream the response from the API with live rendering."""
        full_response = ""

        console.print()
        console.print(
            Panel(
                f"[bold cyan]AI Analysis[/] using [bold]{self.model}[/]",
                border_style="cyan",
                padding=(0, 1),
            )
        )
        console.print()

        try:
            response = requests.post(
                self.chat_endpoint,
                headers=headers,
                json=payload,
                stream=True,
                timeout=REQUEST_TIMEOUT,
            )

            if response.status_code != 200:
                error_body = response.text[:500]
                return (
                    f"!! API returned status {response.status_code}.\n"
                    f"Response: {error_body}\n\n"
                    f"Check your API key and model name.\n"
                    f"Endpoint used: {self.chat_endpoint}"
                )

            # Native Ollama streaming format: each line is a JSON object
            # with {"message": {"content": "..."}, "done": false}
            for line in response.iter_lines(decode_unicode=True):
                if not line:
                    continue

                try:
                    chunk = json.loads(line)

                    # Check for errors in response
                    if "error" in chunk:
                        return f"!! API error: {chunk['error']}"

                    # Native Ollama format: message.content
                    message = chunk.get("message", {})
                    content = message.get("content", "")

                    if content:
                        full_response += content
                        sys.stdout.write(content)
                        sys.stdout.flush()

                    # Check if done
                    if chunk.get("done", False):
                        break

                except json.JSONDecodeError:
                    continue

            sys.stdout.write("\n")
            sys.stdout.flush()

        except requests.exceptions.RequestException as e:
            return f"!! Request failed: {str(e)}"

        return full_response

    def _batch_response(self, headers: dict, payload: dict) -> str:
        """Get the full response in one batch (no streaming)."""
        payload["stream"] = False

        try:
            response = requests.post(
                self.chat_endpoint,
                headers=headers,
                json=payload,
                timeout=REQUEST_TIMEOUT,
            )

            if response.status_code != 200:
                error_body = response.text[:500]
                return (
                    f"!! API returned status {response.status_code}.\n"
                    f"Response: {error_body}\n"
                    f"Endpoint used: {self.chat_endpoint}"
                )

            # Native Ollama format: {"message": {"content": "..."}}
            result = response.json()

            if "error" in result:
                return f"!! API error: {result['error']}"

            return result.get("message", {}).get("content", "")

        except requests.exceptions.RequestException as e:
            return f"!! Request failed: {str(e)}"

    def test_connection(self) -> bool:
        """Test the API connection with a simple request."""
        if not self.is_configured():
            return False

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": "Say 'HoundBot ready' in exactly 2 words."}],
            "stream": False,
        }

        try:
            response = requests.post(
                self.chat_endpoint,
                headers=headers,
                json=payload,
                timeout=30,
            )
            return response.status_code == 200
        except Exception:
            return False
