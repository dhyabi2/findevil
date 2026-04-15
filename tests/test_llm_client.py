"""Tests for LLM client configuration loading."""

import os
import unittest
import yaml

from agent.llm_client import LLMConfig


class TestLLMConfig(unittest.TestCase):

    def test_default_config(self):
        cfg = LLMConfig()
        self.assertEqual(cfg.provider, "openrouter")
        self.assertEqual(cfg.model, "google/gemma-4-31b-it")
        self.assertEqual(cfg.base_url, "https://openrouter.ai/api/v1")
        self.assertEqual(cfg.temperature, 0.2)

    def test_from_yaml(self):
        with open("config.yaml") as f:
            raw = yaml.safe_load(f)
        cfg = LLMConfig.from_yaml(raw)
        self.assertEqual(cfg.provider, "openrouter")
        self.assertEqual(cfg.model, "google/gemma-4-31b-it")
        self.assertEqual(cfg.fallback_model, "google/gemma-3-27b-it")
        self.assertEqual(cfg.max_tokens, 8192)

    def test_env_var_resolution(self):
        os.environ["TEST_API_KEY"] = "test-key-123"
        raw = {
            "llm": {
                "provider": "openrouter",
                "openrouter": {
                    "api_key": "${TEST_API_KEY}",
                    "default_model": "test/model",
                },
            }
        }
        cfg = LLMConfig.from_yaml(raw)
        self.assertEqual(cfg.api_key, "test-key-123")
        del os.environ["TEST_API_KEY"]

    def test_missing_env_var(self):
        raw = {
            "llm": {
                "provider": "openrouter",
                "openrouter": {
                    "api_key": "${NONEXISTENT_VAR}",
                },
            }
        }
        cfg = LLMConfig.from_yaml(raw)
        self.assertEqual(cfg.api_key, "")


if __name__ == "__main__":
    unittest.main()
