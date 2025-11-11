"""AI provider abstraction for multi-model support."""

import os
from typing import List, Dict, Any, Optional, Tuple
from abc import ABC, abstractmethod

from ..utils.logging import get_logger

logger = get_logger(__name__)


class AIProvider(ABC):
    """Abstract base class for AI providers."""

    @abstractmethod
    def create_completion(self, prompt: str, max_tokens: int, temperature: float) -> str:
        """Create a text completion."""
        pass

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Get provider name for logging."""
        pass

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Get model name for logging."""
        pass


class AnthropicProvider(AIProvider):
    """Anthropic Claude provider."""

    def __init__(self, model: str = "claude-sonnet-4-5-20250929", api_key: Optional[str] = None):
        from anthropic import Anthropic

        self.model = model
        api_key = api_key or os.getenv("ANTHROPIC_API_KEY")

        if not api_key:
            raise ValueError(
                "Anthropic API key not found. Set ANTHROPIC_API_KEY environment variable."
            )

        self.client = Anthropic(api_key=api_key)
        logger.info(f"Initialized Anthropic provider with model: {model}")

    def create_completion(self, prompt: str, max_tokens: int, temperature: float) -> str:
        """Create completion using Claude."""
        response = self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.content[0].text

    @property
    def provider_name(self) -> str:
        return "Anthropic Claude"

    @property
    def model_name(self) -> str:
        return self.model


class OpenAIProvider(AIProvider):
    """OpenAI provider."""

    def __init__(self, model: str = "gpt-4o", api_key: Optional[str] = None):
        from openai import OpenAI

        self.model = model
        api_key = api_key or os.getenv("OPENAI_API_KEY")

        if not api_key:
            raise ValueError(
                "OpenAI API key not found. Set OPENAI_API_KEY environment variable."
            )

        self.client = OpenAI(api_key=api_key)
        logger.info(f"Initialized OpenAI provider with model: {model}")

    def create_completion(self, prompt: str, max_tokens: int, temperature: float) -> str:
        """Create completion using OpenAI."""
        response = self.client.chat.completions.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content

    @property
    def provider_name(self) -> str:
        return "OpenAI"

    @property
    def model_name(self) -> str:
        return self.model


def detect_provider(
    config_provider: Optional[str] = None,
    config_model: Optional[str] = None
) -> Tuple[str, str]:
    """
    Detect which AI provider to use based on configuration and available API keys.

    Priority:
    1. Use config_provider if specified and API key available
    2. Use ANTHROPIC_API_KEY if available
    3. Fall back to OPENAI_API_KEY if available
    4. Raise error if no API keys found

    Args:
        config_provider: Provider from config ('anthropic' or 'openai')
        config_model: Model from config

    Returns:
        Tuple of (provider_type, model_name)
    """
    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    openai_key = os.getenv("OPENAI_API_KEY")

    # Default models
    DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-5-20250929"
    DEFAULT_OPENAI_MODEL = "gpt-4o"

    # If provider explicitly configured
    if config_provider:
        config_provider = config_provider.lower()

        if config_provider == "anthropic":
            if not anthropic_key:
                logger.warning("Anthropic configured but ANTHROPIC_API_KEY not found")
                if openai_key:
                    logger.info("Falling back to OpenAI")
                    return "openai", config_model or DEFAULT_OPENAI_MODEL
                raise ValueError("ANTHROPIC_API_KEY not set")

            model = config_model or DEFAULT_ANTHROPIC_MODEL
            logger.info(f"Using configured provider: Anthropic Claude ({model})")
            return "anthropic", model

        elif config_provider == "openai":
            if not openai_key:
                logger.warning("OpenAI configured but OPENAI_API_KEY not found")
                if anthropic_key:
                    logger.info("Falling back to Anthropic Claude")
                    return "anthropic", config_model or DEFAULT_ANTHROPIC_MODEL
                raise ValueError("OPENAI_API_KEY not set")

            model = config_model or DEFAULT_OPENAI_MODEL
            logger.info(f"Using configured provider: OpenAI ({model})")
            return "openai", model

    # Auto-detect: prefer Anthropic if both available
    if anthropic_key:
        model = config_model or DEFAULT_ANTHROPIC_MODEL
        logger.info(f"Auto-detected provider: Anthropic Claude ({model})")
        return "anthropic", model

    if openai_key:
        model = config_model or DEFAULT_OPENAI_MODEL
        logger.info(f"Auto-detected provider: OpenAI ({model})")
        return "openai", model

    raise ValueError(
        "No AI provider API key found. Set ANTHROPIC_API_KEY or OPENAI_API_KEY environment variable."
    )


def create_provider(
    config_provider: Optional[str] = None,
    config_model: Optional[str] = None,
    api_key: Optional[str] = None
) -> AIProvider:
    """
    Create an AI provider instance based on configuration.

    Args:
        config_provider: Provider from config ('anthropic' or 'openai')
        config_model: Model from config
        api_key: Explicit API key (overrides env vars)

    Returns:
        AIProvider instance
    """
    provider_type, model = detect_provider(config_provider, config_model)

    if provider_type == "anthropic":
        return AnthropicProvider(model=model, api_key=api_key)
    elif provider_type == "openai":
        return OpenAIProvider(model=model, api_key=api_key)
    else:
        raise ValueError(f"Unknown provider type: {provider_type}")
