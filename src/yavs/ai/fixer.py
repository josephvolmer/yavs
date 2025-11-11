"""AI-powered fix suggestion generator with multi-provider support."""

import os
import time
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional

from .provider import create_provider, AIProvider
from ..utils.logging import LoggerMixin


class Fixer(LoggerMixin):
    """
    AI-powered remediation guidance generator for security findings.

    Uses AI (Claude or OpenAI) to generate actionable suggestions including:
    - Step-by-step remediation instructions
    - Example code snippets (for reference, not auto-applied)
    - Configuration change recommendations
    - Package upgrade commands
    - Verification steps

    Note: This generates suggestions only - it does NOT automatically apply fixes.
    """

    def __init__(
        self,
        model: Optional[str] = None,
        provider: Optional[str] = None,
        api_key: Optional[str] = None,
        max_tokens: int = 2048,
        temperature: float = 0.0,
        parallel_requests: int = 5,
        rate_limit_rpm: int = 50,
        rate_limit_tpm: int = 40000
    ):
        """
        Initialize fixer.

        Args:
            model: AI model to use (provider-specific)
            provider: AI provider ('anthropic' or 'openai')
            api_key: API key (or from environment)
            max_tokens: Maximum tokens for response
            temperature: Sampling temperature
            parallel_requests: Number of parallel requests (1-10)
            rate_limit_rpm: Requests per minute limit
            rate_limit_tpm: Tokens per minute limit
        """
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.parallel_requests = min(max(1, parallel_requests), 10)  # Clamp to 1-10
        self.rate_limit_rpm = rate_limit_rpm
        self.rate_limit_tpm = rate_limit_tpm

        # Rate limiting tracking
        self.request_times = []
        self.token_count = 0
        self.last_token_reset = time.time()

        # Create provider
        self.provider: AIProvider = create_provider(
            config_provider=provider,
            config_model=model,
            api_key=api_key
        )

        # Log which provider we're using
        self.logger.info(
            f"[bold cyan]AI Fixer using:[/bold cyan] {self.provider.provider_name} ({self.provider.model_name})",
            extra={"markup": True}
        )
        self.logger.info(
            f"[bold cyan]Parallel requests:[/bold cyan] {self.parallel_requests} (Rate limit: {self.rate_limit_rpm} RPM)",
            extra={"markup": True}
        )

    def generate_fix(self, finding: Dict[str, Any]) -> str:
        """
        Generate a fix suggestion for a single finding.

        Args:
            finding: Normalized finding dictionary

        Returns:
            Fix suggestion text
        """
        self.logger.debug(f"Generating fix for: {finding.get('message')}")

        prompt = self._build_fix_prompt(finding)

        try:
            fix_text = self.provider.create_completion(
                prompt=prompt,
                max_tokens=self.max_tokens,
                temperature=self.temperature
            )
            return fix_text

        except Exception as e:
            self.logger.error(f"Failed to generate fix: {str(e)}")
            return f"Unable to generate fix: {str(e)}"

    def _wait_for_rate_limit(self):
        """Wait if necessary to respect rate limits."""
        current_time = time.time()

        # Clean up old request times (older than 1 minute)
        self.request_times = [t for t in self.request_times if current_time - t < 60]

        # Check if we're at the rate limit
        if len(self.request_times) >= self.rate_limit_rpm:
            # Wait until the oldest request is more than 1 minute old
            oldest_time = self.request_times[0]
            wait_time = 60 - (current_time - oldest_time)
            if wait_time > 0:
                self.logger.debug(f"Rate limit reached, waiting {wait_time:.1f}s")
                time.sleep(wait_time)

        # Record this request
        self.request_times.append(time.time())

    def _generate_fix_with_rate_limit(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate fix for a single finding with rate limiting.

        Args:
            finding: Finding dictionary

        Returns:
            Finding with ai_fix added
        """
        self._wait_for_rate_limit()

        severity = finding.get("severity", "").upper()
        if severity in ["CRITICAL", "HIGH"]:
            fix = self.generate_fix(finding)
            finding["ai_fix"] = fix
            finding["ai_provider"] = self.provider.provider_name
            finding["ai_model"] = self.provider.model_name

        return finding

    def generate_fixes_batch(
        self,
        findings: List[Dict[str, Any]],
        limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Generate fixes for multiple findings using parallel processing.

        Args:
            findings: List of findings
            limit: Maximum number of fixes to generate (None for all)

        Returns:
            List of findings with added 'ai_fix' field
        """
        findings_to_fix = findings[:limit] if limit else findings

        # Filter to high/critical severity
        critical_findings = [
            f for f in findings_to_fix
            if f.get("severity", "").upper() in ["CRITICAL", "HIGH"]
        ]

        self.logger.info(f"Generating fixes for {len(critical_findings)} critical/high findings")

        if not critical_findings:
            return findings

        # Create a mapping to track which findings need fixes
        findings_needing_fixes = set(id(f) for f in critical_findings)

        # Use ThreadPoolExecutor for parallel processing
        enhanced_critical = []
        with ThreadPoolExecutor(max_workers=self.parallel_requests) as executor:
            # Submit all critical findings for processing
            future_to_finding = {
                executor.submit(self._generate_fix_with_rate_limit, finding): finding
                for finding in critical_findings
            }

            # Collect results as they complete
            for future in as_completed(future_to_finding):
                try:
                    enhanced_finding = future.result()
                    enhanced_critical.append(enhanced_finding)
                except Exception as e:
                    finding = future_to_finding[future]
                    self.logger.error(f"Failed to generate fix for finding: {str(e)}")
                    enhanced_critical.append(finding)  # Add without fix

        # Build final list with all findings
        enhanced_findings = []
        for finding in findings:
            if id(finding) in findings_needing_fixes:
                # Find the enhanced version
                enhanced = next(
                    (f for f in enhanced_critical if id(f) == id(finding)),
                    finding
                )
                enhanced_findings.append(enhanced)
            else:
                enhanced_findings.append(finding)

        return enhanced_findings

    def _build_fix_prompt(self, finding: Dict[str, Any]) -> str:
        """Build prompt for fix generation."""
        category = finding.get("category", "unknown")
        severity = finding.get("severity", "UNKNOWN")
        message = finding.get("message", "Security issue")
        file_path = finding.get("file", "unknown")
        rule_id = finding.get("rule_id", "")

        # Build context based on category
        context_parts = []

        if category == "dependency":
            package = finding.get("package", "unknown")
            version = finding.get("version", "unknown")
            fixed_version = finding.get("fixed_version", "latest")
            context_parts.append(f"Package: {package} v{version}")
            if fixed_version:
                context_parts.append(f"Fixed in: {fixed_version}")

        elif category == "sast":
            line = finding.get("line")
            if line:
                context_parts.append(f"Line: {line}")

        elif category == "compliance":
            resource = finding.get("metadata", {}).get("resource")
            if resource:
                context_parts.append(f"Resource: {resource}")

        context = "\n".join(context_parts) if context_parts else "No additional context"

        prompt = f"""You are a security engineer. Provide a BRIEF remediation guide in markdown.

**Finding:** {severity} - {message}
**File:** {file_path}
**Rule:** {rule_id}
**Context:** {context}

Format your response EXACTLY like this:

### Fix
One sentence explaining what to do.

### Implementation
ALL code/commands MUST be in markdown code blocks with language tags.

Example format:
```python
# Your code here
```

Or for shell:
```bash
command here
```

### Verification
One sentence on how to verify.

CRITICAL REQUIREMENTS:
- ALL code MUST be in ```language code blocks
- Maximum 100 words total
- NO emojis
- NO prose before/after code blocks"""

        return prompt

    def get_provider_info(self) -> Dict[str, str]:
        """Get provider information for metadata."""
        return {
            "provider": self.provider.provider_name,
            "model": self.provider.model_name
        }
