"""AI-powered triage and clustering engine with multi-provider support."""

import os
from typing import List, Dict, Any, Optional
from collections import defaultdict

from .provider import create_provider, AIProvider
from ..utils.logging import LoggerMixin


class TriageEngine(LoggerMixin):
    """
    AI-powered triage engine for vulnerability clustering.

    Uses AI (Claude or OpenAI) to:
    - Cluster related vulnerabilities
    - Identify root causes
    - Prioritize remediation efforts
    - Reduce noise and duplicates
    """

    def __init__(
        self,
        model: Optional[str] = None,
        provider: Optional[str] = None,
        api_key: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: float = 0.0
    ):
        """
        Initialize triage engine.

        Args:
            model: AI model to use (provider-specific)
            provider: AI provider ('anthropic' or 'openai')
            api_key: API key (or from environment)
            max_tokens: Maximum tokens for response
            temperature: Sampling temperature
        """
        self.max_tokens = max_tokens
        self.temperature = temperature

        # Create provider
        self.provider: AIProvider = create_provider(
            config_provider=provider,
            config_model=model,
            api_key=api_key
        )

        # Log which provider we're using
        self.logger.info(
            f"[bold cyan]AI Triage using:[/bold cyan] {self.provider.provider_name} ({self.provider.model_name})",
            extra={"markup": True}
        )

    def triage(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Triage and cluster findings.

        Args:
            findings: List of normalized findings

        Returns:
            Dictionary with triage results including clusters and priorities
        """
        if not findings:
            return {
                "clusters": [],
                "priorities": [],
                "insights": "No findings to triage.",
                "ai_provider": None,
                "ai_model": None
            }

        self.logger.info(f"Triaging {len(findings)} findings")

        # First, do basic clustering by similarity
        basic_clusters = self._basic_clustering(findings)

        # Then use AI for intelligent clustering and prioritization
        ai_analysis = self._ai_triage(findings, basic_clusters)

        # Add provider info
        ai_analysis["ai_provider"] = self.provider.provider_name
        ai_analysis["ai_model"] = self.provider.model_name

        return ai_analysis

    def _basic_clustering(self, findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Perform basic clustering by rule_id and message similarity.

        Args:
            findings: List of findings

        Returns:
            Dictionary mapping cluster keys to finding lists
        """
        clusters = defaultdict(list)

        for finding in findings:
            # Cluster by rule_id primarily
            rule_id = finding.get("rule_id") or finding.get("message", "unknown")
            clusters[rule_id].append(finding)

        return dict(clusters)

    def _ai_triage(
        self,
        findings: List[Dict[str, Any]],
        basic_clusters: Dict[str, List[Dict[str, Any]]]
    ) -> Dict[str, Any]:
        """
        Use AI to perform intelligent triage.

        Args:
            findings: List of findings
            basic_clusters: Pre-computed basic clusters

        Returns:
            Triage analysis with clusters and priorities
        """
        prompt = self._build_triage_prompt(findings, basic_clusters)

        try:
            analysis = self.provider.create_completion(
                prompt=prompt,
                max_tokens=self.max_tokens,
                temperature=self.temperature
            )

            # Return structured results
            return {
                "clusters": basic_clusters,
                "cluster_count": len(basic_clusters),
                "total_findings": len(findings),
                "ai_analysis": analysis,
            }

        except Exception as e:
            self.logger.error(f"AI triage failed: {str(e)}")
            return {
                "clusters": basic_clusters,
                "cluster_count": len(basic_clusters),
                "total_findings": len(findings),
                "ai_analysis": f"Triage analysis unavailable: {str(e)}",
            }

    def _build_triage_prompt(
        self,
        findings: List[Dict[str, Any]],
        clusters: Dict[str, List[Dict[str, Any]]]
    ) -> str:
        """Build prompt for AI triage."""
        # Prepare cluster summary
        cluster_summaries = []
        for cluster_key, cluster_findings in list(clusters.items())[:20]:  # Limit to top 20
            count = len(cluster_findings)
            severity = cluster_findings[0].get("severity", "UNKNOWN")
            category = cluster_findings[0].get("category", "unknown")

            cluster_summaries.append(
                f"- {cluster_key}: {count} findings, Severity: {severity}, Category: {category}"
            )

        cluster_text = "\n".join(cluster_summaries)

        # Get severity distribution
        severity_counts = defaultdict(int)
        for f in findings:
            severity_counts[f.get("severity", "UNKNOWN")] += 1

        prompt = f"""You are a security analyst performing triage on vulnerability scan results. Analyze the findings and provide prioritized remediation guidance.

## Overall Statistics
- Total findings: {len(findings)}
- Unique issue types: {len(clusters)}
- Critical: {severity_counts.get('CRITICAL', 0)}
- High: {severity_counts.get('HIGH', 0)}
- Medium: {severity_counts.get('MEDIUM', 0)}
- Low: {severity_counts.get('LOW', 0)}

## Clustered Issues (top 20 shown):
{cluster_text}

Please provide:
1. **Root Cause Analysis**: Identify common underlying issues or patterns
2. **Priority Recommendations**: Which issue clusters should be addressed first and why?
3. **Quick Wins**: Any easy fixes that would eliminate multiple findings?
4. **Systemic Issues**: Are there patterns suggesting process or architectural problems?
5. **Remediation Strategy**: Suggested order of operations for fixing these issues

Be concise and actionable. Format in clear markdown."""

        return prompt

    def get_top_priorities(
        self,
        findings: List[Dict[str, Any]],
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Get top priority findings based on severity and impact.

        Args:
            findings: List of findings
            limit: Number of top priorities to return

        Returns:
            Sorted list of top priority findings
        """
        # Score each finding
        severity_scores = {
            "CRITICAL": 100,
            "HIGH": 50,
            "MEDIUM": 25,
            "LOW": 10,
            "INFO": 1,
            "UNKNOWN": 5
        }

        scored_findings = []
        for finding in findings:
            score = severity_scores.get(finding.get("severity", "UNKNOWN"), 0)

            # Boost score for certain categories
            if finding.get("category") == "secret":
                score *= 1.5
            elif finding.get("category") == "sast":
                score *= 1.2

            scored_findings.append((score, finding))

        # Sort by score descending
        scored_findings.sort(key=lambda x: x[0], reverse=True)

        # Return top N
        return [f[1] for f in scored_findings[:limit]]

    def get_provider_info(self) -> Dict[str, str]:
        """Get provider information for metadata."""
        return {
            "provider": self.provider.provider_name,
            "model": self.provider.model_name
        }
