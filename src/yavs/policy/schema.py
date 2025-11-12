"""Policy schema definitions using Pydantic."""

from typing import List, Dict, Optional, Literal, Any
from pydantic import BaseModel, Field


class PolicyCondition(BaseModel):
    """Single condition in a policy rule."""
    field: str = Field(..., description="Finding field to match")
    operator: Literal["equals", "contains", "regex", "gt", "lt", "in"] = "equals"
    value: Any = Field(..., description="Value to compare against")
    case_sensitive: bool = True


class PolicyRule(BaseModel):
    """Individual policy rule."""
    id: str = Field(..., description="Unique rule identifier")
    name: str = Field(..., description="Human-readable rule name")
    description: Optional[str] = None
    enabled: bool = True

    # Conditions (all must match - AND logic)
    conditions: List[PolicyCondition] = Field(default_factory=list)

    # Actions when rule matches
    action: Literal["suppress", "fail", "warn", "tag"] = "suppress"
    action_config: Dict = Field(default_factory=dict)

    # Metadata
    severity_override: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    owner: Optional[str] = None
    reason: Optional[str] = None


class PolicyFile(BaseModel):
    """Top-level policy configuration."""
    version: str = "1.0"
    name: str = Field(..., description="Policy pack name")
    description: Optional[str] = None

    # Global settings
    settings: Dict = Field(default_factory=dict)

    # Rules
    rules: List[PolicyRule] = Field(default_factory=list)
