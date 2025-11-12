"""Policy file loader and validator."""

import yaml
import json
from pathlib import Path
from .schema import PolicyFile


def load_policy_file(path: Path) -> PolicyFile:
    """
    Load and validate a policy file.

    Args:
        path: Path to policy file (YAML or JSON)

    Returns:
        Validated PolicyFile object

    Raises:
        ValueError: If file format is unsupported
        ValidationError: If policy schema is invalid
    """
    content = path.read_text()

    # Parse based on extension
    if path.suffix in [".yaml", ".yml"]:
        data = yaml.safe_load(content)
    elif path.suffix == ".json":
        data = json.loads(content)
    else:
        raise ValueError(f"Unsupported policy file format: {path.suffix}")

    # Validate against schema
    return PolicyFile(**data)
