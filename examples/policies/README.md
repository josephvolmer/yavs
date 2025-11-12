# YAVS Policy Examples

This directory contains example policy files demonstrating Policy-as-Code capabilities.

## Available Policies

### 1. `security-baseline.yaml`
Enterprise security baseline with common suppression and enforcement rules.

**Usage:**
```bash
yavs scan --all --policy examples/policies/security-baseline.yaml
```

### 2. `compliance-pci.yaml`
PCI-DSS 3.2.1 compliance rules for payment card industry standards.

**Usage:**
```bash
yavs scan --all --policy examples/policies/compliance-pci.yaml --policy-mode enforce
```

### 3. `team-exceptions.yaml`
Example team-specific overrides and exceptions.

**Usage:**
```bash
yavs scan --all \
  --policy examples/policies/security-baseline.yaml \
  --policy examples/policies/team-exceptions.yaml
```

## Testing Policies

**Audit Mode** (test without failing builds):
```bash
yavs scan --all --policy examples/policies/security-baseline.yaml --policy-mode audit
```

**Enforce Mode** (fail on violations):
```bash
yavs scan --all --policy examples/policies/security-baseline.yaml --policy-mode enforce
```

## Custom Policies

Create your own policy file following the schema at `docs/schemas/schema-policy.json`.

See comprehensive documentation at `docs/POLICY.md`.
