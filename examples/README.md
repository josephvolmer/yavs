# YAVS Examples

This directory contains example configurations and usage patterns for YAVS.

## Directory Structure

```
examples/
├── configs/          # Configuration file examples
├── docker/           # Docker-related examples
└── ci-cd/           # CI/CD pipeline examples
```

## Configuration Examples

### configs/yavs-config-full.yaml
Complete YAVS configuration with all available options, including AI features, scanner settings, and output formats.

### configs/yavs-config-native.yaml
Configuration using native scanner config files (.semgrep.yml, trivy.yaml, etc.)

### configs/.checkov.yaml
Native Checkov configuration example

### configs/.semgrep.yml
Native Semgrep configuration example

### configs/trivy.yaml
Native Trivy configuration example

## Docker Examples

### docker/images.txt
Example file containing a list of Docker images to scan (one per line).

Usage:
```bash
yavs scan --images-file examples/docker/images.txt --sbom
```

## CI/CD Examples

Comprehensive CI/CD pipeline examples for various platforms:
- **github-actions.yml** - GitHub Actions workflow
- **gitlab-ci.yml** - GitLab CI/CD pipeline
- **jenkinsfile** - Jenkins declarative pipeline
- **azure-pipelines.yml** - Azure DevOps pipeline

All examples demonstrate full YAVS capabilities including scanning, reporting, SBOM generation, and optional integrations (Slack/Teams notifications, issue creation).

## Quick Start

1. Copy a config example to your project:
   ```bash
   cp examples/configs/yavs-config-full.yaml .yavs.yaml
   ```

2. Edit the configuration to match your needs

3. Run YAVS:
   ```bash
   yavs scan --config .yavs.yaml
   ```

For more detailed documentation, run:
```bash
yavs man
```
