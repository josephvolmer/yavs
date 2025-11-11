.PHONY: help install install-dev setup clean clean-all clean-artifacts clean-test-results scan scan-ai scan-structured scan-flat summarize summarize-enrich report test check-env test-combinations test-all verify-tools update-tools pin-tools lint format build

.DEFAULT_GOAL := help

help: ## Show this help message
	@echo "YAVS - Yet Another Vulnerability Scanner"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*?##/ { printf "  %-20s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

install: ## Install YAVS in development mode
	@pip install -e .

install-dev: ## Install YAVS with development dependencies
	@pip install -e ".[dev]"
	@echo "✓ Installed YAVS with dev dependencies (pytest, black, ruff)"

setup: install ## Install scanner dependencies (Trivy)
	@yavs tools install

# ============================================================================
# Tool Management
# ============================================================================

verify-tools: ## Check installed scanner versions
	@echo "======================================"
	@echo "Scanner Tool Versions"
	@echo "======================================"
	@echo ""
	@echo "Trivy:"
	@trivy --version 2>/dev/null || echo "  ✗ Not installed"
	@echo ""
	@echo "Semgrep:"
	@semgrep --version 2>/dev/null || echo "  ✗ Not installed"
	@echo ""
	@echo "Bandit:"
	@bandit --version 2>/dev/null || echo "  ✗ Not installed"
	@echo ""
	@echo "Checkov:"
	@checkov --version 2>/dev/null || echo "  ✗ Not installed"
	@echo ""
	@echo "BinSkim:"
	@binskim --version 2>/dev/null || echo "  ✗ Not installed (Windows only)"
	@echo ""
	@echo "======================================"

update-tools: ## Update all scanner tools to latest versions
	@echo "Updating scanner tools..."
	@echo ""
	@echo "Updating Trivy..."
	@pip install --upgrade trivy 2>/dev/null || echo "  Install manually: https://aquasecurity.github.io/trivy/"
	@echo ""
	@echo "Updating Semgrep..."
	@pip install --upgrade semgrep
	@echo ""
	@echo "Updating Bandit..."
	@pip install --upgrade bandit
	@echo ""
	@echo "Updating Checkov..."
	@pip install --upgrade checkov
	@echo ""
	@echo "✓ Scanner tools updated!"
	@echo ""
	@make verify-tools

pin-tools: ## Show current tool versions and create requirements-scanners.txt
	@echo "Creating requirements-scanners.txt with pinned versions..."
	@echo "# Scanner tool versions - Generated on $$(date)" > requirements-scanners.txt
	@echo "# Install with: pip install -r requirements-scanners.txt" >> requirements-scanners.txt
	@echo "" >> requirements-scanners.txt
	@semgrep --version 2>/dev/null | head -1 | awk '{print "semgrep==" $$2}' >> requirements-scanners.txt || echo "# semgrep - not installed" >> requirements-scanners.txt
	@bandit --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 | awk '{print "bandit==" $$1}' >> requirements-scanners.txt || echo "# bandit - not installed" >> requirements-scanners.txt
	@checkov --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 | awk '{print "checkov==" $$1}' >> requirements-scanners.txt || echo "# checkov - not installed" >> requirements-scanners.txt
	@echo "" >> requirements-scanners.txt
	@echo "# Note: Trivy should be installed via system package manager" >> requirements-scanners.txt
	@echo "# See: https://aquasecurity.github.io/trivy/latest/getting-started/installation/" >> requirements-scanners.txt
	@echo ""
	@cat requirements-scanners.txt
	@echo ""
	@echo "✓ Pinned versions saved to requirements-scanners.txt"

check-env: ## Check if API keys are set
	@echo "Checking API keys..."
	@if [ -f .env ]; then \
		echo "✓ .env file found"; \
		if grep -q "ANTHROPIC_API_KEY" .env 2>/dev/null && [ -n "$$(grep ANTHROPIC_API_KEY .env | cut -d= -f2 | sed 's/ //g')" ]; then \
			echo "✓ ANTHROPIC_API_KEY is set"; \
		else \
			echo "✗ ANTHROPIC_API_KEY not set"; \
		fi; \
		if grep -q "OPENAI_API_KEY" .env 2>/dev/null && [ -n "$$(grep OPENAI_API_KEY .env | cut -d= -f2 | sed 's/ //g')" ]; then \
			echo "✓ OPENAI_API_KEY is set"; \
		else \
			echo "✗ OPENAI_API_KEY not set"; \
		fi; \
	else \
		echo "✗ No .env file found"; \
		echo ""; \
		echo "Create .env with:"; \
		echo "  ANTHROPIC_API_KEY=sk-ant-..."; \
		echo "  OPENAI_API_KEY=sk-..."; \
	fi

# ============================================================================
# Scanning Targets (all output to artifacts/)
# ============================================================================

scan: setup ## Run basic scan on sample project (no AI)
	@echo "Running scan..."
	@mkdir -p artifacts/quick-scan
	@yavs scan tests/fixtures/sample_project --all --no-ai --project "Sample Python Project" --branch "main" -o artifacts/quick-scan
	@echo ""
	@echo "✓ Scan complete!"
	@echo "Results: artifacts/quick-scan/"

scan-ai: setup check-env ## Run scan with AI features
	@echo "Running scan with AI..."
	@mkdir -p artifacts/ai-scan
	@if [ -f .env ]; then \
		export $$(grep -v '^#' .env | sed 's/#.*//g' | xargs) && \
		yavs scan tests/fixtures/sample_project --all --project "Sample Python Project" --branch "main" -o artifacts/ai-scan; \
	else \
		echo "No .env file found. Running without AI..."; \
		yavs scan tests/fixtures/sample_project --all --no-ai --project "Sample Python Project" --branch "main" -o artifacts/ai-scan; \
	fi
	@echo ""
	@echo "✓ Scan complete!"
	@echo "Results: artifacts/ai-scan/"

scan-structured: setup check-env ## Run scan with structured output format (default)
	@echo "Running scan with structured output (default)..."
	@mkdir -p artifacts/structured-scan
	@if [ -f .env ]; then \
		export $$(grep -v '^#' .env | sed 's/#.*//g' | xargs) && \
		yavs scan tests/fixtures/sample_project --all --project "Sample Python Project" --branch "main" -o artifacts/structured-scan; \
	else \
		echo "No .env file found. Running without AI..."; \
		yavs scan tests/fixtures/sample_project --all --no-ai --project "Sample Python Project" --branch "main" -o artifacts/structured-scan; \
	fi
	@echo ""
	@echo "✓ Scan complete with structured output!"
	@echo "Results: artifacts/structured-scan/"

scan-flat: setup check-env ## Run scan with flat output format
	@echo "Running scan with flat output..."
	@mkdir -p artifacts/flat-scan
	@if [ -f .env ]; then \
		export $$(grep -v '^#' .env | sed 's/#.*//g' | xargs) && \
		yavs scan tests/fixtures/sample_project --all --flat --project "Sample Python Project" --branch "main" -o artifacts/flat-scan; \
	else \
		echo "No .env file found. Running without AI..."; \
		yavs scan tests/fixtures/sample_project --all --no-ai --flat --project "Sample Python Project" --branch "main" -o artifacts/flat-scan; \
	fi
	@echo ""
	@echo "✓ Scan complete with flat output!"
	@echo "Results: artifacts/flat-scan/"

scan-images: setup ## Scan Docker images (requires Docker)
	@echo "Scanning Docker images..."
	@if [ ! -f images.txt ]; then \
		echo "Creating sample images.txt..."; \
		cp images.txt.example images.txt 2>/dev/null || \
		echo "# Sample Docker images\nnginx:latest\nubuntu:22.04\npython:3.11-slim" > images.txt; \
	fi
	@mkdir -p artifacts/image-scan
	@yavs scan --images-file images.txt --sbom --no-ai -o artifacts/image-scan
	@echo ""
	@echo "✓ Image scan complete!"
	@echo "Results: artifacts/image-scan/"

scan-all-fixtures: setup ## Comprehensive scan of all test fixtures
	@echo "======================================"
	@echo "Comprehensive YAVS Test Scan"
	@echo "======================================"
	@echo ""
	@mkdir -p artifacts/fixtures
	@echo "Scanning Python project..."
	@yavs scan tests/fixtures/sample_project --all --no-ai --project "Sample Python Project" --branch "main" -o artifacts/fixtures/python || true
	@echo ""
	@echo "Scanning Node.js project..."
	@yavs scan tests/fixtures/nodejs_project --sbom --no-ai --project "Sample Node.js Project" --branch "main" -o artifacts/fixtures/nodejs || true
	@echo ""
	@echo "Scanning Java project..."
	@yavs scan tests/fixtures/java_project --sbom --no-ai --project "Sample Java Project" --branch "main" -o artifacts/fixtures/java || true
	@echo ""
	@echo "Scanning Go project..."
	@yavs scan tests/fixtures/go_project --sbom --no-ai --project "Sample Go Project" --branch "main" -o artifacts/fixtures/go || true
	@echo ""
	@echo "Scanning Kubernetes manifests..."
	@yavs scan tests/fixtures/kubernetes --compliance --no-ai --project "Sample Kubernetes Project" --branch "main" -o artifacts/fixtures/kubernetes || true
	@echo ""
	@echo "======================================"
	@echo "✓ All fixture scans complete!"
	@echo "Results: artifacts/fixtures/"
	@echo "======================================"

scan-multi-dir: setup ## Test multi-directory scanning
	@echo "Testing multi-directory scan..."
	@mkdir -p artifacts/multi-dir
	@yavs scan tests/fixtures/sample_project tests/fixtures/nodejs_project --all --no-ai --project "Multi-Language Project" --branch "main" -o artifacts/multi-dir
	@echo ""
	@echo "✓ Multi-directory scan complete!"
	@echo "Results: artifacts/multi-dir/"

summarize: check-env ## Generate AI summary of scan results (separate file)
	@echo "Generating AI summary..."
	@if [ ! -f artifacts/quick-scan/yavs-results.json ]; then \
		echo "✗ No results found. Run 'make scan' first."; \
		exit 1; \
	fi
	@if [ -f .env ]; then \
		export $$(grep -v '^#' .env | sed 's/#.*//g' | xargs) && \
		yavs summarize artifacts/quick-scan/yavs-results.json -o artifacts/quick-scan; \
	else \
		echo "✗ No .env file found. AI features require API keys."; \
		exit 1; \
	fi
	@echo ""
	@echo "✓ Summary saved to: artifacts/quick-scan/yavs-ai-summary.json"

summarize-enrich: check-env ## Generate AI summary and enrich scan results file
	@echo "Generating AI summary (enriched mode)..."
	@if [ ! -f artifacts/quick-scan/yavs-results.json ]; then \
		echo "✗ No results found. Run 'make scan' first."; \
		exit 1; \
	fi
	@if [ -f .env ]; then \
		export $$(grep -v '^#' .env | sed 's/#.*//g' | xargs) && \
		yavs summarize artifacts/quick-scan/yavs-results.json --enrich; \
	else \
		echo "✗ No .env file found. AI features require API keys."; \
		exit 1; \
	fi
	@echo ""
	@echo "✓ Scan results enriched with AI summary"

report: ## Generate HTML security report from scan results
	@echo "Generating HTML report..."
	@if [ ! -f artifacts/quick-scan/yavs-results.json ]; then \
		echo "✗ No results found. Run 'make scan' first."; \
		exit 1; \
	fi
	@yavs report artifacts/quick-scan/yavs-results.json -o artifacts/quick-scan/security-report.html
	@echo ""
	@echo "✓ HTML report generated!"
	@echo "  Open: file://$$(pwd)/artifacts/quick-scan/security-report.html"

# ============================================================================
# Testing Targets
# ============================================================================

test: install ## Run pytest test suite
	@pytest tests/ -v

test-coverage: install ## Run tests with coverage report
	@pytest tests/ --cov=yavs --cov-report=html --cov-report=term
	@echo ""
	@echo "✓ Coverage report generated in htmlcov/index.html"

test-integration: install ## Run integration tests only
	@pytest tests/test_integration.py tests/test_multi_language.py -v -m integration

test-multi-language: install ## Test multi-language fixtures
	@pytest tests/test_multi_language.py -v

test-combinations: setup ## Run comprehensive combination tests (41 scenarios)
	@echo "Running comprehensive combination tests..."
	@./tests/test_all_combinations.sh

test-all: test test-combinations ## Run all tests (pytest + combination tests)
	@echo ""
	@echo "======================================"
	@echo "✓ All tests complete!"
	@echo "======================================"

# ============================================================================
# Docker Image Testing
# ============================================================================

build-test-images: ## Build Docker test images
	@cd tests/fixtures/docker_images && ./build-test-images.sh

scan-test-images: build-test-images ## Build and scan Docker test images
	@mkdir -p artifacts/docker-images
	@cd tests/fixtures/docker_images && ./build-test-images.sh scan

# ============================================================================
# Cleanup Targets
# ============================================================================

clean-artifacts: ## Clean all test artifacts
	@echo "Cleaning artifacts directory..."
	@rm -rf artifacts/
	@echo "✓ Cleaned artifacts/"

clean-test-results: ## Clean scattered test results from fixtures
	@echo "Cleaning scattered test results..."
	@find tests/fixtures -name "yavs-results.*" -delete 2>/dev/null || true
	@find tests/fixtures -name "sbom.json" -delete 2>/dev/null || true
	@rm -rf tests/multi-dir-results/ 2>/dev/null || true
	@echo "✓ Cleaned test fixture results"

clean: ## Clean build artifacts and temporary files
	@echo "Cleaning build artifacts and temporary files..."
	@rm -rf build/ dist/ *.egg-info src/*.egg-info .pytest_cache .coverage htmlcov/
	@rm -rf .claude/
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete
	@find . -type f -name "*.pyo" -delete
	@find . -type f -name ".DS_Store" -delete
	@find . -type f -name "*.swp" -delete
	@find . -type f -name "*.swo" -delete
	@find . -type f -name "*~" -delete
	@find . -type f -name "*.tmp" -delete
	@find . -type f -name "*.bak" -delete
	@find . -type f -name ".make_*" -delete
	@echo "✓ Cleaned build artifacts and temporary files"

clean-all: clean clean-artifacts clean-test-results ## Clean everything (build + artifacts + test results)
	@echo ""
	@echo "======================================"
	@echo "✓ Cleaned everything!"
	@echo "======================================"

# ============================================================================
# Development Tools
# ============================================================================

lint: install-dev ## Run code quality checks (ruff)
	@echo "Running linter..."
	@ruff check src/ tests/ || true
	@echo ""
	@echo "✓ Lint check complete"

format: install-dev ## Auto-format code with black
	@echo "Formatting code with black..."
	@black src/ tests/
	@echo ""
	@echo "✓ Code formatted"

format-check: install-dev ## Check code formatting without changes
	@echo "Checking code format..."
	@black --check src/ tests/
	@echo ""
	@echo "✓ Format check complete"

build: clean ## Build wheel and source distribution
	@echo "Building YAVS package..."
	@python -m build
	@echo ""
	@ls -lh dist/
	@echo ""
	@echo "✓ Build complete!"
	@echo "  Wheel: dist/yavs-*.whl"
	@echo "  Source: dist/yavs-*.tar.gz"

build-check: build ## Build and verify package contents
	@echo ""
	@echo "Checking package contents..."
	@tar -tzf dist/yavs-*.tar.gz | head -30
	@echo ""
	@echo "✓ Package built and verified"

upload-test: build ## Upload package to Test PyPI
	@echo "Uploading to Test PyPI..."
	@python -m twine upload --repository testpypi dist/*
	@echo ""
	@echo "✓ Uploaded to Test PyPI"
	@echo "  Install with: pip install --index-url https://test.pypi.org/simple/ yavs"

upload: build ## Upload package to production PyPI
	@echo "⚠️  WARNING: Uploading to PRODUCTION PyPI!"
	@echo ""
	@read -p "Are you sure? (yes/no): " confirm && [ "$$confirm" = "yes" ]
	@python -m twine upload dist/*
	@echo ""
	@echo "✓ Uploaded to PyPI"
	@echo "  Install with: pip install yavs"
