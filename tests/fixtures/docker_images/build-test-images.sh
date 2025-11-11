#!/bin/bash
#
# Build and test Docker images for YAVS testing
#
# Usage:
#   ./build-test-images.sh         # Build all test images
#   ./build-test-images.sh scan    # Build and scan all images
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "======================================"
echo "YAVS Docker Test Image Builder"
echo "======================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Build Python test image
echo -e "${YELLOW}Building Python test image...${NC}"
if docker build -t yavs-test-python:vulnerable -f Dockerfile.python-app . ; then
    echo -e "${GREEN}✓ Built yavs-test-python:vulnerable${NC}"
else
    echo -e "${RED}✗ Failed to build Python image${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}All test images built successfully!${NC}"
echo ""

# List built images
echo "Built images:"
docker images | grep "yavs-test" || echo "No yavs-test images found"

# If 'scan' argument provided, scan the images
if [ "$1" = "scan" ]; then
    echo ""
    echo "======================================"
    echo "Scanning Test Images"
    echo "======================================"
    echo ""

    # Check if yavs is installed
    if ! command -v yavs &> /dev/null; then
        echo -e "${RED}✗ YAVS not installed. Install with: pip install -e .${NC}"
        exit 1
    fi

    # Navigate to project root
    cd ../../..

    echo -e "${YELLOW}Scanning yavs-test-python:vulnerable...${NC}"
    yavs scan --images yavs-test-python:vulnerable --sbom --no-ai -o tests/fixtures/docker_images/scan-results

    echo ""
    echo -e "${GREEN}✓ Image scans complete!${NC}"
    echo "Results saved to: tests/fixtures/docker_images/scan-results/"
fi

echo ""
echo "======================================"
echo "Usage Examples:"
echo "======================================"
echo ""
echo "# Scan single image:"
echo "yavs scan --images yavs-test-python:vulnerable --sbom"
echo ""
echo "# Scan multiple images:"
echo "yavs scan --images yavs-test-python:vulnerable nginx:latest --sbom"
echo ""
echo "# Scan with structured output:"
echo "yavs scan --images yavs-test-python:vulnerable --sbom --structured"
echo ""
