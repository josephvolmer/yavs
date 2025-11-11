#!/bin/bash
# YAVS Version Bump Script
# Automatically updates version in __init__.py and CHANGELOG.md

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

if [ -z "$1" ]; then
  echo -e "${RED}Error: No version specified${NC}"
  echo ""
  echo "Usage: $0 <new-version> [commit-message]"
  echo ""
  echo "Examples:"
  echo "  $0 1.0.1                           # Patch release"
  echo "  $0 1.1.0 'Add stats command'       # Minor release with message"
  echo "  $0 2.0.0 'Breaking changes'        # Major release"
  exit 1
fi

NEW_VERSION="$1"
COMMIT_MSG="${2:-chore: bump version to $NEW_VERSION}"

# Validate version format (semver)
if ! [[ $NEW_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo -e "${RED}Error: Invalid version format${NC}"
  echo "Version must be in format: MAJOR.MINOR.PATCH (e.g., 1.0.1)"
  exit 1
fi

# Get old version
OLD_VERSION=$(grep '__version__' src/yavs/__init__.py | cut -d'"' -f2)

if [ "$OLD_VERSION" == "$NEW_VERSION" ]; then
  echo -e "${YELLOW}Warning: Version unchanged ($NEW_VERSION)${NC}"
  echo "Are you sure you want to continue? (y/N)"
  read -r response
  if [[ ! "$response" =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
  fi
fi

echo -e "${GREEN}Bumping version: $OLD_VERSION → $NEW_VERSION${NC}"
echo ""

# Update __init__.py
echo "📝 Updating src/yavs/__init__.py..."
if [[ "$OSTYPE" == "darwin"* ]]; then
  # macOS
  sed -i '' "s/__version__ = \"$OLD_VERSION\"/__version__ = \"$NEW_VERSION\"/" src/yavs/__init__.py
else
  # Linux
  sed -i "s/__version__ = \"$OLD_VERSION\"/__version__ = \"$NEW_VERSION\"/" src/yavs/__init__.py
fi

# Update CHANGELOG.md
echo "📝 Updating CHANGELOG.md..."
CHANGELOG_ENTRY="## [$NEW_VERSION] - $(date +%Y-%m-%d)

### Changed
- Version bump to $NEW_VERSION

"

# Insert after line 7 (after the header)
if [[ "$OSTYPE" == "darwin"* ]]; then
  # macOS
  sed -i '' "8i\\
$CHANGELOG_ENTRY
" CHANGELOG.md
else
  # Linux
  sed -i "8i\\
$CHANGELOG_ENTRY
" CHANGELOG.md
fi

echo ""
echo -e "${GREEN}✓ Updated src/yavs/__init__.py${NC}"
echo -e "${GREEN}✓ Updated CHANGELOG.md${NC}"
echo ""

# Show diff
echo "📊 Changes:"
echo ""
git diff src/yavs/__init__.py CHANGELOG.md | head -20
echo ""

# Prompt to commit
echo -e "${YELLOW}Ready to commit and push?${NC}"
echo ""
echo "The following will be executed:"
echo "  git add src/yavs/__init__.py CHANGELOG.md"
echo "  git commit -m '$COMMIT_MSG'"
echo "  git push origin main"
echo ""
echo "Proceed? (y/N)"
read -r response

if [[ "$response" =~ ^[Yy]$ ]]; then
  echo ""
  echo "🚀 Committing and pushing..."
  git add src/yavs/__init__.py CHANGELOG.md
  git commit -m "$COMMIT_MSG"
  git push origin main

  echo ""
  echo -e "${GREEN}✅ Version $NEW_VERSION pushed to main!${NC}"
  echo ""
  echo "Next steps:"
  echo "1. Watch GitHub Actions: https://github.com/$(git config --get remote.origin.url | sed 's/.*github.com[:/]\(.*\)\.git/\1/')/actions"
  echo "2. Monitor PyPI: https://pypi.org/project/yavs/"
  echo "3. Check release: https://github.com/$(git config --get remote.origin.url | sed 's/.*github.com[:/]\(.*\)\.git/\1/')/releases/tag/v$NEW_VERSION"
else
  echo ""
  echo -e "${YELLOW}⚠️  Changes staged but not committed.${NC}"
  echo ""
  echo "Next steps:"
  echo "1. Review changes: git diff"
  echo "2. Edit CHANGELOG.md to add proper release notes"
  echo "3. Commit manually:"
  echo "   git add src/yavs/__init__.py CHANGELOG.md"
  echo "   git commit -m '$COMMIT_MSG'"
  echo "   git push origin main"
fi

echo ""
echo -e "${GREEN}Done!${NC}"
