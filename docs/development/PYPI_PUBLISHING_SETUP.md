# PyPI Publishing Setup Guide

Complete guide to setting up automated PyPI publishing for YAVS.

---

## 🎯 Overview

The GitHub Actions workflow automatically publishes YAVS to PyPI whenever:
1. The version in `src/yavs/__init__.py` is changed on `main` branch
2. Manual workflow dispatch is triggered

**Publishing Pipeline:**
```
Version Change → Tests → Build → TestPyPI → PyPI → GitHub Release → Announce
```

---

## 🔐 Method 1: Trusted Publishing (Recommended)

Trusted publishing uses OpenID Connect (OIDC) - no API tokens needed!

### Setup Steps:

#### 1. Configure PyPI Trusted Publisher

**For Production PyPI:**
1. Go to https://pypi.org/manage/account/publishing/
2. Add a new "pending publisher":
   - **PyPI Project Name**: `yavs`
   - **Owner**: Your GitHub username/org (e.g., `YAVS-OSS`)
   - **Repository name**: `yavs`
   - **Workflow name**: `pypi-publish.yml`
   - **Environment name**: `pypi`

**For TestPyPI:**
1. Go to https://test.pypi.org/manage/account/publishing/
2. Add the same configuration:
   - **Environment name**: `testpypi`

#### 2. Create GitHub Environments

1. Go to your repo → Settings → Environments
2. Create environment: `testpypi`
   - No protection rules needed
   - No secrets needed (trusted publishing)
3. Create environment: `pypi`
   - **Add protection rule**: Require reviewers (optional but recommended)
   - Select reviewers who can approve production releases
   - No secrets needed (trusted publishing)

#### 3. Test the Setup

```bash
# Bump version
sed -i '' 's/__version__ = "1.0.0"/__version__ = "1.0.1"/' src/yavs/__init__.py

# Commit and push
git add src/yavs/__init__.py
git commit -m "chore: bump version to 1.0.1"
git push origin main

# Watch the workflow at:
# https://github.com/YOUR-ORG/yavs/actions
```

---

## 🔑 Method 2: API Tokens (Alternative)

If you prefer using API tokens instead of trusted publishing:

### Setup Steps:

#### 1. Generate PyPI API Tokens

**For PyPI:**
1. Go to https://pypi.org/manage/account/token/
2. Create token:
   - **Token name**: `yavs-github-actions`
   - **Scope**: Project: `yavs`
3. Copy the token (starts with `pypi-`)

**For TestPyPI:**
1. Go to https://test.pypi.org/manage/account/token/
2. Create token with same settings
3. Copy the token

#### 2. Add Secrets to GitHub

1. Go to repo → Settings → Secrets and variables → Actions
2. Create repository secrets:
   - **PYPI_API_TOKEN**: Paste production PyPI token
   - **TEST_PYPI_API_TOKEN**: Paste TestPyPI token

#### 3. Update Workflow

Edit `.github/workflows/pypi-publish.yml`:

```yaml
# For TestPyPI job, change from:
- name: Publish to TestPyPI
  uses: pypa/gh-action-pypi-publish@release/v1
  with:
    repository-url: https://test.pypi.org/legacy/

# To:
- name: Publish to TestPyPI
  uses: pypa/gh-action-pypi-publish@release/v1
  with:
    repository-url: https://test.pypi.org/legacy/
    password: ${{ secrets.TEST_PYPI_API_TOKEN }}

# For PyPI job, change from:
- name: Publish to PyPI
  uses: pypa/gh-action-pypi-publish@release/v1

# To:
- name: Publish to PyPI
  uses: pypa/gh-action-pypi-publish@release/v1
  with:
    password: ${{ secrets.PYPI_API_TOKEN }}
```

---

## 🚀 Usage

### Automatic Publishing (Recommended)

Every time you bump the version in `src/yavs/__init__.py` and push to main:

```bash
# 1. Update version
vim src/yavs/__init__.py
# Change: __version__ = "1.0.0" → "1.0.1"

# 2. Update CHANGELOG.md
vim CHANGELOG.md
# Add section for 1.0.1

# 3. Commit and push
git add src/yavs/__init__.py CHANGELOG.md
git commit -m "chore: bump version to 1.0.1"
git push origin main

# 4. Workflow automatically:
#    ✓ Detects version change
#    ✓ Runs tests
#    ✓ Builds package
#    ✓ Publishes to TestPyPI
#    ✓ Publishes to PyPI
#    ✓ Creates GitHub release
#    ✓ Adds git tag v1.0.1
```

### Manual Publishing

Trigger workflow manually with a button click:

1. Go to Actions → "Publish to PyPI"
2. Click "Run workflow"
3. Select branch (usually `main`)
4. Optionally check "Skip tests" (not recommended)
5. Click "Run workflow"

### Version Bumping Helper Script

Create `scripts/bump-version.sh`:

```bash
#!/bin/bash
set -e

if [ -z "$1" ]; then
  echo "Usage: $0 <new-version>"
  echo "Example: $0 1.0.1"
  exit 1
fi

NEW_VERSION="$1"
OLD_VERSION=$(grep '__version__' src/yavs/__init__.py | cut -d'"' -f2)

echo "Bumping version: $OLD_VERSION → $NEW_VERSION"

# Update __init__.py
sed -i '' "s/__version__ = \"$OLD_VERSION\"/__version__ = \"$NEW_VERSION\"/" src/yavs/__init__.py

# Update CHANGELOG.md (add placeholder)
sed -i '' "7i\\
## [$NEW_VERSION] - $(date +%Y-%m-%d)\\
\\
### Changed\\
- Version bump to $NEW_VERSION\\
\\
" CHANGELOG.md

echo "✓ Updated src/yavs/__init__.py"
echo "✓ Updated CHANGELOG.md"
echo ""
echo "Next steps:"
echo "1. Edit CHANGELOG.md to add proper release notes"
echo "2. git add src/yavs/__init__.py CHANGELOG.md"
echo "3. git commit -m 'chore: bump version to $NEW_VERSION'"
echo "4. git push origin main"
```

Usage:
```bash
chmod +x scripts/bump-version.sh
./scripts/bump-version.sh 1.0.1
```

---

## 🔍 Monitoring & Verification

### Watch the Workflow

```bash
# View workflow runs
gh run list --workflow=pypi-publish.yml

# Watch live logs
gh run watch
```

### Verify Publication

```bash
# Check TestPyPI
curl -s https://test.pypi.org/pypi/yavs/json | jq -r '.info.version'

# Check PyPI
curl -s https://pypi.org/pypi/yavs/json | jq -r '.info.version'

# Test installation
python -m venv test-env
source test-env/bin/activate
pip install yavs==1.0.1
yavs version
```

### Check GitHub Release

```bash
# List releases
gh release list

# View specific release
gh release view v1.0.1
```

---

## 🛡️ Safety Features

### 1. Version Change Detection
- Only publishes when `__version__` actually changes
- Prevents accidental re-publishing

### 2. Multi-Environment Testing
- Tests on Python 3.10, 3.11, 3.12
- Must pass all tests before publishing

### 3. Staging Environment
- Publishes to TestPyPI first
- Validates installation from TestPyPI
- Only then proceeds to production PyPI

### 4. Manual Approval (Optional)
- Configure `pypi` environment to require approval
- Reviewer must approve before production publish

### 5. Skip on Non-Version Changes
- Won't trigger on README edits
- Won't trigger on documentation changes
- Only triggers on `src/yavs/__init__.py` or `pyproject.toml` changes

---

## 🐛 Troubleshooting

### "No files found to upload"

**Cause**: Build step failed or no dist/ directory
**Fix**: Check build logs, ensure `pyproject.toml` is valid

```bash
# Test build locally
python -m build
ls -l dist/
```

### "File already exists on PyPI"

**Cause**: Trying to publish same version twice
**Fix**: PyPI doesn't allow overwriting. Bump version:

```bash
# Increment patch version
./scripts/bump-version.sh 1.0.2
```

### "Trusted publishing failed"

**Cause**: OIDC configuration mismatch
**Fix**: Verify PyPI trusted publisher settings match exactly:
- Owner name
- Repo name
- Workflow file name
- Environment name

### Tests Failing

**Cause**: Code changes broke tests
**Fix**: Fix tests before merging to main

```bash
# Run tests locally
make test

# Or directly
pytest tests/ -v
```

### "Permission denied" on GitHub Release

**Cause**: Missing `contents: write` permission
**Fix**: Already configured in workflow, check repo settings

---

## 📋 Pre-Flight Checklist

Before your first publish:

- [ ] Claimed package name on PyPI (`yavs`)
- [ ] Claimed package name on TestPyPI (`yavs`)
- [ ] Configured trusted publishing or API tokens
- [ ] Created GitHub environments (`pypi`, `testpypi`)
- [ ] Set up environment protection rules (optional)
- [ ] Tested workflow with a patch version bump
- [ ] Verified installation from PyPI works
- [ ] GitHub releases working correctly

---

## 🔄 Release Workflow

### For Patch Releases (1.0.0 → 1.0.1)

```bash
# Bug fixes, small improvements
./scripts/bump-version.sh 1.0.1
# Edit CHANGELOG.md
git add src/yavs/__init__.py CHANGELOG.md
git commit -m "chore: release v1.0.1"
git push origin main
```

### For Minor Releases (1.0.0 → 1.1.0)

```bash
# New features, backward compatible
./scripts/bump-version.sh 1.1.0
# Edit CHANGELOG.md with feature list
git add src/yavs/__init__.py CHANGELOG.md
git commit -m "feat: release v1.1.0 with new features"
git push origin main
```

### For Major Releases (1.0.0 → 2.0.0)

```bash
# Breaking changes
./scripts/bump-version.sh 2.0.0
# Edit CHANGELOG.md with migration guide
git add src/yavs/__init__.py CHANGELOG.md
git commit -m "feat!: release v2.0.0 (breaking changes)"
git push origin main

# Announce breaking changes in discussions
gh issue create --title "v2.0.0 Released - Breaking Changes" \
  --body "See CHANGELOG.md for migration guide"
```

---

## 📊 Post-Release Monitoring

### First 24 Hours

```bash
# Monitor download stats
pip install pypistats
pypistats recent yavs

# Check for issues
gh issue list --label "bug"

# Monitor discussions
gh browse /discussions
```

### Weekly Stats

```bash
# Download statistics
pypistats overall yavs

# Version distribution
pypistats python_minor yavs

# System distribution
pypistats system yavs
```

---

## 🎓 Best Practices

1. **Always Update CHANGELOG.md** - Users need to know what changed
2. **Semantic Versioning** - Follow semver.org strictly
3. **Test Locally First** - `make test && make build`
4. **Small Increments** - Release often, release small
5. **Monitor After Release** - Check for issues in first hour
6. **Communicate Breaking Changes** - Give users advance notice
7. **Keep Dependencies Updated** - Regular `pip list --outdated`

---

## 📚 Additional Resources

- [PyPI Trusted Publishing Guide](https://docs.pypi.org/trusted-publishers/)
- [GitHub Actions Publishing](https://packaging.python.org/en/latest/guides/publishing-package-distribution-releases-using-github-actions-ci-cd-workflows/)
- [Semantic Versioning](https://semver.org/)
- [Keep a Changelog](https://keepachangelog.com/)

---

**Ready to publish!** 🚀
