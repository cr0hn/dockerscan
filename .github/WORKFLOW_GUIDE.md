# 🔄 DockerScan CI/CD Workflow Guide

## Overview

DockerScan uses a **simple manual-trigger workflow** for releases. Just provide a version tag and everything runs automatically.

## 🎯 How to Use

### 1. Navigate to Actions

1. Go to your GitHub repository
2. Click on the **Actions** tab
3. Select **DockerScan CI/CD** from the workflows list

### 2. Run Workflow

Click the **Run workflow** button and enter the version:

```
┌─────────────────────────────────────────────┐
│ Run workflow                                │
├─────────────────────────────────────────────┤
│ Branch: main                        [▼]     │
│                                             │
│ Release version (e.g., v2.0.0): [v2.0.0]   │
│                                             │
│              [Run workflow]                 │
└─────────────────────────────────────────────┘
```

That's it! The workflow will automatically:
- ✅ Run all tests with full coverage
- ✅ Build binaries for 9 platforms
- ✅ Create the git tag
- ✅ Create the GitHub release
- ✅ Upload all binaries to the release
- ✅ Generate professional release notes

## 📋 What Happens Automatically

### Step 1: Tests (Always)
- Runs full test suite with coverage
- Executes `go vet` static analysis
- Runs `staticcheck` linter
- Uploads coverage to Codecov
- **If tests fail, workflow stops**

### Step 2: Build (After tests pass)
- Compiles for 9 platforms:
  * Linux: amd64, arm64, 386
  * macOS: amd64, arm64
  * Windows: amd64, arm64, 386
  * FreeBSD: amd64
- Generates SHA256 checksums
- Uploads artifacts (30-day retention)

### Step 3: Release (After build succeeds)
- **Creates git tag** (e.g., `v2.0.0`)
- Creates GitHub release
- Uploads all binaries
- Generates professional release notes with:
  - Installation instructions
  - Feature list
  - Security coverage details
  - Usage examples
  - Download links
- Updates 'latest' tag

### Step 4: Summary (Always)
- Shows status of all jobs
- Provides download link
- Displays workflow results

## 🎬 Example Usage

### Creating Release v2.0.0

1. Go to Actions → DockerScan CI/CD
2. Click "Run workflow"
3. Enter version: `v2.0.0`
4. Click "Run workflow"

**Result**:
- Tests run ✅
- Binaries built for all platforms ✅
- Tag `v2.0.0` created ✅
- GitHub release created at `/releases/tag/v2.0.0` ✅
- Binaries uploaded to release ✅
- Release notes auto-generated ✅

### Creating Beta Release

1. Go to Actions → DockerScan CI/CD
2. Click "Run workflow"
3. Enter version: `v2.1.0-beta`
4. Click "Run workflow"

**Result**: Same as above, but marked as pre-release

## 📊 Workflow Jobs

The workflow consists of 4 jobs that run sequentially:

```
┌──────────────┐
│    Test      │ ← Runs all tests
└──────┬───────┘
       │
       ▼
┌──────────────┐
│    Build     │ ← Builds binaries (9 platforms)
└──────┬───────┘
       │
       ▼
┌──────────────┐
│   Release    │ ← Creates tag + release
└──────┬───────┘
       │
       ▼
┌──────────────┐
│   Summary    │ ← Shows results
└──────────────┘
```

### Job Dependencies:
- **Build** requires **Test** to pass
- **Release** requires **Test** and **Build** to pass
- **Summary** always runs (even on failure)

## 🎯 Artifacts

After a successful build, artifacts are available for 30 days:

**Location**: Actions → Workflow run → Artifacts section

**Contents**:
```
dockerscan-binaries-{version}/
├── dockerscan-linux-amd64
├── dockerscan-linux-arm64
├── dockerscan-linux-386
├── dockerscan-darwin-amd64
├── dockerscan-darwin-arm64
├── dockerscan-windows-amd64.exe
├── dockerscan-windows-arm64.exe
├── dockerscan-windows-386.exe
├── dockerscan-freebsd-amd64
└── checksums.txt
```

## 📝 Workflow Summary

After each run, check the **Summary** tab:

```markdown
# 🐋 DockerScan CI/CD Summary

By Daniel Garcia (cr0hn) | https://cr0hn.com

## Workflow Results

| Job | Status |
|-----|--------|
| Tests | success |
| Build | success |
| Release | success |

## 🎉 Release Information

**Version**: v2.0.0

**Download**: https://github.com/cr0hn/dockerscan/releases/tag/v2.0.0
```

## 🚀 Best Practices

### Version Naming
1. **Use semantic versioning**: `v2.0.0`, `v2.1.0`, `v2.1.1`
2. **Major releases**: `v2.0.0`, `v3.0.0` (breaking changes)
3. **Minor releases**: `v2.1.0`, `v2.2.0` (new features)
4. **Patch releases**: `v2.0.1`, `v2.0.2` (bug fixes)
5. **Pre-releases**: `v2.1.0-beta`, `v2.1.0-rc1`, `v2.1.0-alpha`

### Release Checklist
- [ ] Update version in code if needed
- [ ] Update CHANGELOG.md
- [ ] Merge all changes to main
- [ ] Run workflow with version tag
- [ ] Verify release page looks correct
- [ ] Test downloaded binaries
- [ ] Announce release

### For Development Testing
If you just want to test without creating a release:
- Clone the repo
- Run `make test` locally
- Run `make build-all` to build for all platforms
- Artifacts will be in `dockerscan-v2/bin/`

## 🔧 Troubleshooting

### Tests Fail
- Check the test output in the workflow logs
- Run `make test` locally to reproduce
- Fix the failing tests
- Push the fix and re-run workflow

### Build Fails
- Check Go syntax errors in code
- Verify all dependencies are in `go.mod`
- Run `make build-all` locally to test
- Check platform-specific issues

### Release Fails
- **Tag already exists**: Delete the tag first or use a new version
  ```bash
  git tag -d v2.0.0
  git push origin :refs/tags/v2.0.0
  ```
- **Permission denied**: Check GitHub token has write permissions
- **Missing artifacts**: Build job must complete successfully first

### Artifacts Missing
- Check if build job completed successfully
- Artifacts expire after 30 days
- Download from the release page instead

## 🔐 Security

The workflow has minimal permissions:
- `contents: write` - Required to create releases and tags
- `security-events: write` - For future security scanning integration

The workflow uses:
- Official GitHub Actions (checkout@v4, setup-go@v5)
- Trusted third-party actions (softprops/action-gh-release@v1)

## 📞 Support

- **Issues**: https://github.com/cr0hn/dockerscan/issues
- **Author**: Daniel Garcia (cr0hn)
- **Website**: https://cr0hn.com

---

**Making Docker Security Accessible to Everyone** 🐋🔒
