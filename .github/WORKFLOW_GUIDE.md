# 🔄 DockerScan CI/CD Workflow Guide

## Overview

DockerScan uses a **unified manual-trigger workflow** that gives you complete control over CI/CD operations.

## 🎯 How to Use

### 1. Navigate to Actions

1. Go to your GitHub repository
2. Click on the **Actions** tab
3. Select **DockerScan CI/CD** from the workflows list

### 2. Run Workflow

Click the **Run workflow** button and configure:

```
┌─────────────────────────────────────────────┐
│ Run workflow                                │
├─────────────────────────────────────────────┤
│ Branch: main                        [▼]     │
│                                             │
│ ☑ Run tests                    [default: ✓]│
│ ☑ Build binaries              [default: ✓]│
│ ☐ Create GitHub release       [default: ✗]│
│ Release version (e.g., v2.0.0): [_______]  │
│ ☐ Run security scan           [default: ✗]│
│                                             │
│              [Run workflow]                 │
└─────────────────────────────────────────────┘
```

## 📋 Configuration Options

### Run Tests
- **Default**: ✅ Enabled
- **What it does**:
  - Runs full test suite with coverage
  - Executes `go vet` static analysis
  - Runs `staticcheck` linter
  - Uploads coverage to Codecov
- **When to disable**: Never (always run tests!)

### Build Binaries
- **Default**: ✅ Enabled
- **What it does**:
  - Compiles for 9 platforms:
    * Linux: amd64, arm64, 386
    * macOS: amd64, arm64
    * Windows: amd64, arm64, 386
    * FreeBSD: amd64
  - Generates SHA256 checksums
  - Uploads artifacts (30-day retention)
- **When to disable**: Testing-only runs

### Create GitHub Release
- **Default**: ❌ Disabled
- **What it does**:
  - Creates a GitHub release
  - Uploads all binaries
  - Generates professional release notes
  - Updates 'latest' tag
- **Requirements**:
  - ✅ Must provide release version (e.g., v2.0.0)
  - ✅ Tests must pass
  - ✅ Binaries must build successfully
- **When to enable**: Making an official release

### Release Version
- **Default**: Empty
- **Format**: `v2.0.0`, `v2.1.0-beta`, etc.
- **Required**: Only if "Create GitHub release" is enabled
- **Used for**: Version in binaries and release tag

### Run Security Scan
- **Default**: ❌ Disabled
- **What it does**:
  - Runs CodeQL security analysis
  - Detects vulnerabilities
  - Creates security alerts
- **When to enable**: Weekly/monthly security checks

## 🎬 Common Scenarios

### Scenario 1: Development Testing
**Goal**: Test code changes

```yaml
✅ Run tests: Yes
✅ Build binaries: Yes
❌ Create release: No
❌ Security scan: No
```

**Result**:
- Tests run
- Binaries built and available as artifacts
- No release created

---

### Scenario 2: Create Release
**Goal**: Publish new version

```yaml
✅ Run tests: Yes
✅ Build binaries: Yes
✅ Create release: Yes
Release version: v2.1.0
❌ Security scan: No
```

**Result**:
- Tests run
- Binaries built for all platforms
- GitHub release created at `/releases/tag/v2.1.0`
- Binaries uploaded to release
- Release notes auto-generated

---

### Scenario 3: Security Audit
**Goal**: Check for vulnerabilities

```yaml
✅ Run tests: Yes
❌ Build binaries: No
❌ Create release: No
✅ Security scan: Yes
```

**Result**:
- Tests run
- CodeQL security analysis performed
- Security alerts generated if issues found

---

### Scenario 4: Full Pipeline
**Goal**: Everything

```yaml
✅ Run tests: Yes
✅ Build binaries: Yes
✅ Create release: Yes
Release version: v2.0.0
✅ Security scan: Yes
```

**Result**:
- Complete CI/CD pipeline
- All checks performed
- Release published
- Security verified

## 📊 Workflow Jobs

The workflow consists of 5 jobs that run conditionally:

```
┌──────────────┐
│    Test      │ ← Always runs if enabled
└──────┬───────┘
       │
       ▼
┌──────────────┐
│    Build     │ ← Runs after tests (if enabled)
└──────┬───────┘
       │
       ├─────────────────┐
       │                 │
       ▼                 ▼
┌──────────────┐  ┌──────────────┐
│   Security   │  │   Release    │ ← Conditional
└──────────────┘  └──────┬───────┘
                         │
                         ▼
                  ┌──────────────┐
                  │   Summary    │ ← Always runs
                  └──────────────┘
```

### Job Dependencies:
- **Build** requires **Test** to pass
- **Release** requires **Test** and **Build** to pass
- **Security** runs independently
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
| Tests | ✅ Success |
| Build | ✅ Success |
| Security Scan | ⏭️ Skipped |
| Release | ✅ Success |

## 🎉 Release Information

**Version**: v2.0.0

**Download**: https://github.com/cr0hn/dockerscan/releases/tag/v2.0.0

## ⚙️ Configuration

- Run Tests: true
- Build Binaries: true
- Create Release: true
- Security Scan: false
```

## 🚀 Best Practices

### For Development
1. **Always run tests** before merging
2. **Build binaries** to ensure cross-platform compatibility
3. **Don't create releases** from feature branches

### For Releases
1. **Create release from main** branch only
2. **Use semantic versioning**: `v2.0.0`, `v2.1.0`, `v2.1.1`
3. **Run security scan** before major releases
4. **Test the binaries** before publishing

### For Security
1. **Run security scans** weekly or after dependency updates
2. **Review CodeQL alerts** in Security tab
3. **Keep Go version updated** in workflow

## 🔧 Troubleshooting

### Build Fails
- Check Go syntax errors in code
- Verify all dependencies are in `go.mod`
- Check if tests pass first

### Release Fails
- Ensure version format is correct (`v2.0.0`)
- Check if tag already exists
- Verify GitHub token has write permissions

### Artifacts Missing
- Check if build job completed successfully
- Artifacts expire after 30 days
- Download before expiration

## 📞 Support

- **Issues**: https://github.com/cr0hn/dockerscan/issues
- **Author**: Daniel Garcia (cr0hn)
- **Website**: https://cr0hn.com

---

**Making Docker Security Accessible to Everyone** 🐋🔒
