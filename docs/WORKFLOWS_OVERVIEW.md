# YAVS GitHub Actions Workflows - Visual Overview

## 🎯 Workflow Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     YAVS CI/CD Pipeline                         │
└─────────────────────────────────────────────────────────────────┘

    Development Flow                    Security Gates
    ────────────────                   ──────────────

    📝 Code Change                     🔒 Security Check
         │                                    │
         ├─► PR Created ────────┐            │
         │                      │            │
         └─► Push to Branch ────┼───────────►│
                                │            │
                   ┌────────────┘            │
                   │                         │
                   ▼                         ▼
           ┌────────────────┐       ┌────────────────┐
           │ security-scan  │       │ dependency-scan│
           │  .yml          │       │    .yml        │
           │                │       │                │
           │ • All scanners │       │ • Trivy only   │
           │ • AI summary   │       │ • Fast (<2min) │
           │ • PR comments  │       │ • Dep files    │
           └────────────────┘       └────────────────┘
                   │                         │
                   └─────────┬───────────────┘
                             │
                             ▼
                     ✅ Merge Approved


    Continuous Monitoring              Release Pipeline
    ────────────────────              ────────────────

    ⏰ Cron Schedule                   🏷️ Version Tag
         │                                   │
         ▼                                   ▼
    ┌────────────────┐              ┌────────────────┐
    │ scheduled-scan │              │ release-scan   │
    │    .yml        │              │    .yml        │
    │                │              │                │
    │ • Daily 2 AM   │              │ • Pre-release  │
    │ • New CVEs     │              │ • Blocks if ❌ │
    │ • Auto issues  │              │ • Attaches to  │
    │ • Slack notify │              │   GitHub rel   │
    └────────────────┘              └────────────────┘
         │                                   │
         ▼                                   ▼
    📊 Weekly Report              🚀 Production Deploy


    Deep Analysis                    Environment Gates
    ────────────                    ─────────────────

    🎯 Manual Trigger                🌍 Env-Specific
         │                                  │
         ▼                                  ▼
    ┌────────────────┐           ┌──────────────────┐
    │comprehensive   │           │multi-environment │
    │  -scan.yml     │           │  -scan.yml       │
    │                │           │                  │
    │ • Full reports │           │ • Dev policy     │
    │ • Statistics   │           │ • Staging gate   │
    │ • AI triage    │           │ • Prod strict    │
    │ • Top 10 list  │           │ • Env thresholds │
    └────────────────┘           └──────────────────┘
         │                                  │
         ▼                                  ▼
    📈 Management Review         🎚️ Policy Enforcement
```

---

## 📊 Workflow Comparison Matrix

```
┌──────────────────────┬─────────┬──────────┬─────────┬────────────┬──────────────┐
│ Workflow             │ Speed   │ Coverage │ AI      │ Frequency  │ Exit on Fail │
├──────────────────────┼─────────┼──────────┼─────────┼────────────┼──────────────┤
│ security-scan        │ ⚡⚡ 3min│ Full     │ ✅ Yes  │ Every PR   │ ❌ No        │
│ scheduled-scan       │ ⚡⚡ 3min│ Full     │ ✅ Yes  │ Daily      │ ❌ No        │
│ release-scan         │ ⚡  5min│ Full     │ ✅ Yes  │ On tag     │ ✅ Yes       │
│ dependency-scan      │ ⚡⚡⚡ 1m │ Deps     │ ✅ Yes  │ Dep change │ ✅ Yes*      │
│ comprehensive-scan   │ ⚡  10m │ Full+    │ ✅ Yes  │ Weekly     │ ❌ No        │
│ multi-environment    │ ⚡⚡ 4min│ Full     │ 🔄 Env  │ Per deploy │ 🔄 Env**     │
│ yavs-self-scan       │ ⚡⚡ 2min│ Full     │ ❌ No   │ Every push │ ✅ Yes***    │
└──────────────────────┴─────────┴──────────┴─────────┴────────────┴──────────────┘

*   Only on CRITICAL vulnerabilities
**  Depends on environment policy
*** Only on CRITICAL in YAVS codebase itself
```

---

## 🔄 Typical CI/CD Flow

```
Developer Workflow:
──────────────────

1. Developer commits code
        │
        ▼
2. dependency-scan.yml (if deps changed)
   ⚡ 1 minute check
        │
        ├─► ✅ Pass → Continue
        └─► ❌ Fail → Fix critical deps
                │
                ▼
3. security-scan.yml (on PR)
   ⚡ 3 minute full scan
        │
        ├─► Posts results to PR
        ├─► Uploads SARIF
        └─► Adds AI summary
                │
                ▼
4. Review & Merge
        │
        ▼
5. Merge to main
        │
        ▼
6. Scheduled nightly scan
   (catch new CVEs)


Release Workflow:
────────────────

1. Tag version (v1.0.0)
        │
        ▼
2. release-scan.yml
   ⚡ 5 minute pre-release check
        │
        ├─► ✅ Pass → Create release
        │            + Attach reports
        │
        └─► ❌ Fail → Block release
                     + Notify team


Weekly Review:
─────────────

1. Every Monday 9 AM
        │
        ▼
2. comprehensive-scan.yml
   ⚡ 10 minute deep analysis
        │
        ├─► Generate reports
        ├─► Create statistics
        ├─► AI triage
        └─► Create issue if needed
                │
                ▼
3. Security team reviews
```

---

## 🎨 Workflow Features Map

```
                        ┌─────────────────────────┐
                        │   Common Features       │
                        │   (All Workflows)       │
                        ├─────────────────────────┤
                        │ ✅ SARIF upload         │
                        │ ✅ Artifact storage     │
                        │ ✅ Error handling       │
                        │ ✅ Caching             │
                        └──────────┬──────────────┘
                                   │
        ┌──────────────────────────┼──────────────────────────┐
        │                          │                          │
        ▼                          ▼                          ▼
┌────────────────┐        ┌────────────────┐        ┌────────────────┐
│ PR/Push Tools  │        │  Monitoring    │        │  Reporting     │
├────────────────┤        ├────────────────┤        ├────────────────┤
│ • PR comments  │        │ • Issue create │        │ • Statistics   │
│ • Status checks│        │ • Slack notify │        │ • AI analysis  │
│ • Inline notes │        │ • Trend track  │        │ • Top 10 list  │
└────────────────┘        └────────────────┘        └────────────────┘

        ▼                          ▼                          ▼
┌────────────────┐        ┌────────────────┐        ┌────────────────┐
│ Used by:       │        │ Used by:       │        │ Used by:       │
│ • security-    │        │ • scheduled-   │        │ • comprehensive│
│   scan         │        │   scan         │        │   -scan        │
│ • dependency-  │        │ • multi-env    │        │ • release-scan │
│   scan         │        │                │        │                │
└────────────────┘        └────────────────┘        └────────────────┘
```

---

## 🚦 Security Policy Enforcement

```
Environment-Specific Thresholds:
────────────────────────────────

Production    Staging       Development
──────────   ──────────    ────────────
CRITICAL  ❌  CRITICAL  ❌  CRITICAL  ⚠️
HIGH      ❌  HIGH      ⚠️  HIGH      ✅
MEDIUM    ⚠️  MEDIUM    ✅  MEDIUM    ✅
LOW       ✅  LOW       ✅  LOW       ✅

Legend:
  ❌ = Blocks deployment
  ⚠️ = Warning (review required)
  ✅ = Informational only


Severity-Based Actions:
───────────────────────

CRITICAL findings:
  → Block all environments (except dev)
  → Create P0 issue
  → Notify security team
  → Require immediate fix

HIGH findings:
  → Block production
  → Warn on staging
  → Track in dev
  → AI fix suggestions

MEDIUM findings:
  → Warn on production
  → Info on staging/dev
  → Group by root cause

LOW findings:
  → Informational
  → Trend tracking
  → Technical debt
```

---

## 📈 Integration Points

```
┌─────────────────────────────────────────────────────┐
│              External Integrations                  │
└─────────────────────────────────────────────────────┘

    GitHub Security                 Notifications
    ───────────────                ─────────────

    • Code Scanning tab            • Slack webhooks
    • Security advisories          • Email (via Actions)
    • Dependabot alerts            • PagerDuty (custom)
    • Secret scanning              • Teams (custom)
         │                              │
         └────────┬─────────────────────┘
                  │
                  ▼
          ┌──────────────┐
          │     YAVS     │
          │   Workflows  │
          └──────────────┘
                  │
         ┌────────┴────────┐
         │                 │
         ▼                 ▼
    Artifacts          CI/CD Tools
    ─────────         ───────────

    • JSON reports     • GitHub Actions
    • SARIF files      • Jenkins (export)
    • AI summaries     • GitLab CI (adapt)
    • Statistics       • CircleCI (adapt)
```

---

## 🎯 Quick Start Recommendations

### Minimal Setup (Start Here)
```yaml
1. security-scan.yml        # PR checks
2. scheduled-scan.yml       # Daily monitoring
```

### Standard Setup (Recommended)
```yaml
1. security-scan.yml        # PR checks
2. dependency-scan.yml      # Fast dep checks
3. scheduled-scan.yml       # Daily monitoring
4. release-scan.yml         # Release gate
```

### Enterprise Setup (Full Featured)
```yaml
1. security-scan.yml        # PR checks
2. dependency-scan.yml      # Fast dep checks
3. scheduled-scan.yml       # Daily monitoring
4. release-scan.yml         # Release gate
5. comprehensive-scan.yml   # Weekly reviews
6. multi-environment-scan.yml # Env policies
```

---

## 📝 Configuration Requirements

```
Required Secrets:
────────────────
None (minimal functionality)

Optional Secrets (for full features):
─────────────────────────────────────
• ANTHROPIC_API_KEY     → AI-powered analysis
• SLACK_WEBHOOK_URL     → Slack notifications
• GITHUB_TOKEN          → (Auto-provided by Actions)

Permissions Required:
────────────────────
• contents: read        → Read repository
• security-events: write → Upload SARIF
• issues: write         → Create issues
• pull-requests: write  → Comment on PRs
```

---

For detailed setup instructions, see the [Workflows README](.github/workflows/README.md).
