# Repository settings checklist

These settings live in GitHub's repository UI; a file in the repository cannot switch them on by itself.

## About

**Description**

> A local-first Rust SAST tool that scans source code and configuration files for security-sensitive patterns and exports SARIF.

**Suggested topics**

`rust`, `security`, `sast`, `static-analysis`, `application-security`, `cli`, `sarif`, `devsecops`, `code-scanning`

## Apply repository metadata with GitHub CLI

After pushing this version, run this once from a terminal where `gh auth status` succeeds:

```bash
gh repo edit abduforge/FerroScout \
  --description "A local-first Rust SAST scanner with heuristic security rules and SARIF reports." \
  --add-topic rust \
  --add-topic security \
  --add-topic sast \
  --add-topic static-analysis \
  --add-topic application-security \
  --add-topic cli \
  --add-topic sarif \
  --add-topic devsecops \
  --enable-discussions \
  --enable-issues \
  --enable-projects \
  --enable-wiki
```

GitHub CLI exposes repository descriptions, topics, and feature toggles through `gh repo edit`; see the [official command reference](https://cli.github.com/manual/gh_repo_edit).

## Features

- Keep **Issues** enabled: bug reports and feature requests use the forms in `.github/ISSUE_TEMPLATE/`.
- Keep **Pull requests** enabled: reviews use `.github/PULL_REQUEST_TEMPLATE.md` and `.github/CODEOWNERS`.
- Enable **Discussions** for usage questions and design ideas. The templates in `.github/DISCUSSION_TEMPLATE/` provide Q&A and idea forms. Suggested categories: Announcements, Q&A, Ideas.
- Wiki is optional; the README files and `CONTRIBUTING.md` are the maintained documentation.
- Projects are optional; use a board only when there is an active roadmap to maintain.

## Security

- Check **Settings → Security → Code security and analysis** and enable code scanning if it is available for this repository. `.github/workflows/code-scanning.yml` uploads FerroScout's SARIF output.
- Enable private vulnerability reporting if available. `SECURITY.md` links to GitHub's private reporting page.
- Enable secret scanning and push protection if available for this repository. GitHub may restrict these switches by repository type or plan.
- Keep Dependabot alerts and security updates enabled where available. `.github/dependabot.yml` also opens version-update pull requests for Cargo and GitHub Actions.

Optional secret-protection switches through GitHub CLI:

```bash
gh repo edit abduforge/FerroScout \
  --enable-secret-scanning \
  --enable-secret-scanning-push-protection
```


## Releases

Create a release by pushing a version tag that matches `Cargo.toml`, for example `v0.2.0`. `.github/workflows/release.yml` tests the tag, builds a Linux x86_64 binary, creates a `.tar.gz` archive, and attaches its SHA-256 checksum.
