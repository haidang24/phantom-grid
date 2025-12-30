# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Open-source project structure with CONTRIBUTING.md, CODE_OF_CONDUCT.md, SECURITY.md
- GitHub Actions CI pipeline for automated testing and linting
- Issue and pull request templates
- CHANGELOG.md for version tracking
- Organized documentation in `docs/` directory
- Build output directory (`bin/`) for cleaner project structure

### Changed
- Improved Makefile with better clean targets and build organization
- Updated .gitignore patterns for correct eBPF generated file paths
- Standardized project structure documentation in README

### Fixed
- Corrected .gitignore patterns for generated eBPF files location
- Removed broken debug target from Makefile
- Fixed project structure documentation to match actual layout

## [0.1.0] - 2025-01-XX

### Added
- Initial release of Phantom Grid
- eBPF-powered XDP program for kernel-level packet filtering
- Single Packet Authorization (SPA) mechanism
- Honeypot with fake service emulation
- Real-time forensics dashboard
- OS fingerprint mutation
- Egress DLP (Data Loss Prevention)
- Stealth scan detection

---

## Release Notes Format

- **Added** for new features
- **Changed** for changes in existing functionality
- **Deprecated** for soon-to-be removed features
- **Removed** for now removed features
- **Fixed** for any bug fixes
- **Security** for vulnerability fixes

