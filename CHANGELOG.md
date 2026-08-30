# Changelog

All notable changes to Fleet Audit are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases use [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-08-30

### Added

- `collect --dry-run` executes collection, optional policy evaluation and schema
  validation without publishing a snapshot.
- Release documentation now includes the data flow, pipx installation, real
  terminal output and explicit output-format boundaries.

### Changed

- Synthetic-data guidance no longer names previous employers.

## [0.1.0] - 2026-08-30

Initial alpha release.

### Added

- A read-only Linux inventory command covering platform, hardware, storage, privacy-safe network exposure, packages, services and maintenance state.
- Versioned JSON snapshots validated against a packaged JSON Schema.
- Explicit partial-result and capability reporting for missing commands, permission failures, timeouts and bounded-output failures.
- TOML policy evaluation for filesystem utilisation, pending updates, maximum uptime, required services and prohibited listening ports.
- Semantic snapshot comparison with text and JSON output, deterministic ordering and optional CI failure on material change.
- Privacy tests and schema restrictions that exclude hostnames, usernames, addresses, hardware identifiers, credentials and arbitrary host content.
- Synthetic snapshots for an offline validation and comparison demonstration.
- Automated Python and shell checks on GitHub Actions.

### Security

- Collection requires no root privileges, never invokes `sudo` and performs no remediation or network requests.
- Temporary workspaces and published snapshots use owner-only permissions.
- Collector execution uses fixed paths, timeouts, output limits and fail-closed snapshot validation.

### Known limitations

- Live collection targets Ubuntu 22.04 and 24.04; Debian 12 is a secondary compatibility target.
- Disposable minimal-container checks verify OS userland behaviour and graceful degradation, not the complete network and service paths of representative systemd hosts.
- Package update counts depend on the host's existing APT metadata because collection never refreshes package indexes.
- The release provides terminal and JSON comparison output only. It does not include CSV, HTML, a hosted service, remote collection or automatic remediation.
- This alpha release has not been validated as a production fleet, compliance or vulnerability-management system.

[0.1.1]: https://github.com/ericjaytech/fleet-audit/releases/tag/v0.1.1
[0.1.0]: https://github.com/ericjaytech/fleet-audit/releases/tag/v0.1.0
