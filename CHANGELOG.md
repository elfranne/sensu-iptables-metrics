# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic
Versioning](http://semver.org/spec/v2.0.0.html).

## Unreleased

### Added
- CI now runs `go vet`, builds, and runs the tests with `-race` plus a coverage summary.
- Workflows declare least-privilege `permissions` and cancel superseded runs via a
  `concurrency` group. Test and lint also run on `pull_request` and `workflow_dispatch`.

### Changed
- The release workflow checks out with `fetch-depth: 0` instead of running
  `git fetch --prune --unshallow`, which errors when the checkout is already complete. It also
  runs the tests before releasing.
- Pinned `golangci-lint` to v2.13 so a lint release cannot break CI unannounced.
- The test workflow no longer runs on macOS and Windows; the plugin is Linux-only.

## [0.0.1] - 2000-01-01

### Added
- Initial release
