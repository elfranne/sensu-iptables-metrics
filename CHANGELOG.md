# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## Unreleased

## [0.3.1] - 2025-01-13

### Changed
- Updated Go toolchain to 1.23.4 and refreshed all module dependencies.

## [0.3] - 2024-09-16

### Changed
- Updated Go toolchain to 1.23.1.
- Release workflow: bumped `actions/checkout` to v4, `actions/setup-go` to v5 and
  `goreleaser/goreleaser-action` to v6, and replaced the removed `--rm-dist` flag with `--clean`.
- Release workflow can now be started manually via `workflow_dispatch`.

## [0.2.0] - 2024-04-15

### Fixed
- Rule-matching regex now anchors on `\s*` instead of `\s+`, so the first rule of a chain is no
  longer skipped when its packet counter starts at the beginning of the line.
- Plugin identified itself as `check-cpu-usage` — a leftover from the check-plugin-template it was
  generated from. It now reports as `metrics-iptables`, with the keyspace
  `sensu.io/plugins/metrics-iptables/config`.
- Corrected a typo in the `--ftype` usage string.

### Changed
- Updated Go toolchain to 1.21 and refreshed dependencies.

## [0.1.1] - 2023-07-11

### Changed
- Dropped the macOS and Windows builds from the Bonsai asset definition; iptables is Linux-only.

## [0.1.0]

### Added
- Initial release: collects packet and byte counters from iptables rules tagged with a
  `/* <id> <name> */` comment and emits them as Graphite plaintext metrics.

[0.3.1]: https://github.com/elfranne/sensu-iptables-metrics/releases/tag/0.3.1
[0.3]: https://github.com/elfranne/sensu-iptables-metrics/releases/tag/0.3
[0.2.0]: https://github.com/elfranne/sensu-iptables-metrics/releases/tag/0.2.0
[0.1.1]: https://github.com/elfranne/sensu-iptables-metrics/releases/tag/0.1.1
