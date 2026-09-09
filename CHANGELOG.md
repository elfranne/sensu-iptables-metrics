# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## Unreleased

### Added
- CI now runs `go vet`, builds, and runs the tests with `-race` plus a coverage summary.
- Workflows declare least-privilege `permissions` and cancel superseded runs via a
  `concurrency` group. Test and lint also run on `pull_request` and `workflow_dispatch`.
- Real test coverage for the rule parser: a table-driven `main_test.go` built on captured
  `iptables -L -nvx` output, covering chain and column headers, untagged rules, extra match
  extensions, digit-heavy addresses, `uint64` counters, and the documented quirks of the
  comment regex.

### Changed
- `.goreleaser.yml` migrated to the GoReleaser v2 schema: added `version: 2`, replaced the
  deprecated `archives.format` with `formats`, and dropped `goos`/`goarch`, which GoReleaser
  ignores when `targets` is set. The previous file failed `goreleaser check`. Archive filenames
  are unchanged.
- The release workflow checks out with `fetch-depth: 0` instead of running
  `git fetch --prune --unshallow`, which errors when the checkout is already complete. It also
  runs the tests before releasing.
- Pinned `golangci-lint` to v2.13 so a lint release cannot break CI unannounced.
- The test workflow no longer runs on macOS and Windows; the plugin is Linux-only.
- Extracted parsing and metric formatting out of `executeCheck` into `writeMetrics`, so it can
  be tested without shelling out to iptables. Metric output is unchanged.
- The rule regex is compiled once at package level instead of on every invocation.

### Fixed
- `.bonsai.yml` now declares the `linux_armv5` build. GoReleaser has been building that archive
  all along, but Bonsai never referenced it, so armv5 entities could not resolve the asset.
- **Behaviour change:** an iptables failure now returns `CRITICAL` with the command's output in
  the error. It previously called `log.Fatalf`, which bypassed the Sensu SDK and exited 1, so
  the check surfaced as `WARNING`. Alerting tuned to WARNING on this check will see a different
  severity.
- All metrics from one run now share a single timestamp. `time.Now()` was called twice per rule,
  so a scrape crossing a second boundary emitted inconsistent timestamps.
- Scanner errors are no longer swallowed; truncated iptables output previously reported `OK`.

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
